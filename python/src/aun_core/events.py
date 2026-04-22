from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections import defaultdict
from collections.abc import Callable
from typing import Any

_events_log = logging.getLogger("aun_core.events")

EventHandler = Callable[[Any], Any]


class Subscription:
    """事件订阅句柄。

    调用 :meth:`unsubscribe` 后，该 handler 将在下一次 ``publish`` 时被排除
    （快照隔离语义）。如果 ``publish`` 正在遍历 handler 列表，当前轮次中该
    handler 仍可能被调用；取消操作在下一次 ``publish`` 生效。
    """

    def __init__(self, dispatcher: "EventDispatcher", event: str, handler: EventHandler) -> None:
        self._dispatcher = dispatcher
        self._event = event
        self._handler = handler
        self._active = True

    def unsubscribe(self) -> None:
        """取消订阅。采用快照隔离：取消在下一次 publish 生效。"""
        if not self._active:
            return
        self._dispatcher.unsubscribe(self._event, self._handler)
        self._active = False


class EventDispatcher:
    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        # 订阅列表可能在不同线程/协程中被读写（主 loop publish + 工作线程 subscribe/unsubscribe），
        # 用 RLock 保护字典结构，避免迭代中发生 `dictionary changed size during iteration` 等竞态。
        self._lock = threading.RLock()

    def subscribe(self, event: str, handler: EventHandler) -> Subscription:
        with self._lock:
            self._handlers[event].append(handler)
        return Subscription(self, event, handler)

    def unsubscribe(self, event: str, handler: EventHandler) -> None:
        with self._lock:
            handlers = self._handlers.get(event, [])
            self._handlers[event] = [registered for registered in handlers if registered is not handler]
            if not self._handlers[event]:
                self._handlers.pop(event, None)

    async def publish(self, event: str, payload: Any) -> None:
        """发布事件，按订阅顺序调用所有 handler。

        handler 列表在调用前做快照拷贝，因此在遍历过程中新增或取消的
        订阅不影响本轮分发，下一次 ``publish`` 才生效。

        单个 handler 抛出异常时：
        - 记录 warning 日志
        - 发布 ``handler.error`` 事件通知调用方（防止无限递归：
          ``handler.error`` 自身的 handler 异常不再递归发布）
        - 继续执行后续 handler
        """
        with self._lock:
            handlers = list(self._handlers.get(event, []))

        async def _safe_call(h: EventHandler) -> None:
            """单个 handler 的安全调用包装，异常不中断其他 handler。"""
            try:
                result = h(payload)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                _events_log.warning("事件 %s 处理器 %s 执行异常: %s", event, getattr(h, "__name__", h), exc, exc_info=True)
                # 发布 handler.error 事件通知调用方；防止无限递归：
                # 如果当前事件本身就是 handler.error，不再递归发布
                if event != "handler.error":
                    try:
                        await self.publish("handler.error", {
                            "event": event,
                            "handler": getattr(h, "__name__", str(h)),
                            "error": exc,
                        })
                    except Exception:
                        pass  # handler.error 的 handler 也异常时静默跳过，避免无限递归

        if handlers:
            await asyncio.gather(*[_safe_call(h) for h in handlers])
