from __future__ import annotations

import inspect
import logging
import threading
from collections import defaultdict
from collections.abc import Callable
from typing import Any

_events_log = logging.getLogger("aun_core.events")

EventHandler = Callable[[Any], Any]


class Subscription:
    def __init__(self, dispatcher: "EventDispatcher", event: str, handler: EventHandler) -> None:
        self._dispatcher = dispatcher
        self._event = event
        self._handler = handler
        self._active = True

    def unsubscribe(self) -> None:
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
        with self._lock:
            handlers = list(self._handlers.get(event, []))
        for handler in handlers:
            try:
                result = handler(payload)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                _events_log.warning("事件 %s 处理器 %s 执行异常: %s", event, getattr(handler, "__name__", handler), exc)
                continue
