from __future__ import annotations

from enum import Enum
from typing import Any, Literal, TypedDict


class ConnectionState(str, Enum):
    """AUNClient 连接状态枚举。"""
    NO_IDENTITY = "no_identity"
    STANDBY = "standby"
    AUTHENTICATED = "authenticated"
    CONNECTING = "connecting"
    READY = "ready"
    RETRY_BACKOFF = "retry_backoff"
    RECONNECTING = "reconnecting"
    CONNECTION_FAILED = "connection_failed"
    CLOSED = "closed"


JsonValue = Any


Message = TypedDict(
    "Message",
    {
        "message_id": str,
        "seq": int,
        "from": str,
        "to": str,
        "type": str,
        "payload": JsonValue,
        "encrypted": bool,
        "delivery_mode": Literal["fanout", "queue"],
        "timestamp": int,
        "e2ee": dict[str, Any],
    },
    total=False,
)


class SendResult(TypedDict, total=False):
    ok: bool
    message_id: str
    seq: int
    timestamp: int
    status: Literal["sent", "delivered", "duplicate"]
    delivery_mode: Literal["fanout", "queue"]


class AckResult(TypedDict, total=False):
    success: bool
    ack_seq: int


class PullResult(TypedDict, total=False):
    messages: list[Message]
    count: int
    latest_seq: int


class ConnectionOptions(TypedDict, total=False):
    auto_reconnect: bool          # 是否自动重连，默认 True
    connect_timeout: float        # 连接超时（秒），默认 5
    retry_initial_delay: float    # 最小退避间隔（秒），默认 1
    retry_max_delay: float        # 最大退避间隔（秒），默认 64
    retry_max_attempts: int       # 最大重试次数，0=无限，默认 0
    heartbeat_interval: float     # 心跳间隔（秒），默认 30
    call_timeout: float           # RPC 调用超时（秒），默认 35
    connection_kind: str          # 连接类型：'long'（默认）或 'short'
    short_ttl_ms: int             # short 连接的 TTL（毫秒），仅 connection_kind='short' 时有效
    extra_info: dict              # 附加信息，透传给 gateway
    delivery_mode: dict           # 消息投递模式配置，含 mode（fanout/queue）
    background_sync: bool         # 是否启用后台同步，默认 True
