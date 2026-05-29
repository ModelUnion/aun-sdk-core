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
