from __future__ import annotations

from typing import Any, Literal, TypedDict


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
