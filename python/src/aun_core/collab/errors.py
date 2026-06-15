from __future__ import annotations

from typing import Any

from aun_core.errors import AUNError


class CollabError(AUNError):
    pass


class CollabConflictError(CollabError):
    def __init__(
        self,
        message: str,
        *,
        current_version: int | None = None,
        current_target: str = "",
        hint: str = "",
        code: int = -32009,
        data: Any = None,
        trace_id: str | None = None,
    ) -> None:
        super().__init__(message, code=code, data=data, trace_id=trace_id)
        self.current_version = current_version
        self.current_target = current_target
        self.hint = hint


def map_collab_error(exc: BaseException) -> BaseException:
    if isinstance(exc, CollabError):
        return exc
    code = getattr(exc, "code", None)
    data = getattr(exc, "data", None)
    message = str(exc) or type(exc).__name__
    if code == -32009:
        payload = data if isinstance(data, dict) else {}
        return CollabConflictError(
            message,
            current_version=payload.get("current_version"),
            current_target=str(payload.get("current_target") or ""),
            hint=str(payload.get("hint") or ""),
            code=int(code or -32009),
            data=data,
            trace_id=getattr(exc, "trace_id", None),
        )
    return exc
