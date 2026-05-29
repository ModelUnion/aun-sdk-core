from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, TypeVar


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    code: str
    message: str
    cause: BaseException | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.cause is not None:
            data["cause"] = str(self.cause)
        return data

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


@dataclass(frozen=True, slots=True)
class Result(Generic[T]):
    ok: bool
    data: T | None = None
    error: ErrorInfo | None = None

    def to_dict(self) -> dict[str, Any]:
        if self.ok:
            return {"ok": True, "data": self.data}
        return {"ok": False, "error": self.error.to_dict() if self.error else None}

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __bool__(self) -> bool:
        return self.ok


def result_ok(data: T) -> Result[T]:
    return Result(ok=True, data=data, error=None)


def result_err(code: str, message: str, cause: BaseException | None = None) -> Result[Any]:
    return Result(ok=False, data=None, error=ErrorInfo(code=code, message=message, cause=cause))
