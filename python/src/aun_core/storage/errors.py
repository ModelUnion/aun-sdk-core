from __future__ import annotations

from typing import Any

from aun_core.errors import AUNError, NotFoundError as AUNNotFoundError
from aun_core.errors import PermissionError as AUNPermissionError
from aun_core.errors import VersionConflictError


class StorageError(Exception):
    def __init__(self, message: str, *, code: int | str = "ESTORAGE", path: str = "", data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.data = data


class NotFoundError(StorageError):
    pass


class ExistsError(StorageError):
    pass


class AccessDeniedError(StorageError):
    pass


class NotADirectoryError(StorageError):
    pass


class IsADirectoryError(StorageError):
    pass


class ConflictError(StorageError):
    pass


class QuotaError(StorageError):
    pass


class SessionExpiredError(StorageError):
    pass


class LoopError(StorageError):
    pass


class DanglingSymlinkError(StorageError):
    pass


def map_storage_error(exc: BaseException, *, path: str = "") -> StorageError:
    if isinstance(exc, StorageError):
        return exc

    code = getattr(exc, "code", None)
    data = getattr(exc, "data", None)
    message = str(exc) or type(exc).__name__
    lowered = message.lower()

    if isinstance(exc, (AUNNotFoundError, FileNotFoundError)) or code in {-32008, 404, 4040}:
        return NotFoundError(message, code="ENOENT", path=path, data=data)
    if isinstance(exc, VersionConflictError) or code == -32009 or "version conflict" in lowered:
        return ConflictError(message, code="ECONFLICT", path=path, data=data)
    if isinstance(exc, AUNPermissionError) or code in {-32004, 403, 4030}:
        return AccessDeniedError(message, code="EACCES", path=path, data=data)
    if code == -32031 or "eloop" in lowered or "循环" in message:
        return LoopError(message, code="ELOOP", path=path, data=data)
    if code == -32032 or "dangling" in lowered or "软链目标不存在" in message:
        return DanglingSymlinkError(message, code="EDANGLING", path=path, data=data)
    if code in {-32010, -32011, -32013} or "session" in lowered and "expired" in lowered:
        return SessionExpiredError(message, code="ESESSIONEXPIRED", path=path, data=data)
    if "quota" in lowered or "配额" in message:
        return QuotaError(message, code="EQUOTA", path=path, data=data)
    if "already exists" in lowered or "已存在" in message:
        return ExistsError(message, code="EEXIST", path=path, data=data)
    if "not a directory" in lowered or "不是目录" in message:
        return NotADirectoryError(message, code="ENOTDIR", path=path, data=data)
    if "is a directory" in lowered or "是目录" in message:
        return IsADirectoryError(message, code="EISDIR", path=path, data=data)
    if code == -32602 and ("不存在" in message or "not found" in lowered or "no such" in lowered):
        return NotFoundError(message, code="ENOENT", path=path, data=data)
    if isinstance(exc, AUNError):
        return StorageError(message, code=code or "ERPC", path=path, data=data)
    return StorageError(message, code=code or "ESTORAGE", path=path, data=data)
