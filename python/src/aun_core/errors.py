from __future__ import annotations

from typing import Any


class AUNError(Exception):
    def __init__(
        self,
        message: str,
        *,
        code: int = -1,
        data: Any = None,
        retryable: bool = False,
        trace_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.data = data
        self.retryable = retryable
        self.trace_id = trace_id


class ConnectionError(AUNError):
    pass


class TimeoutError(AUNError):
    pass


class AuthError(AUNError):
    pass


class IdentityConflictError(AuthError):
    pass


class PermissionError(AUNError):
    pass


class ValidationError(AUNError):
    pass


class NotFoundError(AUNError):
    pass


class RateLimitError(AUNError):
    pass


class StateError(AUNError):
    pass


class SerializationError(AUNError):
    pass


class SessionError(AUNError):
    pass


class GroupError(AUNError):
    pass


class VersionConflictError(AUNError):
    pass


class GroupNotFoundError(GroupError):
    pass


class GroupStateError(GroupError):
    pass


class E2EEError(AUNError):
    def __init__(
        self,
        message: str,
        *,
        local_code: str = "E2EE_ERROR",
        close_reason: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.local_code = local_code
        self.close_reason = close_reason


class E2EEDecryptFailedError(E2EEError):
    def __init__(self, message: str = "e2ee decrypt failed", **kwargs: Any) -> None:
        super().__init__(
            message,
            local_code="E2EE_DECRYPT_FAILED",
            close_reason="decrypt_failed",
            **kwargs,
        )


class CertificateRevokedError(AuthError):
    """对端证书已被吊销"""
    def __init__(self, message: str = "peer certificate has been revoked", **kwargs: Any) -> None:
        super().__init__(message, code=-32050, **kwargs)


class E2EEDegradedError(E2EEError):
    """E2EE 降级（无前向保密）"""
    def __init__(self, message: str = "e2ee degraded: no forward secrecy", **kwargs: Any) -> None:
        super().__init__(message, local_code="E2EE_DEGRADED", **kwargs)


class ClientSignatureError(ValidationError):
    """客户端操作签名验证失败"""
    def __init__(self, message: str = "client signature verification failed", **kwargs: Any) -> None:
        super().__init__(message, code=-32051, **kwargs)


def map_remote_error(error: dict[str, Any]) -> AUNError:
    code = int(error.get("code", -32603))
    message = str(error.get("message", "remote error"))
    data = error.get("data")
    trace_id = None
    if isinstance(data, dict):
        trace_id = data.get("trace_id") or data.get("traceId")

    if code in {4001, 4010, -32001, -32003}:
        cls = AuthError
    elif code == -32004 and message.lower().startswith("rpc handler timeout"):
        cls = TimeoutError
    elif code in {4030, 403, -32004}:
        cls = PermissionError
    elif code == -32008:
        cls = NotFoundError
    elif code == -32009:
        cls = VersionConflictError
    elif code in {4040, 404}:
        cls = NotFoundError
    elif code in {4290, 429, -32029, -32429}:
        cls = RateLimitError
    elif code in {-32010, -32011, -32013}:
        cls = SessionError
    elif code in {-32600, -32601, -32602, 4000}:
        cls = ValidationError
    elif code == -33001:
        cls = GroupNotFoundError
    elif code in {-33002, -33003}:
        cls = GroupStateError
    elif -33009 <= code <= -33004:
        cls = GroupError
    else:
        cls = AUNError

    message_lower = message.strip().lower()
    transient_gateway_degraded = (
        "gateway service degraded" in message_lower
        or "certificate not loaded" in message_lower
    )
    retryable = (
        cls in {RateLimitError, TimeoutError}
        or (5000 <= code < 6000)
        or transient_gateway_degraded
    )
    return cls(message, code=code, data=data, retryable=retryable, trace_id=trace_id)
