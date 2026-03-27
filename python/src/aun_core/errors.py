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


class E2EESessionNotFoundError(E2EEError):
    def __init__(self, message: str = "e2ee session not found", **kwargs: Any) -> None:
        super().__init__(message, local_code="E2EE_SESSION_NOT_FOUND", **kwargs)


class E2EEBadSignatureError(E2EEError):
    def __init__(self, message: str = "e2ee bad signature", **kwargs: Any) -> None:
        super().__init__(message, local_code="E2EE_BAD_SIGNATURE", **kwargs)


class E2EEBadCounterError(E2EEError):
    def __init__(self, message: str = "e2ee bad counter", **kwargs: Any) -> None:
        super().__init__(
            message,
            local_code="E2EE_BAD_COUNTER",
            close_reason="counter_violation",
            **kwargs,
        )


class E2EEDecryptFailedError(E2EEError):
    def __init__(self, message: str = "e2ee decrypt failed", **kwargs: Any) -> None:
        super().__init__(
            message,
            local_code="E2EE_DECRYPT_FAILED",
            close_reason="decrypt_failed",
            **kwargs,
        )


class E2EEUnsupportedSuiteError(E2EEError):
    def __init__(self, message: str = "e2ee unsupported suite", **kwargs: Any) -> None:
        super().__init__(message, local_code="E2EE_UNSUPPORTED_SUITE", **kwargs)


class E2EESessionExpiredError(E2EEError):
    def __init__(self, message: str = "e2ee session expired", **kwargs: Any) -> None:
        super().__init__(
            message,
            local_code="E2EE_SESSION_EXPIRED",
            close_reason="session_expired",
            **kwargs,
        )


class E2EEDowngradeBlockedError(E2EEError):
    def __init__(self, message: str = "e2ee downgrade blocked", **kwargs: Any) -> None:
        super().__init__(message, local_code="E2EE_DOWNGRADE_BLOCKED", **kwargs)


class E2EENegotiationRejectedError(E2EEError):
    def __init__(
        self,
        message: str = "e2ee negotiation rejected",
        *,
        reject_reason: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, local_code="E2EE_NEGOTIATION_REJECTED", **kwargs)
        self.reject_reason = reject_reason


def map_remote_error(error: dict[str, Any]) -> AUNError:
    code = int(error.get("code", -32603))
    message = str(error.get("message", "remote error"))
    data = error.get("data")
    trace_id = None
    if isinstance(data, dict):
        trace_id = data.get("trace_id") or data.get("traceId")

    if code in {4001, 4010, -32003}:
        cls = AuthError
    elif code in {4030, 403}:
        cls = PermissionError
    elif code in {4040, 404, -32004}:
        cls = NotFoundError
    elif code in {4290, 429, -32029}:
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

    retryable = cls is RateLimitError or (5000 <= code < 6000)
    return cls(message, code=code, data=data, retryable=retryable, trace_id=trace_id)
