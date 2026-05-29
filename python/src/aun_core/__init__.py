from .aid import AID
from .aid_store import AIDStore
from .client import AUNClient
from .config import get_device_id
from .e2ee import ProtectedHeaders
from .result import ErrorInfo, Result, result_err, result_ok
from .types import ConnectionState
from .errors import (
    AUNError,
    AuthError,
    IdentityConflictError,
    ConnectionError,
    TimeoutError,
    PermissionError,
    ValidationError,
    NotFoundError,
    RateLimitError,
    StateError,
    SerializationError,
    E2EEError,
    GroupError,
    GroupNotFoundError,
    GroupStateError,
    E2EEGroupSecretMissingError,
    E2EEGroupEpochMismatchError,
    E2EEGroupCommitmentInvalidError,
    E2EEGroupNotMemberError,
    E2EEGroupDecryptFailedError,
)

__version__ = "0.3.6"

__all__ = [
    "__version__",
    "AIDStore",
    "AID",
    "AUNClient",
    "Result",
    "ErrorInfo",
    "result_ok",
    "result_err",
    "ProtectedHeaders",
    "ConnectionState",
    "get_device_id",
    "AUNError",
    "AuthError",
    "ConnectionError",
    "TimeoutError",
    "PermissionError",
    "ValidationError",
    "NotFoundError",
    "RateLimitError",
    "StateError",
    "SerializationError",
    "E2EEError",
    "GroupError",
    "GroupNotFoundError",
    "GroupStateError",
    "E2EEGroupSecretMissingError",
    "E2EEGroupEpochMismatchError",
    "E2EEGroupCommitmentInvalidError",
    "E2EEGroupNotMemberError",
    "E2EEGroupDecryptFailedError",
]
