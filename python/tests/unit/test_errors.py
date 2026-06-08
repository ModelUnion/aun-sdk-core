from aun_core.errors import (
    PermissionError as AUNPermissionError,
    TimeoutError as AUNTimeoutError,
    map_remote_error,
)


def test_rpc_handler_timeout_maps_to_timeout_error():
    err = map_remote_error({
        "code": -32004,
        "message": "RPC handler timeout (>30s): group.resources.resolve_access_ticket",
        "data": {"trace_id": "trace-timeout"},
    })

    assert isinstance(err, AUNTimeoutError)
    assert err.code == -32004
    assert err.retryable is True
    assert err.trace_id == "trace-timeout"


def test_legacy_permission_32004_stays_permission_error():
    err = map_remote_error({
        "code": -32004,
        "message": "Permission denied: requester AID is required",
    })

    assert isinstance(err, AUNPermissionError)
    assert err.retryable is False

