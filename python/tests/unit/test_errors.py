from aun_core.errors import (
    AUNError,
    PermissionError as AUNPermissionError,
    RateLimitError as AUNRateLimitError,
    TimeoutError as AUNTimeoutError,
    map_remote_error,
)


def test_rpc_handler_timeout_maps_to_timeout_error():
    err = map_remote_error({
        "code": -32004,
        "message": "RPC handler timeout (>30s): group.fs.create_download_ticket",
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


def test_gateway_backpressure_32429_maps_to_rate_limit_error():
    """Gateway 入口背压限流码 -32429 应映射为可重试的 RateLimitError。"""
    err = map_remote_error({
        "code": -32429,
        "message": "too many requests: group message service backpressure pending=20 limit=20",
    })

    assert isinstance(err, AUNRateLimitError)
    assert err.code == -32429
    assert err.retryable is True


def test_gateway_certificate_not_loaded_maps_to_retryable_error():
    """Gateway 启动期证书未加载是暂态降级，重连循环应继续退避重试。"""
    err = map_remote_error({
        "code": -32603,
        "message": "Gateway service degraded: certificate not loaded",
    })

    assert isinstance(err, AUNError)
    assert err.retryable is True
