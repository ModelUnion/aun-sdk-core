from __future__ import annotations

from aun_core import result_err, result_ok


def test_result_ok_exposes_data_and_dict_shape():
    result = result_ok({"value": 1})

    assert result.ok is True
    assert result.data == {"value": 1}
    assert result.error is None
    assert result["ok"] is True
    assert result["data"] == {"value": 1}


def test_result_err_exposes_error_info_and_dict_shape():
    cause = RuntimeError("boom")
    result = result_err("NETWORK_ERROR", "network failed", cause=cause)

    assert result.ok is False
    assert result.data is None
    assert result.error is not None
    assert result.error.code == "NETWORK_ERROR"
    assert result.error.message == "network failed"
    assert result.error.cause is cause
    assert result["error"]["code"] == "NETWORK_ERROR"
