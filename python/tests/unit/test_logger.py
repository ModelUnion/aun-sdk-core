from pathlib import Path

from aun_core.logger import AUNLogger


def test_logger_format_includes_aun_path_and_device_id():
    logger = AUNLogger(debug=False, aun_path="/tmp/aun")
    logger.bind_device_id("device-1")

    line = logger._format("INFO", "aun_core.client", "hello %s", ("world",))

    expected_path = str(Path("/tmp/aun").expanduser())
    assert f"[INFO][aun_core.client][aun_path={expected_path}][device_id=device-1] hello world" in line
