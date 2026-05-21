import json
from io import StringIO
from unittest.mock import patch


def test_output_json_dict():
    from aun_cli.output import output_json
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        output_json({"aid": "alice@aid.com", "status": "active"})
    data = json.loads(mock_out.getvalue())
    assert data["aid"] == "alice@aid.com"


def test_output_json_list():
    from aun_cli.output import output_json
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        output_json([{"a": 1}, {"a": 2}])
    data = json.loads(mock_out.getvalue())
    assert len(data) == 2


def test_output_dict_format():
    from aun_cli.output import output_dict
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        output_dict({"AID": "alice@aid.com", "Gateway": "wss://gw.aid.com"})
    text = mock_out.getvalue()
    assert "alice@aid.com" in text
    assert "Gateway" in text


def test_output_error():
    from aun_cli.output import output_error
    with patch("sys.stderr", new_callable=StringIO) as mock_err:
        output_error("connection failed", hint="check gateway URL")
    text = mock_err.getvalue()
    assert "connection failed" in text
    assert "check gateway URL" in text
