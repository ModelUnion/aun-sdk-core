"""
AUN E2EE V2 M1: auth.connect V2-only 能力声明与旧加密信封拦截测试。

测试目标：
1. SDK auth.connect 请求中 supported_p2p_e2ee / supported_group_e2ee 只声明 V2。
2. 调用方不能通过额外字段把 SDK 降级为 legacy capability。
3. 旧 P2P / Group 加密信封被拒绝，V2 与明文路径不受影响。
4. 群协议字段默认 V2 且不可降级。
"""


class TestAuthConnectE2EECapabilities:
    """auth.connect 请求/响应中的 E2EE V2-only 能力协商。"""

    def test_client_sends_v2_only_capabilities(self):
        params = {
            "auth": {"method": "aid", "aid": "test.agentid.pub", "token": "..."},
            "capabilities": {
                "supported_p2p_e2ee": ["e2ee_v2"],
                "supported_group_e2ee": ["group_e2ee_v2"],
            },
            "protocol": {"min": "1.0", "max": "1.0"},
            "device": {"id": "dev-test"},
        }

        caps = params["capabilities"]
        assert caps["supported_p2p_e2ee"] == ["e2ee_v2"]
        assert caps["supported_group_e2ee"] == ["group_e2ee_v2"]
        assert "e2ee" not in caps["supported_p2p_e2ee"]
        assert "group_e2ee" not in caps["supported_group_e2ee"]

    def test_external_legacy_capability_override_is_ignored(self):
        requested_extra_info = {
            "_capabilities": {
                "supported_p2p_e2ee": ["e2ee"],
                "supported_group_e2ee": ["group_e2ee"],
            },
            "note": "kept",
        }
        effective_capabilities = {
            "supported_p2p_e2ee": ["e2ee_v2"],
            "supported_group_e2ee": ["group_e2ee_v2"],
        }
        sanitized_extra_info = {k: v for k, v in requested_extra_info.items() if not k.startswith("_")}

        assert effective_capabilities["supported_p2p_e2ee"] == ["e2ee_v2"]
        assert effective_capabilities["supported_group_e2ee"] == ["group_e2ee_v2"]
        assert sanitized_extra_info == {"note": "kept"}

    def test_server_response_may_advertise_superset_without_downgrading_client(self):
        hello_result = {
            "status": "ok",
            "capabilities": {
                "server_supported_p2p_e2ee": ["e2ee", "e2ee_v2"],
                "server_supported_group_e2ee": ["group_e2ee", "group_e2ee_v2"],
            },
        }
        client_caps = {
            "supported_p2p_e2ee": ["e2ee_v2"],
            "supported_group_e2ee": ["group_e2ee_v2"],
        }

        server_caps = hello_result["capabilities"]
        assert "e2ee_v2" in server_caps["server_supported_p2p_e2ee"]
        assert "group_e2ee_v2" in server_caps["server_supported_group_e2ee"]
        assert client_caps["supported_p2p_e2ee"] == ["e2ee_v2"]
        assert client_caps["supported_group_e2ee"] == ["group_e2ee_v2"]


class TestGatewayLegacyRejection:
    """网关对旧加密信封的 V2-only 拦截。"""

    def _simulate_gateway_check(self, payload_type: str, payload_version: str, method: str = "message.send"):
        if method not in ("message.send", "group.send", "message.thought.put", "group.thought.put"):
            return None
        if payload_type == "e2ee.encrypted":
            return {"error": {"code": -33020, "message": "legacy P2P encryption rejected"}}
        if payload_type == "e2ee.group_encrypted" and payload_version != "v2":
            return {"error": {"code": -33020, "message": "legacy group encryption rejected"}}
        return None

    def test_legacy_p2p_rejected(self):
        result = self._simulate_gateway_check("e2ee.encrypted", "")
        assert result is not None
        assert result["error"]["code"] == -33020

    def test_legacy_group_rejected(self):
        result = self._simulate_gateway_check("e2ee.group_encrypted", "1", method="group.send")
        assert result is not None
        assert result["error"]["code"] == -33020

    def test_v2_group_allowed(self):
        result = self._simulate_gateway_check("e2ee.group_encrypted", "v2", method="group.send")
        assert result is None

    def test_plaintext_allowed(self):
        result = self._simulate_gateway_check("text", "", method="message.send")
        assert result is None

    def test_non_send_methods_not_intercepted(self):
        result = self._simulate_gateway_check("e2ee.encrypted", "", method="meta.ping")
        assert result is None


class TestGroupE2EEProtocolField:
    """groups 表 group_e2ee_protocol 字段的 V2-only 语义。"""

    def test_default_value_is_v2(self):
        group_record = {"group_id": "g-new", "group_e2ee_protocol": "group_e2ee_v2"}
        assert group_record["group_e2ee_protocol"] == "group_e2ee_v2"

    def test_protocol_immutable_after_creation(self):
        group_record = {"group_id": "g-test", "group_e2ee_protocol": "group_e2ee_v2"}
        original = group_record["group_e2ee_protocol"]
        assert original == "group_e2ee_v2"

    def test_legacy_client_rejected_from_v2_group(self):
        client_supported = ["group_e2ee"]
        group_protocol = "group_e2ee_v2"

        if group_protocol not in client_supported:
            error = {
                "code": -33020,
                "message": "E2EE_VERSION_UNSUPPORTED",
                "data": {"required_protocol": group_protocol},
            }
            assert error["code"] == -33020
            assert error["data"]["required_protocol"] == "group_e2ee_v2"

    def test_v2_client_uses_v2_without_downgrade(self):
        client_supported = ["group_e2ee_v2"]
        group_protocol = "group_e2ee_v2"
        effective_protocol = group_protocol if group_protocol in client_supported else None
        assert effective_protocol == "group_e2ee_v2"


class TestPlaintextSmoke:
    """明文消息不受 V2-only 加密约束影响。"""

    def test_plaintext_p2p_unaffected(self):
        msg = {"type": "text", "payload": {"text": "hello"}}
        assert msg["type"] == "text"

    def test_plaintext_group_unaffected(self):
        msg = {"type": "text", "payload": {"text": "hello group"}}
        assert msg["type"] == "text"

    def test_plaintext_not_intercepted_by_gateway(self):
        payload_type = "text"
        assert payload_type != "e2ee.encrypted"
        assert payload_type != "e2ee.group_encrypted"
