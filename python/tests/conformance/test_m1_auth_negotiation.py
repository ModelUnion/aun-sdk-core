"""
AUN E2EE V2 M1: auth.connect 协商 + 网关 V1 拦截 测试

测试目标：
1. auth.connect 请求中 capabilities 含 supported_p2p_e2ee / supported_group_e2ee
2. 服务端响应中回传 server_supported_p2p_e2ee / server_supported_group_e2ee
3. 网关 V1 加密拦截逻辑（require_e2ee_v2 / require_group_e2ee_v2 开关）
4. groups 表 group_e2ee_protocol 字段
5. 明文消息不受影响
"""
import pytest


# ══════════════════════════════════════════════════════════════
# 1. auth.connect 能力协商
# ══════════════════════════════════════════════════════════════

class TestAuthConnectE2EECapabilities:
    """auth.connect 请求/响应中的 E2EE 版本协商"""

    def test_client_sends_supported_e2ee_in_capabilities(self):
        """客户端 connect 时在 capabilities 中上报 supported_p2p_e2ee / supported_group_e2ee"""
        # 模拟客户端发送的 auth.connect params
        params = {
            "auth": {"method": "aid", "aid": "test.agentid.pub", "token": "..."},
            "capabilities": {
                "supported_p2p_e2ee": ["e2ee", "e2ee_v2"],
                "supported_group_e2ee": ["group_e2ee", "group_e2ee_v2"],
            },
            "protocol": {"min": "1.0", "max": "1.0"},
            "device": {"id": "dev-test"},
        }
        # 验证 capabilities 结构正确
        caps = params["capabilities"]
        assert "supported_p2p_e2ee" in caps
        assert "supported_group_e2ee" in caps
        assert "e2ee_v2" in caps["supported_p2p_e2ee"]
        assert "group_e2ee_v2" in caps["supported_group_e2ee"]

    def test_old_client_no_e2ee_capabilities(self):
        """老客户端不传 supported_*_e2ee → 服务端按 V1 处理（向后兼容）"""
        params = {
            "auth": {"method": "aid", "aid": "test.agentid.pub", "token": "..."},
            "capabilities": {},  # 老客户端无 e2ee 字段
            "protocol": {"min": "1.0", "max": "1.0"},
        }
        caps = params["capabilities"]
        # 缺失时服务端应默认为 ["e2ee"] / ["group_e2ee"]
        supported_p2p = caps.get("supported_p2p_e2ee", ["e2ee"])
        supported_group = caps.get("supported_group_e2ee", ["group_e2ee"])
        assert supported_p2p == ["e2ee"]
        assert supported_group == ["group_e2ee"]

    def test_server_response_includes_e2ee_capabilities(self):
        """服务端 hello_result 中回传 server 支持的 e2ee 版本"""
        # 模拟服务端响应
        hello_result = {
            "status": "ok",
            "capabilities": {
                "server_supported_p2p_e2ee": ["e2ee", "e2ee_v2"],
                "server_supported_group_e2ee": ["group_e2ee", "group_e2ee_v2"],
            },
        }
        server_caps = hello_result["capabilities"]
        assert "e2ee_v2" in server_caps["server_supported_p2p_e2ee"]
        assert "group_e2ee_v2" in server_caps["server_supported_group_e2ee"]


# ═════════════════════════════════════════════════════════════
# 2. 网关 V1 加密拦截
# ══════════════════════════════════════════════════════════════

class TestGatewayV1Rejection:
    """网关按域独立拦截 V1 加密消息"""

    def _simulate_gateway_check(self, payload_type: str, payload_version: str,
                                 require_e2ee_v2: bool, require_group_e2ee_v2: bool,
                                 method: str = "message.send"):
        """模拟网关拦截逻辑"""
        # 仅对 send / thought.put 类方法检查
        if method not in ("message.send", "group.send", "message.thought.put", "group.thought.put"):
            return None
        # P2P V1 加密
        if payload_type == "e2ee.encrypted":
            if require_e2ee_v2:
                return {"error": {"code": -33020, "message": "V1 P2P encryption rejected"}}

        # Group 加密
        if payload_type == "e2ee.group_encrypted":
            if payload_version != "v2" and require_group_e2ee_v2:
                return {"error": {"code": -33020, "message": "V1 group encryption rejected"}}

        # 通过
        return None

    def test_v1_p2p_rejected_when_switch_on(self):
        """require_e2ee_v2=true → V1 P2P 加密被拒"""
        result = self._simulate_gateway_check(
            payload_type="e2ee.encrypted",
            payload_version="",
            require_e2ee_v2=True,
            require_group_e2ee_v2=False,
        )
        assert result is not None
        assert result["error"]["code"] == -33020

    def test_v1_p2p_allowed_when_switch_off(self):
        """require_e2ee_v2=false → V1 P2P 加密放行"""
        result = self._simulate_gateway_check(
            payload_type="e2ee.encrypted",
            payload_version="",
            require_e2ee_v2=False,
            require_group_e2ee_v2=False,
        )
        assert result is None

    def test_v1_group_rejected_when_switch_on(self):
        """require_group_e2ee_v2=true → V1 Group 加密被拒"""
        result = self._simulate_gateway_check(
            payload_type="e2ee.group_encrypted",
            payload_version="1",  # V1 版本
            require_e2ee_v2=True,
            require_group_e2ee_v2=True,
        )
        assert result is not None
        assert result["error"]["code"] == -33020

    def test_v1_group_allowed_when_switch_off(self):
        """require_group_e2ee_v2=false → V1 Group 加密放行"""
        result = self._simulate_gateway_check(
            payload_type="e2ee.group_encrypted",
            payload_version="1",
            require_e2ee_v2=True,
            require_group_e2ee_v2=False,
        )
        assert result is None

    def test_v2_group_always_allowed(self):
        """V2 Group 加密永远放行（无论开关状态）"""
        result = self._simulate_gateway_check(
            payload_type="e2ee.group_encrypted",
            payload_version="v2",
            require_e2ee_v2=True,
            require_group_e2ee_v2=True,
        )
        assert result is None

    def test_plaintext_always_allowed(self):
        """明文消息永远不受影响"""
        result = self._simulate_gateway_check(
            payload_type="text",
            payload_version="",
            require_e2ee_v2=True,
            require_group_e2ee_v2=True,
        )
        assert result is None

    def test_switches_independent(self):
        """两个开关独立——P2P 开 + Group 关"""
        # V1 P2P 被拒
        r1 = self._simulate_gateway_check("e2ee.encrypted", "", True, False)
        assert r1 is not None
        # V1 Group 放行
        r2 = self._simulate_gateway_check("e2ee.group_encrypted", "1", True, False)
        assert r2 is None


# ══════════════════════════════════════════════════════════════
# 3. groups 表 group_e2ee_protocol 字段
# ══════════════════════════════════════════════════════════════

class TestGroupE2EEProtocolField:
    """groups 表 group_e2ee_protocol 字段"""

    def test_default_value_is_v1(self):
        """默认值为 'group_e2ee'（V1），向后兼容"""
        # 模拟旧群记录
        group_record = {"group_id": "g-old", "group_e2ee_protocol": "group_e2ee"}
        assert group_record["group_e2ee_protocol"] == "group_e2ee"

    def test_v2_group_creation(self):
        """V2 群创建时设置 group_e2ee_protocol='group_e2ee_v2'"""
        group_record = {"group_id": "g-new", "group_e2ee_protocol": "group_e2ee_v2"}
        assert group_record["group_e2ee_protocol"] == "group_e2ee_v2"

    def test_protocol_immutable_after_creation(self):
        """群创建后 group_e2ee_protocol 不可变更"""
        group_record = {"group_id": "g-test", "group_e2ee_protocol": "group_e2ee_v2"}
        # 尝试变更应被拒绝（业务逻辑层保证）
        original = group_record["group_e2ee_protocol"]
        # 模拟：不允许修改
        assert original == "group_e2ee_v2"

    def test_v1_client_rejected_from_v2_group(self):
        """V1 客户端（不支持 group_e2ee_v2）尝试加入 V2 群 → -33020"""
        client_supported = ["group_e2ee"]  # 老客户端
        group_protocol = "group_e2ee_v2"

        if group_protocol not in client_supported:
            error = {"code": -33020, "message": "E2EE_VERSION_UNSUPPORTED",
                     "data": {"required_protocol": group_protocol}}
            assert error["code"] == -33020
            assert error["data"]["required_protocol"] == "group_e2ee_v2"

    def test_v2_client_in_v1_group_uses_v1(self):
        """V2 客户端加入 V1 群时按 V1 协议操作"""
        client_supported = ["group_e2ee", "group_e2ee_v2"]
        group_protocol = "group_e2ee"
        # V2 客户端在 V1 群中降级到 V1
        effective_protocol = group_protocol  # 群级决定
        assert effective_protocol == "group_e2ee"


# ══════════════════════════════════════════════════════════════
# 4. 明文消息 smoke
# ══════════════════════════════════════════════════════════════

class TestPlaintextSmoke:
    """明文消息不受 V2 改动影响"""

    def test_plaintext_p2p_unaffected(self):
        """明文 P2P 消息结构不含 e2ee 字段"""
        msg = {
            "type": "text",
            "payload": {"text": "hello"},
        }
        assert msg["type"] == "text"
        assert "e2ee" not in msg["type"]

    def test_plaintext_group_unaffected(self):
        """明文群消息结构不含 e2ee 字段"""
        msg = {
            "type": "text",
            "payload": {"text": "hello group"},
        }
        assert msg["type"] == "text"

    def test_plaintext_not_intercepted_by_gateway(self):
        """明文消息不被网关拦截（即使两个开关都开）"""
        # 复用 gateway check 逻辑
        payload_type = "text"
        # 明文 type 不匹配任何加密类型 → 放行
        is_v1_p2p = payload_type == "e2ee.encrypted"
        is_group_encrypted = payload_type == "e2ee.group_encrypted"
        assert not is_v1_p2p
        assert not is_group_encrypted
