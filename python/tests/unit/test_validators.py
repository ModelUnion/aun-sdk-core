"""
测试 AID 和 Group ID 格式校验器。
"""

import pytest

from aun_core.errors import ValidationError
from aun_core.validators import validate_aid_format, validate_group_id_format


class TestValidateAidFormat:
    """测试 AID 格式校验"""

    def test_valid_aid(self):
        """测试合法的 AID"""
        assert validate_aid_format("alice.aid.pub") == "alice.aid.pub"
        assert validate_aid_format("test_user.example.com") == "test_user.example.com"
        assert validate_aid_format("user-123.aid.pub") == "user-123.aid.pub"
        assert validate_aid_format("a1b2.test.co.uk") == "a1b2.test.co.uk"
        assert validate_aid_format("alice.bob.aid.pub") == "alice.bob.aid.pub"

    def test_valid_aid_case_normalization(self):
        """测试大小写规范化"""
        assert validate_aid_format("Alice.AID.PUB") == "alice.aid.pub"
        assert validate_aid_format("  TEST.example.com  ") == "test.example.com"

    def test_invalid_aid_empty(self):
        """测试空 AID"""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_aid_format("")
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_aid_format(None)
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_aid_format("   ")

    def test_invalid_aid_no_issuer(self):
        """测试缺少 issuer 的 AID"""
        with pytest.raises(ValidationError, match="must be in format"):
            validate_aid_format("alice")
        with pytest.raises(ValidationError, match="must be in format"):
            validate_aid_format("test_user")

    def test_invalid_aid_name_too_short(self):
        """测试 name 部分太短"""
        with pytest.raises(ValidationError, match="must be 4-64 characters"):
            validate_aid_format("abc.aid.pub")  # 只有 3 个字符
        with pytest.raises(ValidationError, match="must be 4-64 characters"):
            validate_aid_format("a.aid.pub")

    def test_invalid_aid_name_too_long(self):
        """测试 name 部分太长"""
        long_name = "a" * 65
        with pytest.raises(ValidationError, match="must be 4-64 characters"):
            validate_aid_format(f"{long_name}.aid.pub")

    def test_invalid_aid_name_starts_with_dash(self):
        """测试 name 以 - 开头"""
        with pytest.raises(ValidationError, match="cannot start with '-'"):
            validate_aid_format("-test.aid.pub")
        with pytest.raises(ValidationError, match="must be 4-64 characters"):
            validate_aid_format("-alice.aid.pub")

    def test_invalid_aid_name_starts_with_guest(self):
        """测试 name 以 guest 开头"""
        with pytest.raises(ValidationError, match="cannot start with 'guest'"):
            validate_aid_format("guest.aid.pub")
        with pytest.raises(ValidationError, match="cannot start with 'guest'"):
            validate_aid_format("guest123.aid.pub")
        with pytest.raises(ValidationError, match="cannot start with 'guest'"):
            validate_aid_format("guestuser.aid.pub")

    def test_invalid_aid_name_invalid_chars(self):
        """测试 name 包含非法字符"""
        with pytest.raises(ValidationError, match="must be 4-64 characters"):
            validate_aid_format("alice@bob.aid.pub")  # @ 不允许
        with pytest.raises(ValidationError, match="must be 4-64 characters"):
            validate_aid_format("alice bob.aid.pub")  # 空格不允许
        with pytest.raises(ValidationError, match="must be 4-64 characters"):
            validate_aid_format("alice#test.aid.pub")  # # 不允许

    def test_invalid_aid_invalid_issuer(self):
        """测试非法的 issuer"""
        with pytest.raises(ValidationError, match="issuer part cannot be empty"):
            validate_aid_format("alice.")
        # 注意：空格会被 strip，所以 "alice. " 会变成 "alice."
        # 测试包含特殊字符的域名
        with pytest.raises(ValidationError, match="is not a valid domain"):
            validate_aid_format("alice.#invalid")  # 特殊字符

    def test_invalid_aid_special_cases(self):
        """测试特殊非法情况"""
        # __system__ 这种完全非法的
        with pytest.raises(ValidationError):
            validate_aid_format("__system__")
        # 纯数字但太短
        with pytest.raises(ValidationError):
            validate_aid_format("123.aid.pub")


class TestValidateGroupIdFormat:
    """测试 Group ID 格式校验"""

    def test_valid_group_id_legacy(self):
        """测试合法的 legacy 格式 Group ID (g-[a-z0-9]{4,32})"""
        assert validate_group_id_format("g-abc123") == "g-abc123"
        assert validate_group_id_format("g-test") == "g-test"
        assert validate_group_id_format("g-1234") == "g-1234"
        # 最长 32 位
        long_slug = "a" * 32
        assert validate_group_id_format(f"g-{long_slug}") == f"g-{long_slug}"

    def test_valid_group_id_legacy_with_domain(self):
        """测试带域名的 legacy 格式"""
        assert validate_group_id_format("g-abc123.aid.pub") == "g-abc123.aid.pub"
        assert validate_group_id_format("g-test@example.com") == "g-test@example.com"

    def test_valid_group_id_new_format(self):
        """测试新格式 base ([a-z0-9]{5,})"""
        assert validate_group_id_format("12345") == "12345"
        assert validate_group_id_format("abcde") == "abcde"
        assert validate_group_id_format("a1b2c3") == "a1b2c3"
        # 可以很长
        long_base = "a" * 100
        assert validate_group_id_format(long_base) == long_base

    def test_valid_group_id_group_name(self):
        """测试 group name 格式 ([a-z0-9][a-z0-9_-]{3,63})"""
        assert validate_group_id_format("test_group") == "test_group"
        assert validate_group_id_format("my-team") == "my-team"
        assert validate_group_id_format("team123") == "team123"

    def test_valid_group_id_canonical(self):
        """测试 canonical 格式 group.{issuer}/{base}"""
        assert validate_group_id_format("group.aid.pub/g-abc123") == "group.aid.pub/g-abc123"
        assert validate_group_id_format("group.example.com/12345") == "group.example.com/12345"
        assert validate_group_id_format("group.aid.pub/my_team") == "group.aid.pub/my_team"

    def test_valid_group_id_case_normalization(self):
        """测试大小写规范化"""
        assert validate_group_id_format("G-ABC123") == "g-abc123"
        assert validate_group_id_format("  G-TEST@EXAMPLE.COM  ") == "g-test@example.com"
        assert validate_group_id_format("MyTeam") == "myteam"

    def test_invalid_group_id_empty(self):
        """测试空 Group ID"""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_group_id_format("")
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_group_id_format(None)
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_group_id_format("   ")

    def test_invalid_group_id_legacy_too_short(self):
        """测试 legacy 格式太短（少于 4 个字符）"""
        # 注意：g-ab (4字符) 和 g-abc (5字符) 都会匹配 group name 格式
        # 真正不匹配任何格式的是总长度少于 4 的
        with pytest.raises(ValidationError, match="must be one of"):
            validate_group_id_format("g-a")  # 只有 3 个字符
        with pytest.raises(ValidationError, match="must be one of"):
            validate_group_id_format("ab")  # 只有 2 个字符

    def test_invalid_group_id_legacy_too_long(self):
        """测试 legacy 格式太长（超过 32 个字符）"""
        # 注意：超过 32 字符但在 64 字符内会匹配 group name 格式
        # 真正非法的是超过 64 字符
        long_slug = "a" * 63  # g- + 63 = 65 字符，超过 group name 上限
        with pytest.raises(ValidationError, match="must be one of"):
            validate_group_id_format(f"g-{long_slug}")

    def test_invalid_group_id_new_format_too_short(self):
        """测试新格式太短（少于 5 个字符）"""
        # 注意：1234 (4字符) 会匹配 group name 格式
        # 真正不匹配任何格式的是少于 4 字符的
        with pytest.raises(ValidationError, match="must be one of"):
            validate_group_id_format("123")  # 只有 3 个字符
        with pytest.raises(ValidationError, match="must be one of"):
            validate_group_id_format("ab")

    def test_invalid_group_id_invalid_chars(self):
        """测试包含非法字符"""
        with pytest.raises(ValidationError, match="must be one of"):
            validate_group_id_format("test group")  # 空格
        # test@group 会被解析为 base=test, domain=group，test 是合法的 group name
        # 真正非法的是包含特殊字符的
        with pytest.raises(ValidationError, match="must be one of"):
            validate_group_id_format("test#group")  # #
        with pytest.raises(ValidationError, match="must be one of"):
            validate_group_id_format("test$abc")  # $

    def test_invalid_group_id_invalid_domain(self):
        """测试非法的域名"""
        # 带明显非法字符的域名
        with pytest.raises(ValidationError, match="is not a valid domain"):
            validate_group_id_format("g-test@#invalid")
        # 注意：空格会被 strip，需要在域名中间添加非法字符
        with pytest.raises(ValidationError, match="is not a valid domain"):
            validate_group_id_format("g-test@in valid")  # 域名中有空格

    def test_edge_case_group_name_format(self):
        """测试 group name 格式的边界情况"""
        # 最短 4 个字符
        assert validate_group_id_format("team") == "team"
        # 最长 64 个字符
        long_name = "a" + "b" * 63
        assert validate_group_id_format(long_name) == long_name
        # 包含下划线和短横线
        assert validate_group_id_format("my_team-01") == "my_team-01"


class TestValidateInSendMethods:
    """测试在发送方法中的实际使用场景"""

    def test_message_send_invalid_recipient(self):
        """测试 message.send 拒绝非法 AID"""
        # 这个测试将在集成到 client 后生效
        pass

    def test_group_send_invalid_group_id(self):
        """测试 group.send 拒绝非法 Group ID"""
        # 这个测试将在集成到 client 后生效
        pass
