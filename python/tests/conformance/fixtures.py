"""
AUN E2EE V2 Conformance: 共享测试密钥

这些是固定的 P-256 测试密钥，用于所有 conformance 测试。
不是真实密钥——仅用于测试。
"""
import base64

# ── Alice（模拟接收方 IK）──
ALICE_PRIV = base64.b64decode("pixVw1Nzw9kwG88AXzwvln1EDj59XpREtdl19ohv84E=")
ALICE_PUB_DER = base64.b64decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDU8HhWlb8vRbPSiisDf/jOfGz72hFuyLcJ/+EGJM4fu6KPzKFPAGPWe+QTjqUKmklvGNk9BlKYnCRYM+hwyT1w==")

# ── Bob（模拟接收方 SPK）──
BOB_PRIV = base64.b64decode("kucXls+1l1JEL84puz+hIVGNMQpaBu2GVO1FSAC1Gpg=")
BOB_PUB_DER = base64.b64decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAy/dR85gB8u3wafx7xGDfHfQaCFsOEiHsVRyLTiMoWnIj2Hqp3/HaX9fx1XLbWTG7q5v8HAO202Yj8WtYH1YEA==")

# ── Carol（模拟另一个接收方）──
CAROL_PRIV = base64.b64decode("90MdEDhLSFBux7S2xNkl76QhMr42LY3gMr6ccoVMjwc=")
CAROL_PUB_DER = base64.b64decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVVsLCk1RJUoJ7QInnmFYn6uImW5P9KljxPLD3F827MBZVJAgTuGX21KxZIwjikOGl7jX4fvCY3R8ZtlHICHhZQ==")

# ── Sender Session（模拟发送方一次性会话密钥）──
SENDER_SESSION_PRIV = base64.b64decode("YSJfT/BHTE6J9sDXN495hou7PdjbRqBMLvi46W0NSI4=")
SENDER_SESSION_PUB_DER = base64.b64decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEez5QV1egBYYIgT90RFSMD/Aw9mlpVEBVhGgaSHe7/ek+9pkEBYFmNF7ISWNlBKknsbl2YOD+z/fvFLlcFhM9HQ==")

# ── 角色映射（V2 协议语义）──
# ALICE = 接收方 IK（recv_ik）
# BOB = 接收方 SPK（recv_spk）
# CAROL = 另一个接收方（用于"不同密钥不同结果"测试）
# SENDER_SESSION = 发送方一次性会话密钥（sender_session）
# ALICE_PRIV 也可作为 sender_master_priv（模拟发送方 AID 主私钥）
