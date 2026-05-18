package crypto

// DH 路径派生（V2 §5.2）：
//   3DH wrap_key = HKDF(DH1 || DH2 || DH3, salt, "AUN-V2-3DH", 32)
//     DH1 = ECDH(sender_session_priv, recv_ik_pub)
//     DH2 = ECDH(sender_master_priv, recv_spk_pub)
//     DH3 = ECDH(sender_session_priv, recv_spk_pub)
//   1DH wrap_key = HKDF(DH1, salt, "AUN-V2-1DH", 32)
//     DH1 = ECDH(sender_session_priv, recv_ik_pub)
//
// salt 通常为消息 nonce（V2 spec 推荐使用 message envelope nonce）。
// info 为固定常量字符串，避免与其它派生路径冲突。

const (
	// Info3DH HKDF info for 3DH path
	Info3DH = "AUN-V2-3DH"
	// Info1DH HKDF info for 1DH path
	Info1DH = "AUN-V2-1DH"
	// WrapKeyLen wrap_key 长度（AES-256 密钥）
	WrapKeyLen = 32
)

// Compute3DHWrap 计算 3DH wrap_key（成员设备 prekey 路径）。
//
// senderSessionPriv: 发送方一次性 session 私钥（32B 标量）
// senderMasterPriv:  发送方主身份私钥（32B 标量）
// recvIKPub:         接收方主身份公钥 DER
// recvSPKPub:        接收方设备 SPK 公钥 DER
// salt:              HKDF salt（典型为消息 envelope nonce）
func Compute3DHWrap(senderSessionPriv, senderMasterPriv, recvIKPub, recvSPKPub, salt []byte) ([]byte, error) {
	dh1, err := ECDHComputeShared(senderSessionPriv, recvIKPub)
	if err != nil {
		return nil, err
	}
	dh2, err := ECDHComputeShared(senderMasterPriv, recvSPKPub)
	if err != nil {
		return nil, err
	}
	dh3, err := ECDHComputeShared(senderSessionPriv, recvSPKPub)
	if err != nil {
		return nil, err
	}
	ikm := make([]byte, 0, len(dh1)+len(dh2)+len(dh3))
	ikm = append(ikm, dh1...)
	ikm = append(ikm, dh2...)
	ikm = append(ikm, dh3...)
	return HKDFDerive(ikm, salt, []byte(Info3DH), WrapKeyLen)
}

// Compute1DHWrap 计算 1DH wrap_key（无 SPK 场景，仅用主身份）。
func Compute1DHWrap(senderSessionPriv, recvIKPub, salt []byte) ([]byte, error) {
	dh1, err := ECDHComputeShared(senderSessionPriv, recvIKPub)
	if err != nil {
		return nil, err
	}
	return HKDFDerive(dh1, salt, []byte(Info1DH), WrapKeyLen)
}
