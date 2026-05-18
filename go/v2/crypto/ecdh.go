package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
)

// ECDHComputeShared 计算 ECDH 共享秘密（P-256 X 坐标，32 字节）。
// privateKeyScalar: 32 字节 P-256 私钥标量（big-endian）
// peerPublicKeyDER: DER SubjectPublicKeyInfo 编码的对端公钥
//
// 输出为 P-256 共享点的 X 坐标 32 字节，与其它 SDK（Python/Node/C++）字节级一致。
func ECDHComputeShared(privateKeyScalar []byte, peerPublicKeyDER []byte) ([]byte, error) {
	if len(privateKeyScalar) != 32 {
		return nil, fmt.Errorf("ECDH: 私钥标量长度无效，期望 32 字节，实际 %d", len(privateKeyScalar))
	}

	curve := ecdh.P256()

	priv, err := curve.NewPrivateKey(privateKeyScalar)
	if err != nil {
		return nil, fmt.Errorf("ECDH: 解析私钥失败: %w", err)
	}

	peerPub, err := parseECDHPublicKeyDER(peerPublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("ECDH: 解析对端公钥失败: %w", err)
	}

	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: 计算共享秘密失败: %w", err)
	}

	if len(shared) != 32 {
		return nil, fmt.Errorf("ECDH: 共享秘密长度异常，期望 32 字节，实际 %d", len(shared))
	}

	return shared, nil
}

// GenerateP256Keypair 生成 P-256 密钥对。
// 返回 (privateKeyScalar 32 字节 big-endian, publicKeyDER SubjectPublicKeyInfo)。
func GenerateP256Keypair() ([]byte, []byte, error) {
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: 生成密钥对失败: %w", err)
	}

	scalar := priv.Bytes()
	if len(scalar) != 32 {
		return nil, nil, fmt.Errorf("ECDH: 生成的私钥标量长度异常，期望 32，实际 %d", len(scalar))
	}

	pubDER, err := marshalECDHPublicKeyDER(priv.PublicKey())
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: 序列化公钥失败: %w", err)
	}

	return scalar, pubDER, nil
}

// PrivateToPublicDER 从私钥标量导出公钥 DER（SubjectPublicKeyInfo）。
func PrivateToPublicDER(privateKeyScalar []byte) ([]byte, error) {
	if len(privateKeyScalar) != 32 {
		return nil, fmt.Errorf("ECDH: 私钥标量长度无效，期望 32 字节，实际 %d", len(privateKeyScalar))
	}

	curve := ecdh.P256()
	priv, err := curve.NewPrivateKey(privateKeyScalar)
	if err != nil {
		return nil, fmt.Errorf("ECDH: 解析私钥失败: %w", err)
	}

	pubDER, err := marshalECDHPublicKeyDER(priv.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("ECDH: 序列化公钥失败: %w", err)
	}
	return pubDER, nil
}

// parseECDHPublicKeyDER 解析 SubjectPublicKeyInfo DER 公钥并转为 *ecdh.PublicKey。
//
// x509.ParsePKIXPublicKey 对 EC 曲线返回 *ecdsa.PublicKey；必须经 .ECDH() 转为
// *ecdh.PublicKey 才能用于 crypto/ecdh 包的密钥协商。
func parseECDHPublicKeyDER(der []byte) (*ecdh.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("公钥类型不是 ECDSA P-256")
	}

	ecdhPub, err := ecdsaPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ECDSA → ECDH 转换失败: %w", err)
	}
	return ecdhPub, nil
}

// marshalECDHPublicKeyDER 将 *ecdh.PublicKey 序列化为 SubjectPublicKeyInfo DER。
//
// x509.MarshalPKIXPublicKey 不直接接受 *ecdh.PublicKey，需先转为 *ecdsa.PublicKey。
// crypto/ecdh 的 PublicKey.Bytes() 返回 SEC1 未压缩点（0x04 || X || Y），可以从
// 中提取 X/Y 坐标构造 *ecdsa.PublicKey。
func marshalECDHPublicKeyDER(pub *ecdh.PublicKey) ([]byte, error) {
	raw := pub.Bytes()
	// SEC1 未压缩格式：0x04 || X(32) || Y(32) = 65 字节
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("意外的 P-256 公钥编码：长度=%d, 首字节=0x%x", len(raw), raw[0])
	}

	ecdsaPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:65]),
	}

	return x509.MarshalPKIXPublicKey(ecdsaPub)
}
