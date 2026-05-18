// ECDSA-SHA256 RAW 签名/验签（RFC 6979 deterministic）。
//
// AUN V2 §3.1：
//   - 曲线 P-256 / SHA-256
//   - 签名 RAW 编码 r(32B) || s(32B) = 64 字节定长
//   - MUST 使用 RFC 6979 deterministic nonce 以保证字节级可复现
//
// Go 标准库 crypto/ecdsa 不暴露 RFC 6979 入口（SignASN1 输出 ASN.1 DER 且 nonce
// 由 rand.Reader 提供，非确定性）。本文件实现 RFC 6979 §3.2 的 K 生成算法以及
// 配套的 P-256 ECDSA 签名流程，输出与 Python `cryptography` 的
// `deterministic_signing=True` 字节级一致。

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// ECDSARawSigLen RAW 编码签名长度（r 32B || s 32B）
const ECDSARawSigLen = 64

// ECDSASignRaw 使用 RFC 6979 deterministic nonce 在 P-256 上对 message 做
// SHA-256 ECDSA 签名，输出 RAW 编码 (r 32B || s 32B)。
func ECDSASignRaw(privateKeyScalar, message []byte) ([]byte, error) {
	if len(privateKeyScalar) != 32 {
		return nil, fmt.Errorf("ECDSA: 私钥标量长度无效，期望 32 字节，实际 %d", len(privateKeyScalar))
	}
	curve := elliptic.P256()
	n := curve.Params().N

	d := new(big.Int).SetBytes(privateKeyScalar)
	if d.Sign() == 0 || d.Cmp(n) >= 0 {
		return nil, errors.New("ECDSA: 私钥标量超出曲线阶范围")
	}

	hash := sha256.Sum256(message)
	h1 := hash[:]

	// RFC 6979 §3.2: 派生 deterministic k，并完成签名
	r, s := signRFC6979(curve, d, h1)
	if r == nil || s == nil {
		return nil, errors.New("ECDSA: 签名失败（k 迭代未产生有效结果）")
	}

	out := make([]byte, ECDSARawSigLen)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// ECDSAVerifyRaw 验证 RAW 编码的 ECDSA-SHA256 签名。
func ECDSAVerifyRaw(publicKeyDER, signatureRaw, message []byte) bool {
	if len(signatureRaw) != ECDSARawSigLen {
		return false
	}
	pub, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return false
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() {
		return false
	}
	r := new(big.Int).SetBytes(signatureRaw[:32])
	s := new(big.Int).SetBytes(signatureRaw[32:])
	hash := sha256.Sum256(message)
	return ecdsa.Verify(ecPub, hash[:], r, s)
}

// signRFC6979 在 P-256 上完成 (k, r, s) 的派生与签名。
// 当 r 或 s 为 0 时重新派生 k（RFC 6979 §3.2 规定）。
func signRFC6979(curve elliptic.Curve, d *big.Int, h1 []byte) (*big.Int, *big.Int) {
	params := curve.Params()
	n := params.N
	// 对 SHA-256 + P-256：qlen = 256，rolen = 32
	const rolen = 32

	// hash function constructor
	newHash := sha256.New
	hashLen := sha256.Size

	// h1 = SHA-256(message)，长度 32B，刚好等于 qlen/8。
	// bits2octets(h1) = int2octets(bits2int(h1) mod q)
	h1Int := bits2int(h1, params.BitSize)
	h1Mod := new(big.Int).Mod(h1Int, n)
	h1Octets := int2octets(h1Mod, rolen)
	xOctets := int2octets(d, rolen)

	// V = 0x01 重复 hashLen 次；K = 0x00 重复 hashLen 次
	V := bytes_repeat(0x01, hashLen)
	K := bytes_repeat(0x00, hashLen)

	// K = HMAC_K(V || 0x00 || x_octets || h1_octets)
	K = hmacSum(newHash, K, V, []byte{0x00}, xOctets, h1Octets)
	V = hmacSum(newHash, K, V)
	K = hmacSum(newHash, K, V, []byte{0x01}, xOctets, h1Octets)
	V = hmacSum(newHash, K, V)

	for {
		// 生成 T，长度 >= qlen
		T := make([]byte, 0, rolen)
		for len(T) < rolen {
			V = hmacSum(newHash, K, V)
			T = append(T, V...)
		}
		k := bits2int(T, params.BitSize)
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			// 计算 r = (k*G).x mod n
			kBytes := int2octets(k, rolen)
			x, _ := curve.ScalarBaseMult(kBytes)
			r := new(big.Int).Mod(x, n)
			if r.Sign() != 0 {
				// s = k^-1 * (h + r*d) mod n
				kInv := new(big.Int).ModInverse(k, n)
				if kInv != nil {
					rd := new(big.Int).Mul(r, d)
					rd.Mod(rd, n)
					sum := new(big.Int).Add(h1Mod, rd)
					sum.Mod(sum, n)
					s := new(big.Int).Mul(kInv, sum)
					s.Mod(s, n)
					if s.Sign() != 0 {
						return r, s
					}
				}
			}
		}
		// 失败：迭代 K, V
		K = hmacSum(newHash, K, V, []byte{0x00})
		V = hmacSum(newHash, K, V)
	}
}

// bits2int 取 in 的左侧 qlen 位（不足则补 0），转为大整数。
// 当 in 长度 * 8 > qlen 时，右移多余位。
func bits2int(in []byte, qlen int) *big.Int {
	v := new(big.Int).SetBytes(in)
	vlen := len(in) * 8
	if vlen > qlen {
		v.Rsh(v, uint(vlen-qlen))
	}
	return v
}

// int2octets 将 v 编码为定长 rolen 字节大端。
func int2octets(v *big.Int, rolen int) []byte {
	out := make([]byte, rolen)
	v.FillBytes(out)
	return out
}

func bytes_repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// hmacSum 计算 HMAC(key, concat(parts...))。
func hmacSum(newHash func() hash.Hash, key []byte, parts ...[]byte) []byte {
	mac := hmac.New(newHash, key)
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}
