package session

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

// 默认时间常量。
const (
	// PeerKeyCacheTTL 对端 IK 缓存有效期（1 小时）
	PeerKeyCacheTTL = 1 * time.Hour
	// DestroyDelaySeconds 旧 SPK 销毁安全窗口（7 天）
	DestroyDelaySeconds = 7 * 24 * 3600
	// RecentGenerations 最近 N 代 SPK 保留窗口
	RecentGenerations = 7
	// HardLimitSeconds SPK 180 天硬上限
	HardLimitSeconds = 180 * 24 * 3600
)

// CallFn 服务端 RPC 调用，由 client 注入。
//
// 用于 EnsureRegistered/RotateSPK 调 message.v2.put_peer_pk。
type CallFn func(ctx context.Context, method string, params map[string]any) (map[string]any, error)

// SenderIdentity 加密时使用的发送方身份。
type SenderIdentity struct {
	AID      string
	DeviceID string
	IKPriv   []byte // P-256 标量 32B
	IKPubDER []byte // SubjectPublicKeyInfo DER
}

// peerIKCacheEntry 对端 IK 缓存项。
type peerIKCacheEntry struct {
	pubDER   []byte
	cachedAt time.Time
}

// oldSPKSeq 旧 SPK 的最大引用 seq + 最近一次见到的时间。
type oldSPKSeq struct {
	seq        int64
	lastSeenAt time.Time
}

// V2Session 单设备 V2 E2EE 会话。
//
// 职责：
//   - 维护本设备 IK + SPK 密钥状态
//   - 注册/轮换 SPK 到服务端
//   - 提供加解密所需密钥
//   - 缓存对端 IK 公钥（带 TTL）
//   - 跟踪并销毁旧 SPK（PFS）
//
// 并发安全：所有公开方法均加锁。
type V2Session struct {
	store    *V2KeyStore
	deviceID string
	aid      string

	ikPriv   []byte // = AID 私钥（多设备共享 AID 身份）
	ikPubDER []byte

	spkID      string
	spkPriv    []byte
	spkPubDER  []byte
	registered bool

	// SPK 上传去重
	lastUploadedSPKID     string
	lastUploadedGroupSPKs map[string]string // group_id -> spk_id

	// 对端 IK 缓存：key = peer_aid#device_id
	peerIKCache map[string]peerIKCacheEntry

	// 已验证对端 SPK 集合：key = peer_aid#device_id#spk_id
	verifiedSPKs map[string]bool

	// 旧 SPK 引用最大 seq 跟踪：key = spk_id
	oldSPKMaxSeq map[string]oldSPKSeq

	// 旧 SPK 私钥内存缓存：key = spk_id
	spkCache map[string][]byte

	// nowFn 时间源 hook（测试可注入）
	nowFn func() time.Time

	mu sync.Mutex
}

// NewV2Session 创建会话。
//
// aidPriv / aidPubDER 是 AID 长期密钥（IK），由调用方从 keystore 加载并注入。
// IK 不在本包生成，因为 IK = AID 身份本身。
func NewV2Session(store *V2KeyStore, deviceID, aid string, aidPriv, aidPubDER []byte) *V2Session {
	return &V2Session{
		store:                 store,
		deviceID:              deviceID,
		aid:                   aid,
		ikPriv:                aidPriv,
		ikPubDER:              aidPubDER,
		peerIKCache:           make(map[string]peerIKCacheEntry),
		verifiedSPKs:          make(map[string]bool),
		oldSPKMaxSeq:          make(map[string]oldSPKSeq),
		spkCache:              make(map[string][]byte),
		lastUploadedGroupSPKs: make(map[string]string),
		nowFn:                 time.Now,
	}
}

// SetNowFnForTest 注入虚拟时间源（仅供测试使用）。
func (s *V2Session) SetNowFnForTest(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if fn == nil {
		fn = time.Now
	}
	s.nowFn = fn
}

// EnsureKeys 确保 IK 和 SPK 已加载或生成。
//
// IK 必须在构造时注入；SPK 不存在时本方法生成新的。
func (s *V2Session) EnsureKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ensureKeysLocked()
}

func (s *V2Session) ensureKeysLocked() error {
	if len(s.ikPriv) == 0 || len(s.ikPubDER) == 0 {
		return fmt.Errorf("V2Session: 缺少 AID 主密钥（IK = AID identity）")
	}
	if err := s.store.SaveIK(s.deviceID, s.ikPriv, s.ikPubDER); err != nil {
		return err
	}
	if len(s.spkPriv) > 0 {
		return nil
	}
	// 加载已有 SPK
	spkID, priv, pubDER, err := s.store.LoadCurrentSPK(s.deviceID)
	if err != nil {
		return err
	}
	if len(priv) > 0 {
		s.spkID = spkID
		s.spkPriv = priv
		s.spkPubDER = pubDER
		return nil
	}
	// 生成新 SPK
	return s.generateNewSPKLocked()
}

// generateNewSPKLocked 生成并保存新 SPK，更新内存状态。
func (s *V2Session) generateNewSPKLocked() error {
	priv, pubDER, err := crypto.GenerateP256Keypair()
	if err != nil {
		return fmt.Errorf("V2Session: 生成 SPK 失败: %w", err)
	}
	h := sha256.Sum256(pubDER)
	spkID := "sha256:" + hex.EncodeToString(h[:])[:16]
	if err := s.store.SaveSPK(s.deviceID, spkID, priv, pubDER); err != nil {
		return err
	}
	s.spkID = spkID
	s.spkPriv = priv
	s.spkPubDER = pubDER
	return nil
}

func (s *V2Session) ikSPKIDLocked() string {
	h := sha256.Sum256(s.ikPubDER)
	return "sha256:" + hex.EncodeToString(h[:])[:16]
}

func normalizeGroupSPKLookup(groupID, spkID string) (string, string) {
	parts := strings.SplitN(spkID, "\x00", 2)
	if len(parts) != 2 {
		return groupID, spkID
	}
	return parts[0], parts[1]
}

// putPeerPKParams 构造 message.v2.put_peer_pk 调用参数（已锁定状态下使用）。
func (s *V2Session) putPeerPKParamsLocked() (map[string]any, error) {
	spkTimestamp := s.nowFn().Unix()
	tsStr := strconv.FormatInt(spkTimestamp, 10)
	signData := make([]byte, 0, len(s.spkPubDER)+len(s.spkID)+len(tsStr))
	signData = append(signData, s.spkPubDER...)
	signData = append(signData, []byte(s.spkID)...)
	signData = append(signData, []byte(tsStr)...)
	signature, err := crypto.ECDSASignRaw(s.ikPriv, signData)
	if err != nil {
		return nil, fmt.Errorf("V2Session: SPK 签名失败: %w", err)
	}
	return map[string]any{
		"peer_aid":      s.aid,
		"key_source":    "peer_device_prekey",
		"spk_id":        s.spkID,
		"spk_pk":        base64.StdEncoding.EncodeToString(s.spkPubDER),
		"spk_signature": base64.StdEncoding.EncodeToString(signature),
		"spk_timestamp": spkTimestamp,
	}, nil
}

// EnsureRegistered 注册当前 SPK 到服务端。幂等，重复调用直接返回。
func (s *V2Session) EnsureRegistered(ctx context.Context, callFn CallFn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registered {
		return nil
	}
	if err := s.ensureKeysLocked(); err != nil {
		return err
	}
	uploadedSPKID, err := s.store.LoadLatestUploadedSPKID(s.deviceID)
	if err != nil {
		return err
	}
	if uploadedSPKID != "" {
		s.registered = true
		s.lastUploadedSPKID = uploadedSPKID
		return nil
	}
	params, err := s.putPeerPKParamsLocked()
	if err != nil {
		return err
	}
	if _, err := callFn(ctx, "message.v2.put_peer_pk", params); err != nil {
		return fmt.Errorf("V2Session.EnsureRegistered: %w", err)
	}
	if err := s.store.MarkSPKUploaded(s.deviceID, s.spkID); err != nil {
		return err
	}
	s.registered = true
	s.lastUploadedSPKID = s.spkID
	return nil
}

// GetSenderIdentity 返回加密所需的 sender 信息。
func (s *V2Session) GetSenderIdentity() (SenderIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKeysLocked(); err != nil {
		return SenderIdentity{}, err
	}
	return SenderIdentity{
		AID:      s.aid,
		DeviceID: s.deviceID,
		IKPriv:   s.ikPriv,
		IKPubDER: s.ikPubDER,
	}, nil
}

// GetDecryptKeys 根据消息中的 spk_id 返回 (ikPriv, spkPriv)。
//
//   - spkID == "" → 1DH 路径，spkPriv 为 nil
//   - spkID == 当前/历史 device SPK → 返回对应 spkPriv
//   - spkID == IK 指纹 → 走 IK 特殊 fallback，返回 IK 私钥作为 spkPriv
//   - 其它 → 返回 spk_missing
func (s *V2Session) GetDecryptKeys(spkID string) (ikPriv, spkPriv []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKeysLocked(); err != nil {
		return nil, nil, err
	}
	if spkID == "" {
		return s.ikPriv, nil, nil
	}
	if spkID == s.spkID {
		return s.ikPriv, s.spkPriv, nil
	}
	if cached, ok := s.spkCache[spkID]; ok {
		return s.ikPriv, cached, nil
	}
	oldSPK, err := s.store.LoadSPK(s.deviceID, spkID)
	if err != nil {
		return nil, nil, err
	}
	if len(oldSPK) > 0 {
		s.spkCache[spkID] = oldSPK
		return s.ikPriv, oldSPK, nil
	}
	ikAliasPriv, _, err := s.store.LoadIKSPK(s.deviceID, spkID)
	if err != nil {
		return nil, nil, err
	}
	if len(ikAliasPriv) > 0 {
		return ikAliasPriv, ikAliasPriv, nil
	}
	if spkID == s.ikSPKIDLocked() {
		if err := s.store.SaveIK(s.deviceID, s.ikPriv, s.ikPubDER); err != nil {
			return nil, nil, err
		}
		return s.ikPriv, s.ikPriv, nil
	}
	return nil, nil, fmt.Errorf("spk_missing: spk_id=%s", spkID)
}

// IsCurrentSPK 判断 spk_id 是否命中当前活跃 SPK。
func (s *V2Session) IsCurrentSPK(spkID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return spkID != "" && spkID == s.spkID
}

// CurrentSPKID 返回当前活跃 SPK 的 ID（未生成时返回空串）。
func (s *V2Session) CurrentSPKID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spkID
}

// TrackOldSPKMaxSeq 跟踪旧 SPK 引用的最大 seq（用于销毁判定）。
//
// 当前活跃 SPK 不被跟踪，传入空 spkID 也跳过。
func (s *V2Session) TrackOldSPKMaxSeq(spkID string, seq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if spkID == "" || spkID == s.spkID {
		return
	}
	cur := s.oldSPKMaxSeq[spkID]
	if seq > cur.seq {
		s.oldSPKMaxSeq[spkID] = oldSPKSeq{seq: seq, lastSeenAt: s.nowFn()}
	}
}

// MaybeDestroyOldSPKs 三重条件销毁旧 SPK，返回被销毁的 spk_id 列表。
//
// 销毁条件（必须全部满足）：
//   - contig_seq >= 该 SPK 引用的最大 seq（接收方已消费）
//   - now - last_seen_at >= 7 天
//   - 不在最近 7 代保留窗口内
func (s *V2Session) MaybeDestroyOldSPKs(contigSeq int64) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var destroyed []string
	now := s.nowFn()

	recentKeep := map[string]bool{}
	if s.store != nil {
		if ids, err := s.store.ListRecentSPKIDs(s.deviceID, RecentGenerations); err == nil {
			for _, id := range ids {
				recentKeep[id] = true
			}
		}
	}

	for spkID, info := range s.oldSPKMaxSeq {
		if spkID == s.spkID {
			continue
		}
		if contigSeq < info.seq {
			continue
		}
		if now.Sub(info.lastSeenAt).Seconds() < DestroyDelaySeconds {
			continue
		}
		if recentKeep[spkID] {
			continue
		}
		if s.store != nil {
			if err := s.store.DeleteSPK(s.deviceID, spkID); err != nil {
				// 记录失败但不中断其它销毁
				continue
			}
		}
		delete(s.oldSPKMaxSeq, spkID)
		destroyed = append(destroyed, spkID)
	}

	// 180 天硬上限：无论是否被引用，超龄 SPK 强制销毁
	// 用 ListExpiredSPKIDsAt + s.nowFn() 让测试虚拟时间也能贯穿过期判定
	if s.store != nil {
		if expired, err := s.store.ListExpiredSPKIDsAt(s.deviceID, float64(HardLimitSeconds), now); err == nil {
			for _, spkID := range expired {
				if spkID == s.spkID {
					continue
				}
				if err := s.store.DeleteSPK(s.deviceID, spkID); err != nil {
					continue
				}
				delete(s.oldSPKMaxSeq, spkID)
				found := false
				for _, d := range destroyed {
					if d == spkID {
						found = true
						break
					}
				}
				if !found {
					destroyed = append(destroyed, spkID)
				}
			}
		}
	}

	return destroyed
}

// RotateSPK 生成新 SPK 并向服务端注册。旧 SPK 保留本地用于解密历史消息。
func (s *V2Session) RotateSPK(ctx context.Context, callFn CallFn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ikPriv) == 0 {
		return fmt.Errorf("V2Session.RotateSPK: 缺少 AID 主密钥")
	}
	if err := s.generateNewSPKLocked(); err != nil {
		return err
	}
	params, err := s.putPeerPKParamsLocked()
	if err != nil {
		return err
	}
	if _, err := callFn(ctx, "message.v2.put_peer_pk", params); err != nil {
		return fmt.Errorf("V2Session.RotateSPK: %w", err)
	}
	if err := s.store.MarkSPKUploaded(s.deviceID, s.spkID); err != nil {
		return err
	}
	s.registered = true
	s.lastUploadedSPKID = s.spkID
	return nil
}

// ── Group SPK 独立管理 ──────────────────────────────────────────

// EnsureGroupSPK 确保指定群有独立 group SPK，返回 (spkID, priv, pubDER)。
func (s *V2Session) EnsureGroupSPK(groupID string) (string, []byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKeysLocked(); err != nil {
		return "", nil, nil, err
	}
	spkID, priv, pub, err := s.store.LoadCurrentGroupSPK(s.deviceID, groupID)
	if err != nil {
		return "", nil, nil, err
	}
	if spkID != "" {
		return spkID, priv, pub, nil
	}
	priv, pub, err = crypto.GenerateP256Keypair()
	if err != nil {
		return "", nil, nil, fmt.Errorf("V2Session.EnsureGroupSPK generate: %w", err)
	}
	h := sha256.Sum256(pub)
	spkID = "sha256:" + hex.EncodeToString(h[:])[:16]
	if err := s.store.SaveGroupSPK(s.deviceID, groupID, spkID, priv, pub); err != nil {
		return "", nil, nil, err
	}
	return spkID, priv, pub, nil
}

// EnsureGroupRegistered 注册指定群的 group SPK。group 服务负责成员鉴权。
func (s *V2Session) EnsureGroupRegistered(ctx context.Context, groupID string, callFn CallFn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKeysLocked(); err != nil {
		return err
	}
	uploadedSPKID, err := s.store.LoadLatestUploadedGroupSPKID(s.deviceID, groupID)
	if err != nil {
		return err
	}
	if uploadedSPKID != "" {
		s.lastUploadedGroupSPKs[groupID] = uploadedSPKID
		return nil
	}
	// 加载或生成 group SPK（需要先解锁再加锁，因为 EnsureGroupSPK 也加锁）
	s.mu.Unlock()
	spkID, _, pubDER, err := s.EnsureGroupSPK(groupID)
	s.mu.Lock()
	if err != nil {
		return err
	}
	uploadedSPKID, err = s.store.LoadLatestUploadedGroupSPKID(s.deviceID, groupID)
	if err != nil {
		return err
	}
	if uploadedSPKID != "" {
		s.lastUploadedGroupSPKs[groupID] = uploadedSPKID
		return nil
	}
	return s.publishGroupSPKLocked(ctx, groupID, spkID, pubDER, callFn)
}

// RotateGroupSPK 轮换指定群的 group SPK，保留旧私钥用于缓存窗口内的历史 wrap 解密。
func (s *V2Session) RotateGroupSPK(ctx context.Context, groupID string, callFn CallFn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ikPriv) == 0 {
		return fmt.Errorf("V2Session.RotateGroupSPK: 缺少 AID 主密钥")
	}
	priv, pub, err := crypto.GenerateP256Keypair()
	if err != nil {
		return fmt.Errorf("V2Session.RotateGroupSPK generate: %w", err)
	}
	h := sha256.Sum256(pub)
	spkID := "sha256:" + hex.EncodeToString(h[:])[:16]
	if err := s.store.SaveGroupSPK(s.deviceID, groupID, spkID, priv, pub); err != nil {
		return err
	}
	return s.publishGroupSPKLocked(ctx, groupID, spkID, pub, callFn)
}

// GetGroupDecryptKeys 群消息解密按 group SPK -> device SPK -> IK fallback 查找。
// spkID 非空但三条路径都找不到时返回 spk_missing。
func (s *V2Session) GetGroupDecryptKeys(groupID, spkID string) (ikPriv, spkPriv []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKeysLocked(); err != nil {
		return nil, nil, err
	}
	if spkID == "" {
		return s.ikPriv, nil, nil
	}
	lookupGroupID, lookupSPKID := normalizeGroupSPKLookup(groupID, spkID)
	groupSPK, err := s.store.LoadGroupSPK(s.deviceID, lookupGroupID, lookupSPKID)
	if err != nil {
		return nil, nil, err
	}
	if groupSPK != nil {
		return s.ikPriv, groupSPK, nil
	}
	// fallback 到 device SPK，再 fallback 到 IK 特殊 fallback（兼容历史消息）
	if lookupSPKID == s.spkID {
		return s.ikPriv, s.spkPriv, nil
	}
	oldSPK, err := s.store.LoadSPK(s.deviceID, lookupSPKID)
	if err != nil {
		return nil, nil, err
	}
	if len(oldSPK) > 0 {
		return s.ikPriv, oldSPK, nil
	}
	ikAliasPriv, _, err := s.store.LoadIKSPK(s.deviceID, lookupSPKID)
	if err != nil {
		return nil, nil, err
	}
	if len(ikAliasPriv) > 0 {
		return ikAliasPriv, ikAliasPriv, nil
	}
	if lookupSPKID == s.ikSPKIDLocked() {
		if err := s.store.SaveIK(s.deviceID, s.ikPriv, s.ikPubDER); err != nil {
			return nil, nil, err
		}
		return s.ikPriv, s.ikPriv, nil
	}
	return nil, nil, fmt.Errorf("spk_missing: spk_id=%s", lookupSPKID)
}

// IsLastUploadedSPK 判断 spk_id 是否为本进程最后一次成功上传的 P2P SPK。
func (s *V2Session) IsLastUploadedSPK(spkID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return spkID != "" && spkID == s.lastUploadedSPKID
}

// IsLastUploadedGroupSPK 判断 spk_id 是否为本进程在该群最后一次成功上传的 group SPK。
func (s *V2Session) IsLastUploadedGroupSPK(groupID, spkID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if spkID == "" {
		return false
	}
	lookupGroupID, lookupSPKID := normalizeGroupSPKLookup(groupID, spkID)
	return s.lastUploadedGroupSPKs[lookupGroupID] == lookupSPKID
}

func (s *V2Session) publishGroupSPKLocked(ctx context.Context, groupID, spkID string, pubDER []byte, callFn CallFn) error {
	spkTimestamp := strconv.FormatInt(s.nowFn().Unix(), 10)
	signData := append(append(pubDER, []byte(spkID)...), []byte(spkTimestamp)...)
	sig, err := crypto.ECDSASignRaw(s.ikPriv, signData)
	if err != nil {
		return fmt.Errorf("V2Session.publishGroupSPK sign: %w", err)
	}
	params := map[string]any{
		"group_id":      groupID,
		"key_source":    "group_device_prekey",
		"spk_id":        spkID,
		"spk_pk":        base64.StdEncoding.EncodeToString(pubDER),
		"spk_signature": base64.StdEncoding.EncodeToString(sig),
		"spk_timestamp": spkTimestamp,
	}
	if _, err := callFn(ctx, "group.v2.put_group_pk", params); err != nil {
		return fmt.Errorf("V2Session.publishGroupSPK: %w", err)
	}
	if err := s.store.MarkGroupSPKUploaded(s.deviceID, groupID, spkID); err != nil {
		return err
	}
	s.lastUploadedGroupSPKs[groupID] = spkID
	return nil
}

// CachePeerIK 缓存对端 IK 公钥（带 TTL）。
func (s *V2Session) CachePeerIK(peerAID, deviceID string, pubDER []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerIKCache[peerAID+"#"+deviceID] = peerIKCacheEntry{
		pubDER:   pubDER,
		cachedAt: s.nowFn(),
	}
}

// GetPeerIK 获取对端 IK 公钥；缺失或过期返回 nil。
func (s *V2Session) GetPeerIK(peerAID, deviceID string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := peerAID + "#" + deviceID
	entry, ok := s.peerIKCache[key]
	if !ok {
		return nil
	}
	if s.nowFn().Sub(entry.cachedAt) >= PeerKeyCacheTTL {
		delete(s.peerIKCache, key)
		return nil
	}
	return entry.pubDER
}

// IsPeerSPKVerified 检查对端 SPK 签名是否已验证过。
func (s *V2Session) IsPeerSPKVerified(peerAID, deviceID, spkID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifiedSPKs[peerAID+"#"+deviceID+"#"+spkID]
}

// MarkPeerSPKVerified 标记对端 SPK 已验证。
func (s *V2Session) MarkPeerSPKVerified(peerAID, deviceID, spkID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifiedSPKs[peerAID+"#"+deviceID+"#"+spkID] = true
}

// IKPubDER 返回 IK 公钥 DER（先确保 keys 已就绪）。
func (s *V2Session) IKPubDER() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureKeysLocked(); err != nil {
		return nil, err
	}
	return s.ikPubDER, nil
}

// DeviceID 返回设备 ID。
func (s *V2Session) DeviceID() string {
	return s.deviceID
}

// AID 返回 AID。
func (s *V2Session) AID() string {
	return s.aid
}
