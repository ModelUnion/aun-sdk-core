package aun

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	v2crypto "github.com/modelunion/aun-sdk-core/go/v2/crypto"
)

const (
	GroupIndexSchema = "aun.group.index.v1"
	GroupIndexKey    = "group.index"
	GroupIndexSigAlg = "ECDSA-P256-SHA256"
)

type GroupIndexSigner interface {
	Sign(payload []byte) (string, error)
	Verify(payload []byte, signature string) (bool, error)
}

type GroupIndexBuildOptions struct {
	GroupAID     string
	Entries      []map[string]any
	Signer       GroupIndexSigner
	LastModified int64
	Schema       string
}

type GroupSettingsWithIndexOptions struct {
	GroupAID     string
	Settings     map[string]any
	Signer       GroupIndexSigner
	LastModified int64
	BaseIndex    any
}

type SignedGroupIndex struct {
	Body    string           `json:"body"`
	Meta    map[string]any   `json:"meta"`
	Entries []map[string]any `json:"entries"`
}

type ParsedGroupIndex struct {
	Meta    map[string]any
	Entries []map[string]any
}

type GroupIndexVerifyResult struct {
	Valid   bool
	Reason  string
	Meta    map[string]any
	Entries []map[string]any
}

type GroupIndexMetaCache struct {
	aunPath    string
	mu         sync.Mutex
	remote     map[string]map[string]any
	localEtags map[string]string
	stale      map[string]bool
	settings   map[string]map[string]any
	entryEtags map[string]map[string]string
}

func NewGroupIndexMetaCache(aunPath ...string) *GroupIndexMetaCache {
	root := ""
	if len(aunPath) > 0 {
		root = strings.TrimSpace(aunPath[0])
	}
	return &GroupIndexMetaCache{
		aunPath:    root,
		remote:     map[string]map[string]any{},
		localEtags: map[string]string{},
		stale:      map[string]bool{},
		settings:   map[string]map[string]any{},
		entryEtags: map[string]map[string]string{},
	}
}

func (c *GroupIndexMetaCache) ObserveRPCMeta(meta map[string]any, localAID string) {
	if c == nil {
		return
	}
	groupIndexes, ok := mapFromAny(meta["group_indexes"])
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for groupAID, raw := range groupIndexes {
		value, ok := mapFromAny(raw)
		if !ok {
			continue
		}
		key := c.cacheKey(localAID, groupAID)
		c.loadKeyLocked(localAID, groupAID)
		remoteMeta := map[string]any{}
		for _, name := range []string{"etag", "last_modified", "schema"} {
			if v, exists := value[name]; exists && v != nil {
				remoteMeta[name] = v
			}
		}
		c.remote[key] = remoteMeta
		remoteEtag := stringValue(remoteMeta["etag"])
		if remoteEtag != "" && c.localEtags[key] != remoteEtag {
			c.stale[key] = true
		}
		c.saveKeyLocked(localAID, groupAID)
	}
}

func (c *GroupIndexMetaCache) MarkFresh(localAID, groupAID, etag string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.cacheKey(localAID, groupAID)
	c.loadKeyLocked(localAID, groupAID)
	c.localEtags[key] = etag
	delete(c.stale, key)
	c.saveKeyLocked(localAID, groupAID)
}

func (c *GroupIndexMetaCache) IsStale(localAID, groupAID string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadKeyLocked(localAID, groupAID)
	return c.stale[c.cacheKey(localAID, groupAID)]
}

func (c *GroupIndexMetaCache) RemoteMeta(localAID, groupAID string) map[string]any {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadKeyLocked(localAID, groupAID)
	value := c.remote[c.cacheKey(localAID, groupAID)]
	if value == nil {
		return nil
	}
	return cloneMap(value)
}

func (c *GroupIndexMetaCache) LocalEtag(localAID, groupAID string) string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadKeyLocked(localAID, groupAID)
	return c.localEtags[c.cacheKey(localAID, groupAID)]
}

func (c *GroupIndexMetaCache) CachedSettings(localAID, groupAID string, keys []string) map[string]any {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadKeyLocked(localAID, groupAID)
	value := c.settings[c.cacheKey(localAID, groupAID)]
	if value == nil {
		return nil
	}
	out := map[string]any{}
	for _, key := range keys {
		if item, ok := value[key]; ok {
			out[key] = item
		} else {
			return nil
		}
	}
	return out
}

func (c *GroupIndexMetaCache) CachedSettingsByEntries(localAID, groupAID string, keys []string, entries []map[string]any) (map[string]any, []string) {
	cached := map[string]any{}
	missing := []string{}
	if c == nil {
		return cached, keys
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cacheKey := c.cacheKey(localAID, groupAID)
	c.loadKeyLocked(localAID, groupAID)
	settings := c.settings[cacheKey]
	localEntryEtags := c.entryEtags[cacheKey]
	remoteEntryEtags := map[string]string{}
	for _, entry := range entries {
		remoteEntryEtags[stringValue(entry["key"])] = stringValue(entry["etag"])
	}
	for _, key := range keys {
		if settings != nil && localEntryEtags != nil && localEntryEtags[key] == remoteEntryEtags[key] {
			if value, ok := settings[key]; ok {
				cached[key] = value
				continue
			}
		}
		missing = append(missing, key)
	}
	return cached, missing
}

func (c *GroupIndexMetaCache) CacheSettings(localAID, groupAID string, settings map[string]any, entries []map[string]any, etag string, groupIndex ...any) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := c.cacheKey(localAID, groupAID)
	c.loadKeyLocked(localAID, groupAID)
	current := c.settings[key]
	if current == nil {
		current = map[string]any{}
		c.settings[key] = current
	}
	for name, value := range settings {
		current[name] = value
	}
	if entries != nil {
		entryEtags := c.entryEtags[key]
		if entryEtags == nil {
			entryEtags = map[string]string{}
			c.entryEtags[key] = entryEtags
		}
		for _, entry := range entries {
			entryKey := stringValue(entry["key"])
			if entryKey != "" {
				entryEtags[entryKey] = stringValue(entry["etag"])
			}
		}
	}
	if etag != "" {
		c.localEtags[key] = etag
		delete(c.stale, key)
	}
	c.saveKeyLocked(localAID, groupAID)
	if len(groupIndex) > 0 {
		c.saveGroupIndexBodyLocked(localAID, groupAID, groupIndex[0])
	}
}

func (c *GroupIndexMetaCache) cacheKey(localAID, groupAID string) string {
	return strings.TrimSpace(localAID) + "\x00" + strings.TrimSpace(groupAID)
}

func (c *GroupIndexMetaCache) dirFor(localAID, groupAID string) string {
	if c == nil || strings.TrimSpace(c.aunPath) == "" {
		return ""
	}
	local := strings.TrimSpace(localAID)
	group := strings.TrimSpace(groupAID)
	if local == "" || group == "" {
		return ""
	}
	if strings.ContainsAny(local, `/\`+"\x00") || strings.ContainsAny(group, `/\`+"\x00") {
		return ""
	}
	return filepath.Join(c.aunPath, "AIDs", local, "groups", group)
}

func (c *GroupIndexMetaCache) cachePath(localAID, groupAID string) string {
	dir := c.dirFor(localAID, groupAID)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "group-index-cache.json")
}

func (c *GroupIndexMetaCache) indexPath(localAID, groupAID string) string {
	dir := c.dirFor(localAID, groupAID)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "index.jsonl")
}

func (c *GroupIndexMetaCache) loadKeyLocked(localAID, groupAID string) {
	key := c.cacheKey(localAID, groupAID)
	if c.remote[key] != nil || c.localEtags[key] != "" || c.settings[key] != nil || c.entryEtags[key] != nil {
		return
	}
	path := c.cachePath(localAID, groupAID)
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return
	}
	if remoteMeta, ok := mapFromAny(payload["remote_meta"]); ok {
		c.remote[key] = cloneMap(remoteMeta)
	}
	if localEtag := stringValue(payload["local_etag"]); localEtag != "" {
		c.localEtags[key] = localEtag
	}
	if settings, ok := mapFromAny(payload["settings"]); ok {
		c.settings[key] = cloneMap(settings)
	}
	if rawEntryEtags, ok := mapFromAny(payload["entry_etags"]); ok {
		entryEtags := map[string]string{}
		for entryKey, entryEtag := range rawEntryEtags {
			entryEtags[entryKey] = stringValue(entryEtag)
		}
		c.entryEtags[key] = entryEtags
	}
	remoteEtag := stringValue(c.remote[key]["etag"])
	if remoteEtag != "" && c.localEtags[key] != remoteEtag {
		c.stale[key] = true
	}
}

func (c *GroupIndexMetaCache) saveKeyLocked(localAID, groupAID string) {
	path := c.cachePath(localAID, groupAID)
	if path == "" {
		return
	}
	key := c.cacheKey(localAID, groupAID)
	payload := map[string]any{
		"local_aid":   strings.TrimSpace(localAID),
		"group_aid":   strings.TrimSpace(groupAID),
		"remote_meta": c.remote[key],
		"local_etag":  c.localEtags[key],
		"settings":    c.settings[key],
		"entry_etags": c.entryEtags[key],
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	data = append(data, '\n')
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, data, 0o600)
}

func (c *GroupIndexMetaCache) saveGroupIndexBodyLocked(localAID, groupAID string, groupIndex any) {
	text := groupIndexBodyText(groupIndex)
	if text == "" {
		return
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	path := c.indexPath(localAID, groupAID)
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte(text), 0o600)
}

func ComputeGroupIndexBodyHash(entries []map[string]any) string {
	return "sha256:" + sha256Hex(groupIndexEntriesBytes(entries))
}

func GroupIndexEtag(entries []map[string]any) string {
	return `"sha256:` + sha256Hex(groupIndexEntriesBytes(entries)) + `"`
}

func GroupIndexSigningPayload(meta map[string]any, entries []map[string]any) []byte {
	metaWithoutSignature := cloneMap(meta)
	delete(metaWithoutSignature, "signature")
	lines := []string{canonicalJSONString(metaWithoutSignature)}
	for _, entry := range canonicalGroupIndexEntries(entries) {
		lines = append(lines, canonicalJSONString(entry))
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func BuildSignedGroupIndex(opts GroupIndexBuildOptions) (*SignedGroupIndex, error) {
	if opts.Signer == nil {
		return nil, fmt.Errorf("signer is required")
	}
	signerAID := groupIndexSignerAID(opts.Signer)
	if signerAID == "" {
		return nil, fmt.Errorf("signer aid is required")
	}
	schema := opts.Schema
	if schema == "" {
		schema = GroupIndexSchema
	}
	entries := canonicalGroupIndexEntries(opts.Entries)
	meta := map[string]any{
		"type":          "index_meta",
		"group_aid":     strings.TrimSpace(opts.GroupAID),
		"etag":          GroupIndexEtag(entries),
		"last_modified": opts.LastModified,
		"schema":        schema,
		"body_hash":     ComputeGroupIndexBodyHash(entries),
		"signed_by":     signerAID,
		"sig_alg":       GroupIndexSigAlg,
	}
	signature, err := opts.Signer.Sign(GroupIndexSigningPayload(meta, entries))
	if err != nil {
		return nil, fmt.Errorf("group index signing failed: %w", err)
	}
	meta["signature"] = signature
	lines := []string{canonicalJSONString(meta)}
	for _, entry := range entries {
		lines = append(lines, canonicalJSONString(entry))
	}
	body := strings.Join(lines, "\n") + "\n"
	return &SignedGroupIndex{Body: body, Meta: meta, Entries: entries}, nil
}

func ParseGroupIndex(body any) (*ParsedGroupIndex, error) {
	text := groupIndexBodyText(body)
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("group index body is empty")
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &meta); err != nil {
		return nil, err
	}
	if stringValue(meta["type"]) != "index_meta" {
		return nil, fmt.Errorf("first group index line must be index_meta")
	}
	entries := make([]map[string]any, 0, len(lines)-1)
	for _, line := range lines[1:] {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return &ParsedGroupIndex{Meta: meta, Entries: entries}, nil
}

func VerifyGroupIndex(body any, signer GroupIndexSigner) (*GroupIndexVerifyResult, error) {
	parsed, err := ParseGroupIndex(body)
	if err != nil {
		return nil, err
	}
	signature := stringValue(parsed.Meta["signature"])
	if signature == "" {
		return &GroupIndexVerifyResult{Valid: false, Reason: "signature missing"}, nil
	}
	if stringValue(parsed.Meta["signed_by"]) != groupIndexSignerAID(signer) {
		return &GroupIndexVerifyResult{Valid: false, Reason: "signed_by mismatch"}, nil
	}
	if stringValue(parsed.Meta["sig_alg"]) != GroupIndexSigAlg {
		return &GroupIndexVerifyResult{Valid: false, Reason: "unsupported sig_alg"}, nil
	}
	if stringValue(parsed.Meta["body_hash"]) != ComputeGroupIndexBodyHash(parsed.Entries) {
		return &GroupIndexVerifyResult{Valid: false, Reason: "body_hash mismatch"}, nil
	}
	if stringValue(parsed.Meta["etag"]) != GroupIndexEtag(parsed.Entries) {
		return &GroupIndexVerifyResult{Valid: false, Reason: "etag mismatch"}, nil
	}
	ok, err := signer.Verify(GroupIndexSigningPayload(parsed.Meta, parsed.Entries), signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return &GroupIndexVerifyResult{Valid: false, Reason: "signature verification failed"}, nil
	}
	return &GroupIndexVerifyResult{Valid: true, Meta: parsed.Meta, Entries: canonicalGroupIndexEntries(parsed.Entries)}, nil
}

func PrepareGroupSettingsWithIndex(opts GroupSettingsWithIndexOptions) (map[string]any, error) {
	result := cloneMap(opts.Settings)
	updatedEntries := []map[string]any{}
	for key, value := range opts.Settings {
		if key == GroupIndexKey {
			continue
		}
		updatedEntries = append(updatedEntries, groupIndexSettingEntry(key, value, opts.LastModified))
	}
	updatedKeys := map[string]bool{}
	for _, entry := range updatedEntries {
		updatedKeys[stringValue(entry["key"])] = true
	}
	entries := []map[string]any{}
	if opts.BaseIndex != nil {
		parsed, err := ParseGroupIndex(opts.BaseIndex)
		if err != nil {
			return nil, err
		}
		for _, entry := range parsed.Entries {
			if !updatedKeys[stringValue(entry["key"])] {
				entries = append(entries, cloneMap(entry))
			}
		}
	}
	entries = append(entries, updatedEntries...)
	signed, err := BuildSignedGroupIndex(GroupIndexBuildOptions{
		GroupAID:     opts.GroupAID,
		Entries:      entries,
		Signer:       opts.Signer,
		LastModified: opts.LastModified,
	})
	if err != nil {
		return nil, err
	}
	result[GroupIndexKey] = signedGroupIndexJSONValue(signed)
	return result, nil
}

func signedGroupIndexJSONValue(signed *SignedGroupIndex) map[string]any {
	if signed == nil {
		return map[string]any{}
	}
	return map[string]any{
		"body":    signed.Body,
		"meta":    signed.Meta,
		"entries": signed.Entries,
	}
}

func groupIndexSettingEntry(key string, value any, lastModified int64) map[string]any {
	digest := sha256Hex([]byte(canonicalJSONString(value)))
	return map[string]any{
		"key":           key,
		"source":        "db",
		"etag":          `"sha256:` + digest + `"`,
		"last_modified": lastModified,
	}
}

func groupIndexEntriesBytes(entries []map[string]any) []byte {
	lines := []string{}
	for _, entry := range canonicalGroupIndexEntries(entries) {
		lines = append(lines, canonicalJSONString(entry))
	}
	if len(lines) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func canonicalGroupIndexEntries(entries []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		out = append(out, cloneMap(entry))
	}
	sort.Slice(out, func(i, j int) bool {
		return compareGroupIndexCodePoints(stringValue(out[i]["key"]), stringValue(out[j]["key"])) < 0
	})
	return out
}

func canonicalJSONString(value any) string {
	return string(v2crypto.CanonicalJSON(value))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func groupIndexBodyText(body any) string {
	switch v := body.(type) {
	case nil:
		return ""
	case string:
		return v
	case []byte:
		return string(v)
	case *SignedGroupIndex:
		if v == nil {
			return ""
		}
		return v.Body
	case SignedGroupIndex:
		return v.Body
	case map[string]any:
		return stringValue(v["body"])
	default:
		return fmt.Sprint(v)
	}
}

func groupIndexSignerAID(signer GroupIndexSigner) string {
	if signer == nil {
		return ""
	}
	if aid, ok := signer.(*AID); ok && aid != nil {
		return aid.Aid
	}
	if provider, ok := signer.(interface{ AID() string }); ok {
		return strings.TrimSpace(provider.AID())
	}
	if provider, ok := signer.(interface{ GetAID() string }); ok {
		return strings.TrimSpace(provider.GetAID())
	}
	return ""
}

func cloneMap(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func mapFromAny(value any) (map[string]any, bool) {
	if m, ok := value.(map[string]any); ok {
		return m, true
	}
	return nil, false
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func groupIndexInt64(value any, fallback int64) int64 {
	switch v := value.(type) {
	case nil:
		return fallback
	case int:
		return int64(v)
	case int8:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint:
		return int64(v)
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		if v > math.MaxInt64 {
			return fallback
		}
		return int64(v)
	case float32:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(v.String(), 64); err == nil {
			return int64(f)
		}
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return i
		}
	}
	return fallback
}

func compareGroupIndexCodePoints(a, b string) int {
	ar := []rune(a)
	br := []rune(b)
	n := len(ar)
	if len(br) < n {
		n = len(br)
	}
	for i := 0; i < n; i++ {
		if ar[i] < br[i] {
			return -1
		}
		if ar[i] > br[i] {
			return 1
		}
	}
	switch {
	case len(ar) < len(br):
		return -1
	case len(ar) > len(br):
		return 1
	default:
		return 0
	}
}
