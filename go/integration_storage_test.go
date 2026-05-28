//go:build integration

package aun

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func storageDownloadBytes(t *testing.T, urlText string) []byte {
	t.Helper()
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 测试环境使用自签名证书
		},
	}
	resp, err := client.Get(urlText)
	if err != nil {
		t.Fatalf("HTTP 下载失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		t.Fatalf("HTTP 下载状态异常: status=%d body=%s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取 HTTP 响应失败: %v", err)
	}
	return body
}

// ---------------------------------------------------------------------------
// TestIntegration_StorageInlinePutGetDelete
// 覆盖：inline 存取（put/head/get/delete）、公开对象跨 AID 可读、私有对象跨 AID 拒绝
// ---------------------------------------------------------------------------

func TestIntegration_StorageInlinePutGetDelete(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("sto%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("sto%s-b.%s", rid, testIssuer())
	bucket := fmt.Sprintf("test-bucket-%s", rid)

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 写入私有对象 ----
	privateBody := fmt.Sprintf("secret-%s", rid)
	privateKey := fmt.Sprintf("private/docs/%s/secret.txt", rid)
	privateContent := base64.StdEncoding.EncodeToString([]byte(privateBody))

	putResult, err := alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   privateKey,
		"content":      privateContent,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Skipf("storage 服务不可用: %v", err)
	}
	putMap, _ := putResult.(map[string]any)
	if putMap == nil || putMap["object_key"] != privateKey {
		t.Fatalf("put_object 返回异常: %#v", putResult)
	}

	// ---- head 验证 size 和 is_private ----
	headResult, err := alice.Call(ctx, "storage.head_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": privateKey,
	})
	if err != nil {
		t.Fatalf("head_object 失败: %v", err)
	}
	headMap, _ := headResult.(map[string]any)
	if headMap == nil {
		t.Fatalf("head_object 返回 nil")
	}
	if int(toInt64(headMap["size_bytes"])) != len(privateBody) {
		t.Fatalf("head_object size_bytes 不匹配: 期望 %d, 实际 %v", len(privateBody), headMap["size_bytes"])
	}
	if isPrivate, ok := headMap["is_private"].(bool); !ok || !isPrivate {
		t.Fatalf("head_object is_private 应为 true: %#v", headMap)
	}

	// ---- get 验证内容匹配 ----
	getResult, err := alice.Call(ctx, "storage.get_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": privateKey,
	})
	if err != nil {
		t.Fatalf("get_object 失败: %v", err)
	}
	getMap, _ := getResult.(map[string]any)
	if getMap == nil {
		t.Fatalf("get_object 返回 nil")
	}
	gotContent, _ := getMap["content"].(string)
	decoded, err := base64.StdEncoding.DecodeString(gotContent)
	if err != nil {
		t.Fatalf("get_object content base64 解码失败: %v", err)
	}
	if string(decoded) != privateBody {
		t.Fatalf("get_object 内容不匹配: 期望 %q, 实际 %q", privateBody, string(decoded))
	}

	// ---- delete 验证 deleted: true ----
	delResult, err := alice.Call(ctx, "storage.delete_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": privateKey,
	})
	if err != nil {
		t.Fatalf("delete_object 失败: %v", err)
	}
	delMap, _ := delResult.(map[string]any)
	if delMap == nil {
		t.Fatalf("delete_object 返回 nil")
	}
	if deleted, ok := delMap["deleted"].(bool); !ok || !deleted {
		t.Fatalf("delete_object deleted 应为 true: %#v", delMap)
	}

	// ---- 写入公开对象 ----
	publicBody := fmt.Sprintf("public-%s", rid)
	publicKey := fmt.Sprintf("public/docs/%s/readme.txt", rid)
	publicContent := base64.StdEncoding.EncodeToString([]byte(publicBody))

	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   publicKey,
		"content":      publicContent,
		"content_type": "text/plain",
		"is_private":   false,
	})
	if err != nil {
		t.Fatalf("put_object 公开对象失败: %v", err)
	}

	// ---- Bob 可以读取公开对象 ----
	bobGetResult, err := bob.Call(ctx, "storage.get_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": publicKey,
	})
	if err != nil {
		t.Fatalf("Bob 读取公开对象失败: %v", err)
	}
	bobGetMap, _ := bobGetResult.(map[string]any)
	bobGotContent, _ := bobGetMap["content"].(string)
	bobDecoded, err := base64.StdEncoding.DecodeString(bobGotContent)
	if err != nil {
		t.Fatalf("Bob get_object content base64 解码失败: %v", err)
	}
	if string(bobDecoded) != publicBody {
		t.Fatalf("Bob get_object 内容不匹配: 期望 %q, 实际 %q", publicBody, string(bobDecoded))
	}

	// ---- Bob 不能读取私有对象（已删除，但测试权限拒绝逻辑） ----
	// 重新写入一个私有对象用于测试 Bob 的权限拒绝
	privateKey2 := fmt.Sprintf("private/docs/%s/secret2.txt", rid)
	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   privateKey2,
		"content":      privateContent,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Fatalf("put_object 第二个私有对象失败: %v", err)
	}

	_, err = bob.Call(ctx, "storage.get_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": privateKey2,
	})
	if err == nil {
		t.Fatalf("Bob 读取私有对象应失败，但成功了")
	}
	t.Logf("Bob 读取私有对象被拒绝（符合预期）: %v", err)
}

// ---------------------------------------------------------------------------
// TestIntegration_StoragePrefixPaginationAndVersionConflict
// 覆盖：list_prefixes、list_objects 分页、overwrite 冲突、expected_version 冲突
// ---------------------------------------------------------------------------

func TestIntegration_StoragePrefixPaginationAndVersionConflict(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	defer alice.Close()

	aliceAID := fmt.Sprintf("sto%s.%s", rid, testIssuer())
	bucket := fmt.Sprintf("test-bucket-%s", rid)

	ensureConnected(t, alice, aliceAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	b64 := func(s string) string {
		return base64.StdEncoding.EncodeToString([]byte(s))
	}

	// ---- 写入 3 个 docs/ 前缀对象 + 1 个 notes/ 前缀对象 ----
	putA, err := alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   "docs/a.txt",
		"content":      b64(fmt.Sprintf("A-%s", rid)),
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Skipf("storage 服务不可用: %v", err)
	}
	putAMap, _ := putA.(map[string]any)

	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   "docs/b.txt",
		"content":      b64(fmt.Sprintf("B-%s", rid)),
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Fatalf("put_object docs/b.txt 失败: %v", err)
	}

	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   "docs/c.txt",
		"content":      b64(fmt.Sprintf("C-%s", rid)),
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Fatalf("put_object docs/c.txt 失败: %v", err)
	}

	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   "notes/c.txt",
		"content":      b64(fmt.Sprintf("N-%s", rid)),
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Fatalf("put_object notes/c.txt 失败: %v", err)
	}

	// ---- list_prefixes 验证返回 docs/ 和 notes/ ----
	prefixResult, err := alice.Call(ctx, "storage.list_prefixes", map[string]any{
		"owner_aid": aliceAID,
		"bucket":    bucket,
		"prefix":    "",
		"size":      20,
	})
	if err != nil {
		t.Fatalf("list_prefixes 失败: %v", err)
	}
	prefixMap, _ := prefixResult.(map[string]any)
	prefixList, _ := prefixMap["prefixes"].([]any)
	gotPrefixes := make(map[string]bool)
	for _, p := range prefixList {
		gotPrefixes[fmt.Sprintf("%v", p)] = true
	}
	if !gotPrefixes["docs/"] || !gotPrefixes["notes/"] {
		t.Fatalf("list_prefixes 应包含 docs/ 和 notes/，实际: %v", gotPrefixes)
	}

	// ---- list_objects 分页：size=2 返回第一页 ----
	page1Result, err := alice.Call(ctx, "storage.list_objects", map[string]any{
		"owner_aid": aliceAID,
		"bucket":    bucket,
		"prefix":    "docs/",
		"page":      1,
		"size":      2,
	})
	if err != nil {
		t.Fatalf("list_objects page1 失败: %v", err)
	}
	page1Map, _ := page1Result.(map[string]any)
	page1Items, _ := page1Map["items"].([]any)
	if len(page1Items) != 2 {
		t.Fatalf("list_objects page1 应返回 2 项，实际 %d: %#v", len(page1Items), page1Map)
	}
	nextMarker, _ := page1Map["next_marker"].(string)
	if nextMarker == "" {
		t.Fatalf("list_objects page1 应有 next_marker: %#v", page1Map)
	}

	// ---- 使用 marker 获取第二页 ----
	page2Result, err := alice.Call(ctx, "storage.list_objects", map[string]any{
		"owner_aid": aliceAID,
		"bucket":    bucket,
		"prefix":    "docs/",
		"marker":    nextMarker,
		"size":      2,
	})
	if err != nil {
		t.Fatalf("list_objects page2 失败: %v", err)
	}
	page2Map, _ := page2Result.(map[string]any)
	page2Items, _ := page2Map["items"].([]any)
	if len(page2Items) != 1 {
		t.Fatalf("list_objects page2 应返回 1 项，实际 %d: %#v", len(page2Items), page2Map)
	}

	// ---- overwrite=false 拒绝已存在对象 ----
	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   "docs/a.txt",
		"content":      b64(fmt.Sprintf("A-%s", rid)),
		"content_type": "text/plain",
		"overwrite":    false,
	})
	if err == nil {
		t.Fatalf("overwrite=false 对已存在对象应失败，但成功了")
	}
	t.Logf("overwrite=false 被拒绝（符合预期）: %v", err)

	// ---- expected_version 冲突 ----
	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":        aliceAID,
		"bucket":           bucket,
		"object_key":       "docs/a.txt",
		"content":          b64(fmt.Sprintf("A-%s", rid)),
		"content_type":     "text/plain",
		"expected_version": 999,
	})
	if err == nil {
		t.Fatalf("expected_version=999 应失败，但成功了")
	}
	t.Logf("expected_version 冲突被拒绝（符合预期）: %v", err)

	// ---- 正确的 expected_version 应成功并递增版本 ----
	putAVersion := int(toInt64(putAMap["version"]))
	updatedResult, err := alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":        aliceAID,
		"bucket":           bucket,
		"object_key":       "docs/a.txt",
		"content":          b64(fmt.Sprintf("updated-%s", rid)),
		"content_type":     "text/plain",
		"expected_version": putAVersion,
	})
	if err != nil {
		t.Fatalf("正确 expected_version 更新失败: %v", err)
	}
	updatedMap, _ := updatedResult.(map[string]any)
	newVersion := int(toInt64(updatedMap["version"]))
	if newVersion != putAVersion+1 {
		t.Fatalf("更新后版本号应为 %d，实际 %d", putAVersion+1, newVersion)
	}
}

// ---------------------------------------------------------------------------
// TestIntegration_StorageQuota
// 覆盖：配额查询、写入后增加、删除后恢复
// ---------------------------------------------------------------------------

func TestIntegration_StorageQuota(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	defer alice.Close()

	aliceAID := fmt.Sprintf("sto%s.%s", rid, testIssuer())
	bucket := fmt.Sprintf("test-bucket-%s", rid)

	ensureConnected(t, alice, aliceAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- 获取写入前的配额 ----
	quotaBefore, err := alice.Call(ctx, "storage.get_quota", map[string]any{
		"owner_aid": aliceAID,
	})
	if err != nil {
		t.Skipf("storage 服务不可用: %v", err)
	}
	qbMap, _ := quotaBefore.(map[string]any)
	usedBefore := int(toInt64(qbMap["used_bytes"]))

	// ---- 写入对象 ----
	body := fmt.Sprintf("quota-test-%s", rid)
	objectKey := fmt.Sprintf("quota/%s/test.txt", rid)
	content := base64.StdEncoding.EncodeToString([]byte(body))

	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   objectKey,
		"content":      content,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Fatalf("put_object 失败: %v", err)
	}

	// ---- 获取写入后的配额，used_bytes 应增加 ----
	quotaAfterPut, err := alice.Call(ctx, "storage.get_quota", map[string]any{
		"owner_aid": aliceAID,
	})
	if err != nil {
		t.Fatalf("get_quota（写入后）失败: %v", err)
	}
	qapMap, _ := quotaAfterPut.(map[string]any)
	usedAfterPut := int(toInt64(qapMap["used_bytes"]))
	if usedAfterPut <= usedBefore {
		t.Fatalf("写入后 used_bytes 应增加: before=%d, after=%d", usedBefore, usedAfterPut)
	}

	// ---- 删除对象 ----
	_, err = alice.Call(ctx, "storage.delete_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": objectKey,
	})
	if err != nil {
		t.Fatalf("delete_object 失败: %v", err)
	}

	// ---- 获取删除后的配额，used_bytes 应恢复 ----
	quotaAfterDel, err := alice.Call(ctx, "storage.get_quota", map[string]any{
		"owner_aid": aliceAID,
	})
	if err != nil {
		t.Fatalf("get_quota（删除后）失败: %v", err)
	}
	qadMap, _ := quotaAfterDel.(map[string]any)
	usedAfterDel := int(toInt64(qadMap["used_bytes"]))
	if usedAfterDel != usedBefore {
		t.Fatalf("删除后 used_bytes 应恢复: before=%d, after_del=%d", usedBefore, usedAfterDel)
	}
}

// ---------------------------------------------------------------------------
// TestIntegration_StorageCrossAIDPermission
// 覆盖：私有对象跨 AID 全面拒绝（head/get/quota）、公开对象跨 AID 可读
// ---------------------------------------------------------------------------

func TestIntegration_StorageCrossAIDPermission(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("sto%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("sto%s-b.%s", rid, testIssuer())
	bucket := fmt.Sprintf("test-bucket-%s", rid)

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- Alice 写入私有对象 ----
	privateKey := fmt.Sprintf("private/%s/perm.txt", rid)
	privateContent := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("private-%s", rid)))

	_, err := alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   privateKey,
		"content":      privateContent,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Skipf("storage 服务不可用: %v", err)
	}

	// ---- Bob head_object 私有对象 → 应失败 ----
	_, err = bob.Call(ctx, "storage.head_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": privateKey,
	})
	if err == nil {
		t.Fatalf("Bob head_object 私有对象应失败，但成功了")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "denied") &&
		!strings.Contains(strings.ToLower(err.Error()), "permission") &&
		!strings.Contains(strings.ToLower(err.Error()), "forbidden") &&
		!strings.Contains(strings.ToLower(err.Error()), "not found") &&
		!strings.Contains(strings.ToLower(err.Error()), "private") {
		t.Logf("Bob head_object 返回错误（非标准权限拒绝文本）: %v", err)
	}

	// ---- Bob get_object 私有对象 → 应失败 ----
	_, err = bob.Call(ctx, "storage.get_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": privateKey,
	})
	if err == nil {
		t.Fatalf("Bob get_object 私有对象应失败，但成功了")
	}
	t.Logf("Bob get_object 私有对象被拒绝（符合预期）: %v", err)

	// ---- Bob get_quota Alice → 应失败 ----
	_, err = bob.Call(ctx, "storage.get_quota", map[string]any{
		"owner_aid": aliceAID,
	})
	if err == nil {
		t.Fatalf("Bob get_quota Alice 应失败，但成功了")
	}
	t.Logf("Bob get_quota Alice 被拒绝（符合预期）: %v", err)

	// ---- Alice 写入公开对象 ----
	publicKey := fmt.Sprintf("public/%s/perm.txt", rid)
	publicBody := fmt.Sprintf("public-%s", rid)
	publicContent := base64.StdEncoding.EncodeToString([]byte(publicBody))

	_, err = alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   publicKey,
		"content":      publicContent,
		"content_type": "text/plain",
		"is_private":   false,
	})
	if err != nil {
		t.Fatalf("put_object 公开对象失败: %v", err)
	}

	// ---- Bob 可以读取公开对象 ----
	bobGetResult, err := bob.Call(ctx, "storage.get_object", map[string]any{
		"owner_aid":  aliceAID,
		"bucket":     bucket,
		"object_key": publicKey,
	})
	if err != nil {
		t.Fatalf("Bob 读取公开对象失败: %v", err)
	}
	bobGetMap, _ := bobGetResult.(map[string]any)
	bobGotContent, _ := bobGetMap["content"].(string)
	bobDecoded, err := base64.StdEncoding.DecodeString(bobGotContent)
	if err != nil {
		t.Fatalf("Bob get_object content base64 解码失败: %v", err)
	}
	if string(bobDecoded) != publicBody {
		t.Fatalf("Bob get_object 内容不匹配: 期望 %q, 实际 %q", publicBody, string(bobDecoded))
	}
}

// ---------------------------------------------------------------------------
// TestIntegration_StorageShareLinksAndShortURLs
// 覆盖：分享链接 RPC、/s/{share_id} 短链接下载、授权名单、次数限制和撤销
// ---------------------------------------------------------------------------

func TestIntegration_StorageShareLinksAndShortURLs(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	eve := makeClient(t)
	defer alice.Close()
	defer bob.Close()
	defer eve.Close()

	aliceAID := fmt.Sprintf("stosh%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("stosh%s-b.%s", rid, testIssuer())
	eveAID := fmt.Sprintf("stosh%s-e.%s", rid, testIssuer())
	bucket := fmt.Sprintf("test-share-%s", rid)
	objectKey := fmt.Sprintf("docs/%s/share.txt", rid)
	bodyText := fmt.Sprintf("share-hello-%s", rid)
	content := base64.StdEncoding.EncodeToString([]byte(bodyText))
	shareIDs := make([]string, 0, 3)

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)
	ensureConnected(t, eve, eveAID)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		for _, shareID := range shareIDs {
			_, _ = alice.Call(cleanupCtx, "storage.revoke_share_link", map[string]any{
				"share_id": shareID,
			})
		}
		_, _ = alice.Call(cleanupCtx, "storage.delete_object", map[string]any{
			"owner_aid":  aliceAID,
			"bucket":     bucket,
			"object_key": objectKey,
		})
	}()

	_, err := alice.Call(ctx, "storage.put_object", map[string]any{
		"owner_aid":    aliceAID,
		"bucket":       bucket,
		"object_key":   objectKey,
		"content":      content,
		"content_type": "text/plain",
		"is_private":   true,
	})
	if err != nil {
		t.Skipf("storage 服务不可用: %v", err)
	}

	publicShare, err := alice.Call(ctx, "storage.create_share_link", map[string]any{
		"owner_aid":         aliceAID,
		"bucket":            bucket,
		"object_key":        objectKey,
		"allowed_aids":      []string{"*"},
		"expire_in_seconds": 300,
	})
	if err != nil {
		t.Skipf("storage 分享链接不可用: %v", err)
	}
	publicMap, _ := publicShare.(map[string]any)
	publicShareID, _ := publicMap["share_id"].(string)
	publicShareURL, _ := publicMap["share_url"].(string)
	shareIDs = append(shareIDs, publicShareID)
	if len(publicShareID) != 10 {
		t.Fatalf("share_id 长度异常: %#v", publicMap)
	}
	if !strings.Contains(publicShareURL, "/s/"+publicShareID) {
		t.Fatalf("share_url 未包含短链路径: %#v", publicMap)
	}
	if !strings.HasPrefix(publicShareURL, "http://") && !strings.HasPrefix(publicShareURL, "https://") {
		t.Fatalf("share_url 应为绝对 URL: %#v", publicMap)
	}
	if got := string(storageDownloadBytes(t, publicShareURL)); got != bodyText {
		t.Fatalf("短链接 HTTP 下载内容不匹配: want=%q got=%q", bodyText, got)
	}

	bobPublic, err := bob.Call(ctx, "storage.get_by_share", map[string]any{
		"share_id": publicShareID,
	})
	if err != nil {
		t.Fatalf("Bob 读取公开分享失败: %v", err)
	}
	bobPublicMap, _ := bobPublic.(map[string]any)
	bobPublicContent, _ := bobPublicMap["content"].(string)
	decodedPublic, err := base64.StdEncoding.DecodeString(bobPublicContent)
	if err != nil || string(decodedPublic) != bodyText {
		t.Fatalf("Bob 公开分享内容异常: decoded=%q err=%v map=%#v", string(decodedPublic), err, bobPublicMap)
	}

	restrictedShare, err := alice.Call(ctx, "storage.create_share_link", map[string]any{
		"owner_aid":         aliceAID,
		"bucket":            bucket,
		"object_key":        objectKey,
		"allowed_aids":      []string{bobAID},
		"expire_in_seconds": 300,
	})
	if err != nil {
		t.Fatalf("创建指定 AID 分享失败: %v", err)
	}
	restrictedMap, _ := restrictedShare.(map[string]any)
	restrictedShareID, _ := restrictedMap["share_id"].(string)
	shareIDs = append(shareIDs, restrictedShareID)

	if _, err = bob.Call(ctx, "storage.get_by_share", map[string]any{"share_id": restrictedShareID}); err != nil {
		t.Fatalf("Bob 读取授权分享失败: %v", err)
	}
	if _, err = eve.Call(ctx, "storage.get_by_share", map[string]any{"share_id": restrictedShareID}); err == nil {
		t.Fatalf("Eve 读取未授权分享应失败，但成功了")
	}

	limitedShare, err := alice.Call(ctx, "storage.create_share_link", map[string]any{
		"owner_aid":         aliceAID,
		"bucket":            bucket,
		"object_key":        objectKey,
		"allowed_aids":      []string{"*"},
		"expire_in_seconds": 300,
		"max_uses":          1,
	})
	if err != nil {
		t.Fatalf("创建 max_uses 分享失败: %v", err)
	}
	limitedMap, _ := limitedShare.(map[string]any)
	limitedShareID, _ := limitedMap["share_id"].(string)
	shareIDs = append(shareIDs, limitedShareID)
	if _, err = bob.Call(ctx, "storage.get_by_share", map[string]any{"share_id": limitedShareID}); err != nil {
		t.Fatalf("第一次读取 max_uses 分享失败: %v", err)
	}
	if _, err = bob.Call(ctx, "storage.get_by_share", map[string]any{"share_id": limitedShareID}); err == nil {
		t.Fatalf("max_uses=1 的分享第二次读取应失败，但成功了")
	}

	listed, err := alice.Call(ctx, "storage.list_share_links", map[string]any{
		"bucket":     bucket,
		"object_key": objectKey,
	})
	if err != nil {
		t.Fatalf("list_share_links 失败: %v", err)
	}
	listedMap, _ := listed.(map[string]any)
	links, _ := listedMap["links"].([]any)
	seen := map[string]bool{}
	for _, item := range links {
		if m, ok := item.(map[string]any); ok {
			seen[fmt.Sprintf("%v", m["share_id"])] = true
		}
	}
	if !seen[publicShareID] || !seen[restrictedShareID] {
		t.Fatalf("list_share_links 未返回已创建分享: %#v", listedMap)
	}

	revoked, err := alice.Call(ctx, "storage.revoke_share_link", map[string]any{
		"share_id": restrictedShareID,
	})
	if err != nil {
		t.Fatalf("revoke_share_link 失败: %v", err)
	}
	revokedMap, _ := revoked.(map[string]any)
	if revokedMap["revoked"] != true {
		t.Fatalf("revoke_share_link 返回异常: %#v", revokedMap)
	}
	if _, err = bob.Call(ctx, "storage.get_by_share", map[string]any{"share_id": restrictedShareID}); err == nil {
		t.Fatalf("撤销后的分享应不可读取，但成功了")
	}
}
