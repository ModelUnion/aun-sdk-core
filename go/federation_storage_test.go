//go:build integration

package aun

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func federationStorageRPC(t *testing.T, client *AUNClient, method string, params map[string]any) map[string]any {
	t.Helper()
	resultMap, err := federationStorageCall(client, method, params)
	if err != nil {
		t.Fatalf("%s 失败: %v", method, err)
	}
	return resultMap
}

func federationStorageCall(client *AUNClient, method string, params map[string]any) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result, err := client.Call(ctx, method, params)
	if err != nil {
		return nil, err
	}
	resultMap, _ := result.(map[string]any)
	if resultMap == nil {
		return nil, fmt.Errorf("%s 返回 nil", method)
	}
	if errAny, ok := resultMap["error"]; ok {
		if errMap, ok := errAny.(map[string]any); ok {
			message, _ := errMap["message"].(string)
			if message == "" {
				message = fmt.Sprintf("%v", errMap)
			}
			return resultMap, errors.New(message)
		}
		return resultMap, fmt.Errorf("%v", errAny)
	}
	return resultMap, nil
}

func federationDownloadBytes(t *testing.T, rawURL string) []byte {
	t.Helper()
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("下载群资源失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("下载群资源返回 HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取群资源响应失败: %v", err)
	}
	return body
}

func assertNonLoopbackURL(t *testing.T, rawURL, label string) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("%s URL 非法: %v", label, err)
	}
	host := strings.TrimSpace(strings.ToLower(parsed.Hostname()))
	if host == "" {
		t.Fatalf("%s host 为空: %s", label, rawURL)
	}
	switch host {
	case "127.0.0.1", "localhost", "0.0.0.0", "::1", "::":
		t.Fatalf("%s 不应返回 loopback URL: %s", label, rawURL)
	}
}

func TestFederationStoragePublicInlineRead(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-sto-pub-a-%s.aid.com", rid))
	_ = ensureFederationConnected(t, bob, fmt.Sprintf("go-sto-pub-b-%s.aid.net", rid))

	objectKey := fmt.Sprintf("shared/public-%s.txt", rid)
	content := []byte(fmt.Sprintf("GO_PUBLIC_CROSS_DOMAIN_%s", rid))
	putResult := federationStorageRPC(t, alice, "storage.put_object", map[string]any{
		"object_key":   objectKey,
		"content":      base64.StdEncoding.EncodeToString(content),
		"content_type": "text/plain",
		"is_private":   false,
	})
	if got, _ := putResult["object_key"].(string); got != objectKey {
		t.Fatalf("storage.put_object 返回 object_key 异常: got=%s want=%s", got, objectKey)
	}

	head := federationStorageRPC(t, bob, "storage.head_object", map[string]any{
		"owner_aid":  aliceAID,
		"object_key": objectKey,
	})
	if size := int(toInt64(head["size_bytes"])); size != len(content) {
		t.Fatalf("head_object size 异常: got=%d want=%d", size, len(content))
	}
	if isPrivate, _ := head["is_private"].(bool); isPrivate {
		t.Fatalf("公开对象 is_private 不应为 true: %+v", head)
	}

	objectResult := federationStorageRPC(t, bob, "storage.get_object", map[string]any{
		"owner_aid":  aliceAID,
		"object_key": objectKey,
	})
	contentB64, _ := objectResult["content"].(string)
	actual, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		t.Fatalf("解析 storage.get_object 内容失败: %v", err)
	}
	if string(actual) != string(content) {
		t.Fatalf("storage.get_object 内容不匹配: got=%q want=%q", string(actual), string(content))
	}
}

func TestFederationStoragePrivateDenied(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-sto-pri-a-%s.aid.com", rid))
	_ = ensureFederationConnected(t, bob, fmt.Sprintf("go-sto-pri-b-%s.aid.net", rid))

	objectKey := fmt.Sprintf("private/hidden-%s.txt", rid)
	content := []byte(fmt.Sprintf("GO_PRIVATE_ONLY_%s", rid))
	_ = federationStorageRPC(t, alice, "storage.put_object", map[string]any{
		"object_key":   objectKey,
		"content":      base64.StdEncoding.EncodeToString(content),
		"content_type": "text/plain",
		"is_private":   true,
	})

	if _, err := federationStorageCall(bob, "storage.head_object", map[string]any{
		"owner_aid":  aliceAID,
		"object_key": objectKey,
	}); err == nil {
		t.Fatal("Bob 跨域读取私有对象 metadata 应被拒绝")
	}

	if _, err := federationStorageCall(bob, "storage.get_object", map[string]any{
		"owner_aid":  aliceAID,
		"object_key": objectKey,
	}); err == nil {
		t.Fatal("Bob 跨域读取私有对象内容应被拒绝")
	}
}

func TestFederationGroupResourceProxyAccess(t *testing.T) {
	rid := federationRunID()
	alice := makeFederationClient(t)
	bob := makeFederationClient(t)
	eve := makeFederationClient(t)
	defer alice.Close()
	defer bob.Close()
	defer eve.Close()

	aliceAID := ensureFederationConnected(t, alice, fmt.Sprintf("go-sto-grp-a-%s.aid.com", rid))
	bobAID := ensureFederationConnected(t, bob, fmt.Sprintf("go-sto-grp-b-%s.aid.net", rid))
	_ = ensureFederationConnected(t, eve, fmt.Sprintf("go-sto-grp-e-%s.aid.net", rid))

	objectKey := fmt.Sprintf("group/private-share-%s.txt", rid)
	content := []byte(fmt.Sprintf("GO_GROUP_RESOURCE_%s", rid))
	_ = federationStorageRPC(t, alice, "storage.put_object", map[string]any{
		"object_key":   objectKey,
		"content":      base64.StdEncoding.EncodeToString(content),
		"content_type": "text/plain",
		"is_private":   true,
	})

	groupID := createGroup(t, alice, fmt.Sprintf("go-fed-storage-%s", rid))
	addMember(t, alice, groupID, bobAID)

	resourcePath := fmt.Sprintf("files/private-share-%s.txt", rid)
	direct := federationStorageRPC(t, alice, "group.resources.direct_add", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
		"resource_type": "file",
		"title":         fmt.Sprintf("private-share-%s.txt", rid),
		"storage_ref": map[string]any{
			"owner_aid":  aliceAID,
			"bucket":     "default",
			"object_key": objectKey,
			"filename":   fmt.Sprintf("private-share-%s.txt", rid),
		},
	})
	resource, _ := direct["resource"].(map[string]any)
	if got, _ := resource["resource_path"].(string); got != resourcePath {
		t.Fatalf("group.resources.direct_add 返回异常: %+v", direct)
	}

	listed := federationWaitForMessages(t, bob, func() []map[string]any {
		result := federationStorageRPC(t, bob, "group.resources.list", map[string]any{"group_id": groupID})
		itemsAny, _ := result["items"].([]any)
		items := make([]map[string]any, 0, len(itemsAny))
		for _, raw := range itemsAny {
			if item, ok := raw.(map[string]any); ok {
				items = append(items, item)
			}
		}
		return items
	}, 20*time.Second, func(items []map[string]any) bool {
		for _, item := range items {
			if path, _ := item["resource_path"].(string); path == resourcePath {
				return true
			}
		}
		return false
	}, "等待 Bob 列出群资源")
	if len(listed) == 0 {
		t.Fatal("Bob 未看到群资源")
	}

	access := federationStorageRPC(t, bob, "group.resources.get_access", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
	})
	download, _ := access["download"].(map[string]any)
	downloadURL, _ := download["download_url"].(string)
	if downloadURL == "" {
		t.Fatalf("group.resources.get_access 未返回 download_url: %+v", access)
	}
	assertNonLoopbackURL(t, downloadURL, "group.resources.get_access.download_url")

	body := federationDownloadBytes(t, downloadURL)
	if string(body) != string(content) {
		t.Fatalf("群资源下载内容不匹配: got=%q want=%q", string(body), string(content))
	}

	if _, err := federationStorageCall(eve, "group.resources.get_access", map[string]any{
		"group_id":      groupID,
		"resource_path": resourcePath,
	}); err == nil {
		t.Fatal("非成员 Eve 获取群资源访问应被拒绝")
	}
}
