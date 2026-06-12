//go:build integration

package aun

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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
