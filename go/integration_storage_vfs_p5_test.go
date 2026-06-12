//go:build integration

package aun

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIntegration_StorageVFSP5(t *testing.T) {
	rid := runID()
	alice := makeClient(t)
	bob := makeClient(t)
	defer alice.Close()
	defer bob.Close()

	aliceAID := fmt.Sprintf("p5goa%s.%s", rid, testIssuer())
	bobAID := fmt.Sprintf("p5gob%s.%s", rid, testIssuer())
	bucket := fmt.Sprintf("p5-go-%s", rid)
	filePath := fmt.Sprintf("/docs/%s/a.txt", rid)
	dirPath := fmt.Sprintf("/docs/%s", rid)
	body := []byte(fmt.Sprintf("hello-p5-go-%s", rid))

	ensureConnected(t, alice, aliceAID)
	ensureConnected(t, bob, bobAID)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	written, err := alice.Storage().WriteBytes(ctx, filePath, body, &WriteBytesOptions{
		Owner:       aliceAID,
		Bucket:      bucket,
		ContentType: "text/plain",
	})
	if err != nil {
		t.Fatalf("WriteBytes 失败: %v", err)
	}
	if written.Type != "file" || written.Path != filePath {
		t.Fatalf("写入 NodeView 异常: %#v", written)
	}

	stat, err := alice.Storage().Stat(ctx, filePath, &StatOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}
	if stat.Type != "file" || stat.Mode == "" {
		t.Fatalf("Stat NodeView 异常: %#v", stat)
	}

	listed, err := alice.Storage().List(ctx, dirPath, &ListOptions{Owner: aliceAID, Bucket: bucket, Long: true})
	if err != nil {
		t.Fatalf("List 失败: %v", err)
	}
	found := false
	for _, node := range listed {
		if node.Name == "a.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("List 未返回 a.txt: %#v", listed)
	}

	if _, err := bob.Storage().ReadBytes(ctx, filePath, &ReadOptions{Owner: aliceAID, Bucket: bucket}); err == nil {
		t.Fatalf("Bob 未授权读取私有对象应失败")
	}

	if _, err := alice.Storage().SetACL(ctx, dirPath, SetACLOptions{Owner: aliceAID, Bucket: bucket, GranteeAID: bobAID, Perms: "r"}); err != nil {
		t.Fatalf("SetACL 失败: %v", err)
	}
	bobRead, err := bob.Storage().ReadBytes(ctx, filePath, &ReadOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("Bob ACL 读取失败: %v", err)
	}
	if !bytes.Equal(bobRead, body) {
		t.Fatalf("Bob ACL 读取内容不匹配: got=%q want=%q", string(bobRead), string(body))
	}

	if _, err := alice.Storage().RemoveACL(ctx, dirPath, RemoveACLOptions{Owner: aliceAID, Bucket: bucket, GranteeAID: bobAID}); err != nil {
		t.Fatalf("RemoveACL 失败: %v", err)
	}
	if _, err := bob.Storage().ReadBytes(ctx, filePath, &ReadOptions{Owner: aliceAID, Bucket: bucket}); err == nil {
		t.Fatalf("Bob ACL 删除后读取应失败")
	}

	maxReads := 1
	issued, err := alice.Storage().IssueToken(ctx, filePath, IssueTokenOptions{Owner: aliceAID, Bucket: bucket, MaxReads: &maxReads})
	if err != nil {
		t.Fatalf("IssueToken 失败: %v", err)
	}
	token := storageString(issued["token"], "")
	if strings.TrimSpace(token) == "" {
		t.Fatalf("IssueToken 未返回明文 token: %#v", issued)
	}
	tokenRead, err := bob.Storage().ReadBytes(ctx, filePath, &ReadOptions{Owner: aliceAID, Bucket: bucket, Token: token})
	if err != nil {
		t.Fatalf("token 读取失败: %v", err)
	}
	if !bytes.Equal(tokenRead, body) {
		t.Fatalf("token 读取内容不匹配: got=%q want=%q", string(tokenRead), string(body))
	}
	if _, err := bob.Storage().ReadBytes(ctx, filePath, &ReadOptions{Owner: aliceAID, Bucket: bucket, Token: token}); err == nil {
		t.Fatalf("max_reads=1 token 第二次读取应失败")
	}
}
