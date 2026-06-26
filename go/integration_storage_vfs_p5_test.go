//go:build integration

package aun

import (
	"bytes"
	"context"
	"encoding/base64"
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
	aliceLow := NewStorageLowLevel(alice)
	bobLow := NewStorageLowLevel(bob)

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

	if _, err := alice.Storage().SetACL(ctx, dirPath, SetACLOptions{Owner: aliceAID, Bucket: bucket, GranteeAID: bobAID, Perms: "w"}); err != nil {
		t.Fatalf("SetACL 失败: %v", err)
	}
	if _, err := bob.Storage().ReadBytes(ctx, filePath, &ReadOptions{Owner: aliceAID, Bucket: bucket}); err == nil {
		t.Fatalf("Bob 写 ACL 不应授予直接读取")
	}
	if _, err := bob.Storage().WriteBytes(ctx, fmt.Sprintf("/docs/%s/bob-write.txt", rid), []byte("bob-write"), &WriteBytesOptions{
		Owner:       aliceAID,
		Bucket:      bucket,
		ContentType: "text/plain",
	}); err != nil {
		t.Fatalf("Bob 写 ACL 写入失败: %v", err)
	}
	objectKey := strings.TrimLeft(filePath, "/")
	if _, err := bobLow.CreateShareLink(ctx, aliceAID, bucket, objectKey, []string{bobAID}, nil, nil); err == nil {
		t.Fatalf("Bob 不能代 Alice 创建分享链接")
	}
	expireIn := 300
	share, err := aliceLow.CreateShareLink(ctx, aliceAID, bucket, objectKey, []string{bobAID}, &expireIn, nil)
	if err != nil {
		t.Fatalf("CreateShareLink 失败: %v", err)
	}
	shareID := storageString(share["share_id"], storageString(share["shareId"], ""))
	shared, err := bobLow.GetByShare(ctx, shareID)
	if err != nil {
		t.Fatalf("Bob 分享读取失败: %v", err)
	}
	sharedContent, err := base64.StdEncoding.DecodeString(storageString(shared["content"], ""))
	if err != nil {
		t.Fatalf("分享内容 base64 解码失败: %v", err)
	}
	if !bytes.Equal(sharedContent, body) {
		t.Fatalf("Bob 分享读取内容不匹配: got=%q want=%q", string(sharedContent), string(body))
	}
	if _, err := aliceLow.RevokeShareLink(ctx, shareID); err != nil {
		t.Fatalf("RevokeShareLink 失败: %v", err)
	}
	if _, err := bobLow.GetByShare(ctx, shareID); err == nil {
		t.Fatalf("撤销分享后 Bob 读取应失败")
	}

	if _, err := alice.Storage().RemoveACL(ctx, dirPath, RemoveACLOptions{Owner: aliceAID, Bucket: bucket, GranteeAID: bobAID}); err != nil {
		t.Fatalf("RemoveACL 失败: %v", err)
	}
	if _, err := bob.Storage().WriteBytes(ctx, fmt.Sprintf("/docs/%s/bob-write-after-revoke.txt", rid), []byte("no"), &WriteBytesOptions{
		Owner:       aliceAID,
		Bucket:      bucket,
		ContentType: "text/plain",
	}); err == nil {
		t.Fatalf("Bob ACL 删除后写入应失败")
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

	tokens, err := alice.Storage().ListTokens(ctx, filePath, &UsageOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("ListTokens 失败: %v", err)
	}
	rawTokens, _ := firstNonNil(tokens["tokens"], tokens["items"]).([]any)
	if len(rawTokens) == 0 {
		t.Fatalf("ListTokens 未返回已签发 token: %#v", tokens)
	}

	df, err := alice.Storage().DF(ctx, &UsageOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("DF 失败: %v", err)
	}
	if df.Owner == "" || df.UsedBytes <= 0 {
		t.Fatalf("DF 返回异常: %#v", df)
	}

	copiedPath := fmt.Sprintf("/docs/%s/copied.txt", rid)
	copied, err := alice.Storage().Copy(ctx, filePath, copiedPath, &CopyOptions{Owner: aliceAID, Bucket: bucket, Overwrite: true})
	if err != nil {
		t.Fatalf("Copy 失败: %v", err)
	}
	if copied.Type != "file" || copied.Path != copiedPath {
		t.Fatalf("Copy NodeView 异常: %#v", copied)
	}
	copiedRead, err := alice.Storage().ReadBytes(ctx, copiedPath, &ReadOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil || !bytes.Equal(copiedRead, body) {
		t.Fatalf("Copy 后读取异常: got=%q err=%v", string(copiedRead), err)
	}

	renamedPath := fmt.Sprintf("/docs/%s/renamed.txt", rid)
	renamed, err := alice.Storage().Rename(ctx, copiedPath, renamedPath, &RenameOptions{Owner: aliceAID, Bucket: bucket, Overwrite: true})
	if err != nil {
		t.Fatalf("Rename 失败: %v", err)
	}
	if renamed.Path != renamedPath {
		t.Fatalf("Rename NodeView 异常: %#v", renamed)
	}
	if _, err := alice.Storage().Stat(ctx, copiedPath, &StatOptions{Owner: aliceAID, Bucket: bucket}); err == nil {
		t.Fatalf("Rename 后旧路径不应仍可 stat")
	}

	linkPath := fmt.Sprintf("/docs/%s/current.txt", rid)
	link, err := alice.Storage().Symlink(ctx, renamedPath, linkPath, &SymlinkOptions{Owner: aliceAID, Bucket: bucket, Overwrite: true})
	if err != nil {
		t.Fatalf("Symlink 失败: %v", err)
	}
	if link.Type != "symlink" || link.Target != renamedPath {
		t.Fatalf("Symlink NodeView 异常: %#v", link)
	}
	lstat, err := alice.Storage().Lstat(ctx, linkPath, &StatOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("Lstat 软链失败: %v", err)
	}
	if lstat.Type != "symlink" {
		t.Fatalf("Lstat 应返回 symlink: %#v", lstat)
	}
	statLink, err := alice.Storage().Stat(ctx, linkPath, &StatOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("Stat 软链失败: %v", err)
	}
	if statLink.Type != "file" {
		t.Fatalf("Stat 应跟随软链返回 file: %#v", statLink)
	}
	readlink, err := alice.Storage().Readlink(ctx, linkPath, &ReadlinkOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("Readlink 失败: %v", err)
	}
	if readlink.Target != renamedPath {
		t.Fatalf("Readlink target 异常: %#v", readlink)
	}

	repointed, err := alice.Storage().Repoint(ctx, linkPath, filePath, &RepointOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("Repoint 失败: %v", err)
	}
	if repointed.Target != filePath {
		t.Fatalf("Repoint target 异常: %#v", repointed)
	}
	renamedLinkPath := fmt.Sprintf("/docs/%s/latest.txt", rid)
	renamedLink, err := alice.Storage().RenameSymlink(ctx, linkPath, renamedLinkPath, &RenameSymlinkOptions{Owner: aliceAID, Bucket: bucket, Overwrite: true})
	if err != nil {
		t.Fatalf("RenameSymlink 失败: %v", err)
	}
	if renamedLink.Path != renamedLinkPath || renamedLink.Target != filePath {
		t.Fatalf("RenameSymlink 返回异常: %#v", renamedLink)
	}

	foundNodes, err := alice.Storage().Find(ctx, dirPath, &FindOptions{Owner: aliceAID, Bucket: bucket, Name: "latest.txt", NodeType: "symlink"})
	if err != nil {
		t.Fatalf("Find 失败: %v", err)
	}
	if !hasStorageP5NodeName(foundNodes, "latest.txt") {
		t.Fatalf("Find 未返回 latest.txt: %#v", foundNodes)
	}

	removed, err := alice.Storage().Remove(ctx, renamedLinkPath, &RemoveOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("Remove 软链失败: %v", err)
	}
	if removed.RemovedCount < 1 {
		t.Fatalf("Remove 软链返回异常: %#v", removed)
	}
	removedFile, err := alice.Storage().Remove(ctx, renamedPath, &RemoveOptions{Owner: aliceAID, Bucket: bucket})
	if err != nil {
		t.Fatalf("Remove 文件失败: %v", err)
	}
	if removedFile.RemovedCount < 1 {
		t.Fatalf("Remove 文件返回异常: %#v", removedFile)
	}
}

func hasStorageP5NodeName(nodes []NodeView, name string) bool {
	for _, node := range nodes {
		if node.Name == name {
			return true
		}
	}
	return false
}
