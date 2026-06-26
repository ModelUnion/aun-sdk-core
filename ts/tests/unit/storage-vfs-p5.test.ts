import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { StorageLowLevel, StorageVFS } from '../../src/storage/vfs.js';
import { AUNClient } from '../../src/client.js';

class FakeClient {
  aid = 'alice.agentid.pub';
  calls: Array<{ method: string; params: Record<string, unknown> }> = [];

  async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.calls.push({ method, params: params ?? {} });
    if (method === 'storage.check_upload') return { inline: true, within_limit: true, target_exists: false, skip_upload: false };
    if (method === 'storage.put_object') return { type: 'file', path: params?.object_key, object_key: params?.object_key, owner_aid: params?.owner_aid, size_bytes: 5, sha256: 'sha' };
    if (method === 'storage.get_object') {
      return {
        content: 'aGVsbG8=',
        sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
      };
    }
    if (method === 'storage.create_download_ticket') {
      return {
        download_url: 'https://download.local/docs/a.txt',
        sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
      };
    }
    if (method === 'storage.fs.list') return { nodes: [{ type: 'file', path: 'docs/a.txt', name: 'a.txt', owner_aid: params?.owner_aid, mode: '0644' }] };
    if (method === 'storage.fs.stat') return { type: 'file', path: params?.path, owner_aid: params?.owner_aid, mode: '0644' };
    if (method === 'storage.fs.touch') return { type: 'file', path: params?.path, owner_aid: params?.owner_aid, size: 0, mode: '0644' };
    if (method === 'storage.fs.find') return { items: [
      { type: 'file', path: 'docs/a.txt', name: 'a.txt', owner_aid: params?.owner_aid, size: 5 },
      { type: 'dir', path: 'docs/sub', name: 'sub', owner_aid: params?.owner_aid },
      { type: 'file', path: 'docs/sub/b.txt', name: 'b.txt', owner_aid: params?.owner_aid, size: 7 },
      { type: 'symlink', path: 'docs/current.txt', name: 'current.txt', owner_aid: params?.owner_aid },
    ] };
    if (method === 'storage.fs.df') return { owner_aid: params?.owner_aid, bucket: params?.bucket, used_bytes: 5, quota_bytes: 10, object_count: 1 };
    if (method === 'storage.fs.copy') return { type: 'file', path: params?.dst, owner_aid: params?.dst_owner_aid ?? params?.owner_aid, size_bytes: 5 };
    if (method === 'storage.create_symlink') return { type: 'symlink', path: params?.path, target: params?.target, owner_aid: params?.owner_aid };
    if (method === 'storage.rename_symlink') return { ok: true, type: 'symlink', path: params?.new_path, target: '/target.txt', owner_aid: params?.owner_aid };
    if (method === 'storage.set_acl') return { acl_id: 'acl-1', grantee_aid: params?.grantee_aid, perms: params?.perms };
    if (method === 'storage.set_visibility') return { type: 'file', path: params?.path, allow_roles: params?.allow_roles };
    if (method === 'storage.check_access') return { allowed: true, operation: params?.operation, path: params?.path };
    if (method === 'storage.issue_token') return { token: 'tok-secret', token_id: 'tok-1' };
    if (method === 'storage.list_tokens') return { tokens: [{ token_id: 'tok-1' }] };
    if (method === 'storage.get_quota') return { owner_aid: params?.owner_aid, quota_bytes: 10, used_bytes: 4, object_count: 1 };
    return { ok: true };
  }
}

describe('P5 StorageVFS TypeScript 契约', () => {
  it('writeBytes 使用 check_upload 的 inline 判断上传路径', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    const node = await storage.writeBytes('/docs/a.txt', new TextEncoder().encode('hello'));

    expect(node.type).toBe('file');
    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.check_upload',
      'storage.put_object',
    ]);
    expect(client.calls[1].params).toMatchObject({
      owner_aid: 'alice.agentid.pub',
      bucket: 'default',
      object_key: 'docs/a.txt',
      is_private: true,
      overwrite: false,
    });
  });

  it('writeBytes 默认拒绝覆盖远程已有目标，overwrite=true 才上传', async () => {
    class ExistingTargetClient extends FakeClient {
      async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
        if (method === 'storage.check_upload') {
          this.calls.push({ method, params: params ?? {} });
          return {
            inline: true,
            within_limit: true,
            target_exists: true,
            target: { path: 'docs/a.txt', version: 3, size_bytes: 5, sha256: 'old' },
          };
        }
        return super.call(method, params);
      }
    }
    const client = new ExistingTargetClient();
    const storage = new StorageVFS(client);

    await expect(storage.writeBytes('/docs/a.txt', 'hello')).rejects.toMatchObject({ code: 'EEXIST' });
    expect(client.calls.map((c) => c.method)).toEqual(['storage.check_upload']);

    await expect(storage.writeBytes('/docs/a.txt', 'hello', { overwrite: true })).resolves.toMatchObject({ path: '/docs/a.txt' });
    expect(client.calls.map((c) => c.method)).toEqual(['storage.check_upload', 'storage.check_upload', 'storage.put_object']);
    expect(client.calls[2].params.overwrite).toBe(true);
  });

  it('read/list/stat 支持 token 透传并默认走 storage.fs.*', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    await expect(storage.readBytes('/docs/a.txt', { token: 'tok' })).resolves.toEqual(new TextEncoder().encode('hello'));
    await storage.list('/docs', { token: 'tok', long: true });
    await storage.stat('/docs/a.txt', { token: 'tok' });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.get_object',
      'storage.fs.list',
      'storage.fs.stat',
    ]);
    expect(client.calls.every((c) => c.params.token === 'tok')).toBe(true);
  });

  it('readBytes 支持 offset/limit 范围读取参数', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    await expect(storage.readBytes('/docs/a.txt', { token: 'tok', offset: 1, limit: 3 })).resolves.toEqual(new TextEncoder().encode('hello'));

    expect(client.calls).toHaveLength(1);
    expect(client.calls[0]).toMatchObject({
      method: 'storage.get_object',
      params: {
        object_key: 'docs/a.txt',
        token: 'tok',
        offset: 1,
        limit: 3,
      },
    });
  });

  it('readBytes 返回实际内容并保留内存读取入口', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    const downloaded = await storage.readBytes('/docs/a.txt', { token: 'tok' });

    expect(downloaded).toEqual(new TextEncoder().encode('hello'));
    expect(client.calls).toEqual([{
      method: 'storage.get_object',
      params: {
        owner_aid: 'alice.agentid.pub',
        bucket: 'default',
        object_key: 'docs/a.txt',
        token: 'tok',
      },
    }]);
  });

  it('uploadFile/downloadFile 支持 Node 本地文件路径', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);
    storage.lowlevel.httpGet = vi.fn().mockResolvedValue(new TextEncoder().encode('hello'));
    const dir = await mkdtemp(join(tmpdir(), 'aun-storage-'));
    try {
      const localUpload = join(dir, 'upload.txt');
      const localDownload = join(dir, 'download.txt');
      await writeFile(localUpload, 'hello');

      const uploaded = await storage.uploadFile(localUpload, '/docs/upload.txt', { contentType: 'text/plain' });
      const downloaded = await storage.downloadFile('/docs/a.txt', localDownload, { token: 'tok' });

      await expect(readFile(localDownload, 'utf8')).resolves.toBe('hello');
      expect(uploaded.path).toBe('/docs/upload.txt');
      expect(downloaded).toMatchObject({
        path: '/docs/a.txt',
        localPath: localDownload,
        size: 5,
        verified: true,
      });
      expect(client.calls.map((c) => c.method)).toEqual([
        'storage.check_upload',
        'storage.put_object',
        'storage.create_download_ticket',
      ]);
      expect(client.calls[1].params).toMatchObject({ object_key: 'docs/upload.txt', content_type: 'text/plain', overwrite: false });
      expect(client.calls[2].params).toMatchObject({ object_key: 'docs/a.txt', token: 'tok' });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('downloadFile 本地路径默认拒绝覆盖，overwrite=true 才覆盖', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);
    storage.lowlevel.httpGet = vi.fn().mockResolvedValue(new TextEncoder().encode('hello'));
    const dir = await mkdtemp(join(tmpdir(), 'aun-storage-'));
    try {
      const localDownload = join(dir, 'download.txt');
      await writeFile(localDownload, 'old');

      await expect(storage.downloadFile('/docs/a.txt', localDownload, { token: 'tok' })).rejects.toMatchObject({ code: 'EEXIST' });
      await expect(readFile(localDownload, 'utf8')).resolves.toBe('old');
      expect(storage.lowlevel.httpGet).not.toHaveBeenCalled();

      await storage.downloadFile('/docs/a.txt', localDownload, { token: 'tok', overwrite: true });

      await expect(readFile(localDownload, 'utf8')).resolves.toBe('hello');
      expect(storage.lowlevel.httpGet).toHaveBeenCalledTimes(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('readBytes 用错误码判断 inline 过大并降级到下载 ticket', async () => {
    class TicketClient extends FakeClient {
      async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
        this.calls.push({ method, params: params ?? {} });
        if (method === 'storage.get_object') {
          const error = new Error('object is too large for inline response') as Error & { code?: number };
          error.code = -32602;
          throw error;
        }
        if (method === 'storage.create_download_ticket') {
          return {
            download_url: 'https://download.local/docs/a.txt',
            sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
          };
        }
        return super.call(method, params);
      }
    }
    const client = new TicketClient();
    const storage = new StorageVFS(client);
    storage.lowlevel.httpGet = vi.fn().mockResolvedValue(new TextEncoder().encode('hello'));

    await expect(storage.readBytes('/docs/a.txt')).resolves.toEqual(new TextEncoder().encode('hello'));

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.get_object',
      'storage.create_download_ticket',
    ]);
    expect(storage.lowlevel.httpGet).toHaveBeenCalledWith('https://download.local/docs/a.txt');
  });

  it('crypto.subtle 不可用时 SHA256 计算显式失败', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);
    vi.stubGlobal('crypto', {});
    try {
      await expect(storage.writeBytes('/docs/a.txt', 'hello')).rejects.toMatchObject({
        code: 'EUNSUPPORTED',
      });
      expect(client.calls).toEqual([]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('封装 symlink、ACL、token 和 quota 方法', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    await storage.symlink('/target.txt', '/link.txt');
    await storage.renameSymlink('/link.txt', '/latest.txt', { overwrite: true, expectedVersion: 1 });
    await storage.setAcl('/docs', { granteeAid: 'bob.agentid.pub', perms: 'r', maxUses: 2 });
    await storage.setVisibility('/docs/a.txt', { visibility: 'private', allowRoles: ['admin'] });
    const access = await storage.checkAccess('/docs/a.txt', { operation: 'read' });
    await storage.issueToken('/docs/a.txt', { maxReads: 1 });
    await storage.listTokens('/docs/a.txt');
    const usage = await storage.getUsage();

    expect(access.allowed).toBe(true);
    expect(usage.availBytes).toBe(6);
    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.create_symlink',
      'storage.rename_symlink',
      'storage.set_acl',
      'storage.set_visibility',
      'storage.check_access',
      'storage.issue_token',
      'storage.list_tokens',
      'storage.get_quota',
    ]);
    expect(client.calls[1].params).toMatchObject({ path: 'link.txt', new_path: 'latest.txt', overwrite: true, expected_version: 1 });
    expect(client.calls[2].params).toMatchObject({ grantee_aid: 'bob.agentid.pub', perms: 'r', max_uses: 2 });
    expect(client.calls[3].params).toMatchObject({ path: 'docs/a.txt', visibility: 'private', allow_roles: ['admin'] });
    expect(client.calls[4].params).toMatchObject({ path: 'docs/a.txt', operation: 'read', follow_symlinks: true });
    expect(client.calls[5].params).toMatchObject({ max_reads: 1 });
  });

  it('封装 touch、服务端 find、df 和客户端 du 方法', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    const touched = await storage.touch('/docs/empty.txt', { parents: true, noCreate: true, mtime: 1700000000, followSymlinks: true });
    const nodes = await storage.find('/docs', { name: '*.txt', nodeType: 'f', size: '+3', mtime: '-7', pageSize: 50, token: 'tok' });
    const usage = await storage.df();
    const du = await storage.du('/docs', { maxDepth: 1, pageSize: 25, token: 'tok' });

    expect(touched).toMatchObject({ path: '/docs/empty.txt', size: 0 });
    expect(nodes.map((node) => node.path)).toEqual(['/docs/a.txt', '/docs/sub', '/docs/sub/b.txt', '/docs/current.txt']);
    expect(usage.availBytes).toBe(5);
    expect(du).toEqual({
      path: '/docs',
      sizeBytes: 5,
      fileCount: 1,
      dirCount: 1,
      symlinkCount: 1,
      maxDepth: 1,
      truncated: true,
    });
    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.fs.touch',
      'storage.fs.find',
      'storage.fs.df',
      'storage.fs.find',
    ]);
    expect(client.calls[0].params).toMatchObject({
      path: 'docs/empty.txt',
      parents: true,
      no_create: true,
      mtime: 1700000000,
      follow_symlinks: true,
    });
    expect(client.calls[1].params).toMatchObject({
      path: 'docs',
      name: '*.txt',
      type: 'f',
      size: '+3',
      mtime: '-7',
      page_size: 50,
      token: 'tok',
    });
    expect(client.calls[3].params).toMatchObject({
      path: 'docs',
      page: 1,
      page_size: 25,
      token: 'tok',
    });
  });

  it('copy 支持目标 owner 参数', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    const copied = await storage.copy('/docs/a.txt', '/inbox/a.txt', { owner: 'alice.agentid.pub', dstOwner: 'bob.agentid.pub', recursive: true });

    expect(copied.owner).toBe('bob.agentid.pub');
    expect(client.calls).toHaveLength(1);
    expect(client.calls[0]).toMatchObject({
      method: 'storage.fs.copy',
      params: {
        owner_aid: 'alice.agentid.pub',
        dst_owner_aid: 'bob.agentid.pub',
        src: 'docs/a.txt',
        dst: 'inbox/a.txt',
        recursive: true,
      },
    });
  });

  it('AUNClient 暴露惰性 storage 入口', () => {
    const client = new AUNClient();
    expect(client.storage).toBeInstanceOf(StorageVFS);
    expect(client.storage).toBe(client.storage);
  });
});

describe('P5 StorageLowLevel TypeScript 契约', () => {
  it('removeAcl/revokeToken/listAcl 调用真实 P4 RPC 名称', async () => {
    const client = new FakeClient();
    const low = new StorageLowLevel(client);

    await low.removeAcl({ owner: 'alice.agentid.pub', path: 'docs', granteeAid: 'bob.agentid.pub' });
    await low.listAcl({ owner: 'alice.agentid.pub', path: 'docs' });
    await low.revokeToken({ owner: 'alice.agentid.pub', path: 'docs/a.txt', token: 'tok' });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.remove_acl',
      'storage.list_acl',
      'storage.revoke_token',
    ]);
  });
});
