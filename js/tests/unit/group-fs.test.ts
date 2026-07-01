import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AUNClient, GroupFacade, GroupFSVFS, isGroupRemotePath } from '../../src/index.js';
import type { RpcParams } from '../../src/types.js';

class FakeClient {
  calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  createGroupCalls: Record<string, unknown>[] = [];
  startTransferCalls: Array<{ params: Record<string, unknown>; options: Record<string, unknown> }> = [];
  completeTransferCalls: Array<{ params: Record<string, unknown>; options: Record<string, unknown> }> = [];
  responses: Record<string, unknown> = {};
  _identity?: Record<string, unknown>;
  _sessionParams?: Record<string, unknown>;

  async call(method: string, params?: RpcParams): Promise<unknown> {
    const merged = params ?? {};
    this.calls.push({ method, params: merged });
    const response = this.responses[method];
    if (typeof response === 'function') return (response as (params: RpcParams) => unknown)(merged);
    if (response !== undefined) return response;
    return { method, params: merged };
  }

  async createGroup(params?: RpcParams): Promise<unknown> {
    const merged = params ?? {};
    this.createGroupCalls.push(merged);
    return { group: { group_id: 'group.agentid.pub/10001', group_aid: 'named.agentid.pub' }, params: merged };
  }

  async startGroupTransfer(params?: RpcParams, options?: Record<string, unknown>): Promise<unknown> {
    this.startTransferCalls.push({ params: params ?? {}, options: options ?? {} });
    return { status: 'pending_rekey', group_id: params?.group_id, new_owner: params?.new_owner };
  }

  async completeGroupTransfer(params?: RpcParams, options?: Record<string, unknown>): Promise<unknown> {
    this.completeTransferCalls.push({ params: params ?? {}, options: options ?? {} });
    return { status: 'transferred', group_id: params?.group_id };
  }
}

function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

async function digestHex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

const POSIX_METHODS = ['ls', 'find', 'stat', 'lstat', 'mkdir', 'setAcl', 'removeAcl', 'getAcl', 'listAcl', 'rm', 'cp', 'mv', 'df', 'mount', 'umount'] as const;
const FORBIDDEN_MAIN_METHODS = ['read', 'write', 'put', 'get'] as const;

describe('GroupFSVFS 浏览器 facade 契约', () => {
  it('client.group.fs 存在，暴露 POSIX 方法且不暴露主入口 read/write/put/get', () => {
    const client = new AUNClient();

    expect(client.group).toBeInstanceOf(GroupFacade);
    expect(client.group.fs).toBeInstanceOf(GroupFSVFS);
    expect(client.group.fs).toBe(client.group.fs);
    for (const method of POSIX_METHODS) expect(method in client.group.fs).toBe(true);
    for (const method of FORBIDDEN_MAIN_METHODS) expect(method in client.group.fs).toBe(false);
  });

  it('group.send/pull 缺少 group_id 时不发起 RPC', async () => {
    const client = new FakeClient();
    const group = new GroupFacade(client);

    expect(() => group.send({ payload: { text: 'hi' } })).toThrow(/group_id cannot be empty/);
    expect(() => group.pull({ group_id: '   ', limit: 10 })).toThrow(/group_id cannot be empty/);
    expect(client.calls).toEqual([]);
  });

  it('命名群 create 走 createGroup 以保存 group_aid 私钥', async () => {
    const client = new FakeClient();
    const group = new GroupFacade(client);

    await group.create({ name: 'Named Team', group_name: 'named-team', visibility: 'private' });

    expect(client.createGroupCalls).toEqual([{ name: 'Named Team', group_name: 'named-team', visibility: 'private' }]);
    expect(client.calls).toEqual([]);
  });

  it('transferOwner 带 aidStore 时走 startGroupTransfer 且不透传 aidStore', async () => {
    const client = new FakeClient();
    const group = new GroupFacade(client);
    const aidStore = { tag: 'group-store' };

    await group.transferOwner({ group_id: 'group.agentid.pub/10001', new_owner: 'bob.agentid.pub', aidStore } as any);

    expect(client.startTransferCalls).toEqual([
      {
        params: { group_id: 'group.agentid.pub/10001', new_owner: 'bob.agentid.pub' },
        options: { aidStore },
      },
    ]);
    expect(client.calls).toEqual([]);
  });

  it('completeTransfer 带 aidStore 时走 completeGroupTransfer 且不透传 aidStore', async () => {
    const client = new FakeClient();
    const group = new GroupFacade(client);
    const aidStore = { tag: 'new-owner-store' };

    await group.completeTransfer({ group_id: 'group.agentid.pub/10001', aidStore } as any);

    expect(client.completeTransferCalls).toEqual([
      {
        params: { group_id: 'group.agentid.pub/10001' },
        options: { aidStore },
      },
    ]);
    expect(client.calls).toEqual([]);
  });

  it('POSIX 方法映射到 group.fs.*，memberdata 路径原样透传', async () => {
    const client = new FakeClient();
    const fs = new GroupFacade(client).fs;

    await fs.ls('g-team.agentid.pub:/docs', { page: 1, size: 20 });
    await fs.find('g-team.agentid.pub:/docs', { pattern: '*.md' });
    await fs.stat('g-team.agentid.pub:/memberdata/me/logs/a.md');
    await fs.lstat('g-team.agentid.pub:/docs/link');
    await fs.mkdir('g-team.agentid.pub:/docs/new', { parents: true });
    await fs.setAcl('g-team.agentid.pub:/archive', { granteeAid: 'role:admin', perms: 'rwx' });
    await fs.removeAcl('g-team.agentid.pub:/archive', { granteeAid: 'role:admin' });
    await fs.getAcl('g-team.agentid.pub:/archive');
    await fs.listAcl('g-team.agentid.pub:/archive');
    await fs.rm('g-team.agentid.pub:/docs/old.md', { recursive: false, force: true });
    await fs.cp('g-team.agentid.pub:/docs/a.md', 'g-team.agentid.pub:/docs/b.md', { force: true });
    await fs.mv('g-team.agentid.pub:/docs/b.md', 'g-team.agentid.pub:/docs/c.md');
    await fs.df('g-team.agentid.pub:/');
    await fs.mount('g-team.agentid.pub:/memberdata/alice.agentid.pub');
    await fs.umount('g-team.agentid.pub:/memberdata/alice.agentid.pub');

    expect(client.calls.map((c) => c.method)).toEqual([
      'group.fs.ls',
      'group.fs.find',
      'group.fs.stat',
      'group.fs.lstat',
      'group.fs.mkdir',
      'group.fs.set_acl',
      'group.fs.remove_acl',
      'group.fs.get_acl',
      'group.fs.list_acl',
      'group.fs.rm',
      'group.fs.cp',
      'group.fs.mv',
      'group.fs.df',
      'group.fs.mount',
      'group.fs.umount',
    ]);
    expect(client.calls[2]).toEqual({
      method: 'group.fs.stat',
      params: { path: 'g-team.agentid.pub:/memberdata/me/logs/a.md' },
    });
    expect(client.calls[5]).toEqual({
      method: 'group.fs.set_acl',
      params: { path: 'g-team.agentid.pub:/archive', grantee_aid: 'role:admin', perms: 'rwx' },
    });
    expect(client.calls[6]).toEqual({
      method: 'group.fs.remove_acl',
      params: { path: 'g-team.agentid.pub:/archive', grantee_aid: 'role:admin' },
    });
    expect(client.calls[7]).toEqual({
      method: 'group.fs.get_acl',
      params: { path: 'g-team.agentid.pub:/archive' },
    });
    expect(client.calls[8]).toEqual({
      method: 'group.fs.list_acl',
      params: { path: 'g-team.agentid.pub:/archive' },
    });
    expect(client.calls[10]?.params).toEqual({
      src: 'g-team.agentid.pub:/docs/a.md',
      dst: 'g-team.agentid.pub:/docs/b.md',
      force: true,
    });
    expect(JSON.stringify(client.calls)).not.toContain('group_data');
  });

  it('cp group->group 只调用 group.fs.cp', async () => {
    const client = new FakeClient();
    const fs = new GroupFacade(client).fs;

    await fs.cp('g-team.agentid.pub:/a.md', 'g-team.agentid.pub:/b.md', {
      force: true,
      recursive: true,
      followSymlinks: false,
    });

    expect(client.calls).toEqual([
      {
        method: 'group.fs.cp',
        params: {
          src: 'g-team.agentid.pub:/a.md',
          dst: 'g-team.agentid.pub:/b.md',
          force: true,
          recursive: true,
          follow_symlinks: false,
        },
      },
    ]);
  });

  it('cp bytes/blob->group 走上传控制面并覆盖 force/parents/content_type', async () => {
    const data = bytes('hello group');
    const digest = await digestHex(data);
    const client = new FakeClient();
    client.responses = {
      'group.fs.check_upload': { target_exists: false },
      'group.fs.create_upload_session': {
        upload_url: 'https://upload.example.test/session-1',
        session_id: 's1',
        headers: { 'X-Upload': '1' },
      },
      'group.fs.complete_upload': { type: 'file', path: 'g-team.agentid.pub:/docs/a.md' },
    };
    const fs = new GroupFacade(client).fs;
    fs.lowlevel.httpPut = vi.fn().mockResolvedValue(undefined);

    await fs.cp(new Blob([data], { type: 'text/markdown' }), 'g-team.agentid.pub:/docs/a.md', {
      force: true,
      parents: true,
      metadata: { k: 'v' },
    });

    expect(client.calls.map((c) => c.method)).toEqual([
      'group.fs.check_upload',
      'group.fs.create_upload_session',
      'group.fs.complete_upload',
    ]);
    expect(client.calls[0]?.params).toEqual({
      path: 'g-team.agentid.pub:/docs/a.md',
      size_bytes: data.byteLength,
      sha256: digest,
      content_type: 'text/markdown',
      force: true,
      parents: true,
      metadata: { k: 'v' },
    });
    const putCall = vi.mocked(fs.lowlevel.httpPut).mock.calls[0];
    expect(putCall?.[0]).toBe('https://upload.example.test/session-1');
    expect(Array.from(putCall?.[1] as Uint8Array)).toEqual(Array.from(data));
    expect(putCall?.[2]).toEqual({ 'X-Upload': '1', 'Content-Type': 'text/markdown' });
    expect(client.calls[2]?.params).toMatchObject({ session_id: 's1', sha256: digest });
    expect(JSON.stringify(client.calls)).not.toContain('group_data');
  });

  it('cp string->group 在 JS 浏览器语义下默认把 string 当文本内容上传', async () => {
    const data = bytes('literal group text');
    const digest = await digestHex(data);
    const client = new FakeClient();
    client.responses = {
      'group.fs.check_upload': { target_exists: false },
      'group.fs.create_upload_session': {
        upload_url: 'https://upload.example.test/string-text',
        session_id: 's-text',
      },
      'group.fs.complete_upload': { type: 'file', path: 'g-team.agentid.pub:/docs/text.txt' },
    };
    const fs = new GroupFacade(client).fs;
    fs.lowlevel.httpPut = vi.fn().mockResolvedValue(undefined);

    await fs.cp('literal group text', 'g-team.agentid.pub:/docs/text.txt');

    expect(client.calls[0]?.params).toMatchObject({
      path: 'g-team.agentid.pub:/docs/text.txt',
      size_bytes: data.byteLength,
      sha256: digest,
      content_type: 'text/plain;charset=utf-8',
      parents: true,
    });
    const putCall = vi.mocked(fs.lowlevel.httpPut).mock.calls[0];
    expect(Array.from(putCall?.[1] as Uint8Array)).toEqual(Array.from(data));
    expect(putCall?.[2]).toEqual({ 'Content-Type': 'text/plain;charset=utf-8' });
  });

  it('cp group->bytes/blob 在浏览器返回 DownloadResult.data/blob，不要求写本地文件', async () => {
    const data = bytes('downloaded');
    const digest = await digestHex(data);
    const client = new FakeClient();
    client.responses = {
      'group.fs.create_download_ticket': {
        download_url: 'https://download.example.test/ticket-1',
        sha256: digest,
        content_type: 'text/plain',
      },
    };
    const fs = new GroupFacade(client).fs;
    client._identity = { access_token: 'viewer-token' };
    fs.lowlevel.httpGet = vi.fn().mockResolvedValue(data);

    const result = await fs.cp('g-team.agentid.pub:/docs/a.txt', { type: 'blob' }, { verifyHash: true });

    expect(client.calls).toEqual([
      {
        method: 'group.fs.create_download_ticket',
        params: { path: 'g-team.agentid.pub:/docs/a.txt' },
      },
    ]);
    expect(fs.lowlevel.httpGet).toHaveBeenCalledWith(
      'https://download.example.test/ticket-1',
      { Authorization: 'Bearer viewer-token' },
    );
    expect(result).toMatchObject({
      path: 'g-team.agentid.pub:/docs/a.txt',
      size: data.byteLength,
      sha256: digest,
      verified: true,
    });
    expect(result).not.toHaveProperty('wroteLocalFile');
    expect(Array.from((result as { data: Uint8Array }).data)).toEqual(Array.from(data));
    expect((result as { blob?: Blob }).blob).toBeInstanceOf(Blob);
  });

  it('cp bytes->group instant/dedup 命中时跳过 HTTP PUT', async () => {
    const data = bytes('same content');
    const digest = await digestHex(data);
    const client = new FakeClient();
    client.responses = {
      'group.fs.check_upload': { instant: true, session_id: 'instant-1' },
      'group.fs.complete_upload': { type: 'file', path: 'g-team.agentid.pub:/same.txt' },
    };
    const fs = new GroupFacade(client).fs;
    fs.lowlevel.httpPut = vi.fn().mockResolvedValue(undefined);

    await fs.cp(data, 'g-team.agentid.pub:/same.txt');

    expect(client.calls.map((c) => c.method)).toEqual([
      'group.fs.check_upload',
      'group.fs.complete_upload',
    ]);
    expect(client.calls[0]?.params).toMatchObject({
      path: 'g-team.agentid.pub:/same.txt',
      size_bytes: data.byteLength,
      sha256: digest,
      content_type: 'application/octet-stream',
    });
    expect(client.calls[1]?.params).toMatchObject({
      skip_blob: true,
      session_id: 'instant-1',
    });
    expect(fs.lowlevel.httpPut).not.toHaveBeenCalled();
  });

  it('cp group->bytes/blob 校验 sha256 失败时返回冲突错误', async () => {
    const client = new FakeClient();
    client.responses = {
      'group.fs.create_download_ticket': {
        download_url: 'https://download.example.test/bad',
        sha256: '0'.repeat(64),
      },
    };
    const fs = new GroupFacade(client).fs;
    fs.lowlevel.httpGet = vi.fn().mockResolvedValue(bytes('bad'));

    await expect(fs.cp('g-team.agentid.pub:/bad.txt', { type: 'bytes' }))
      .rejects.toMatchObject({ code: 'ECONFLICT' });
    expect(fs.lowlevel.httpGet).toHaveBeenCalledWith('https://download.example.test/bad', undefined);
  });

  it('cp group->local 在无本地 FS 的浏览器运行时返回数据且不覆盖宿主文件', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-js-'));
    try {
      const target = join(dir, 'a.txt');
      await writeFile(target, 'old');
      const data = bytes('new');
      const digest = await digestHex(data);
      const client = new FakeClient();
      client.responses = {
        'group.fs.create_download_ticket': {
          download_url: 'https://download.example.test/local',
          sha256: digest,
        },
      };
      const fs = new GroupFacade(client).fs;
      fs.lowlevel.httpGet = vi.fn().mockResolvedValue(data);

      const first = await fs.cp('g-team.agentid.pub:/a.txt', target);

      await expect(readFile(target, 'utf8')).resolves.toBe('old');
      expect(first).toMatchObject({
        path: 'g-team.agentid.pub:/a.txt',
        localPath: target,
        wroteLocalFile: false,
        verified: true,
      });

      const result = await fs.cp('g-team.agentid.pub:/a.txt', target, { force: true });

      await expect(readFile(target, 'utf8')).resolves.toBe('old');
      expect(result).toMatchObject({
        path: 'g-team.agentid.pub:/a.txt',
        localPath: target,
        wroteLocalFile: false,
        verified: true,
      });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('Windows drive 不误判为 group remote，显式 group_id 仍可让目标按 group 处理', async () => {
    expect(isGroupRemotePath('D:/tmp/a.md')).toBe(false);
    expect(isGroupRemotePath('D:\\tmp\\a.md')).toBe(false);
    expect(isGroupRemotePath('local:/tmp/a.md')).toBe(false);
    expect(isGroupRemotePath('g-team.agentid.pub:/docs/a.md')).toBe(true);

    const client = new FakeClient();
    client.responses = {
      'group.fs.check_upload': { instant: true, session_id: 'same-1' },
      'group.fs.complete_upload': { ok: true },
    };
    const fs = new GroupFacade(client).fs;
    vi.spyOn(fs as unknown as { sourceBytes(src: unknown): Promise<{ data: Uint8Array; contentType: string }> }, 'sourceBytes')
      .mockResolvedValue({ data: bytes('local'), contentType: 'application/octet-stream' });

    await fs.cp('D:/tmp/a.md', '/docs/a.md', { dstGroupId: 'g-team' });

    expect(client.calls.map((c) => c.method)).toEqual([
      'group.fs.check_upload',
      'group.fs.complete_upload',
    ]);
    expect(client.calls[0]?.params).toMatchObject({
      path: '/docs/a.md',
      group_id: 'g-team',
    });
  });

  it('local: 前缀在 JS SDK 中不会被误判为 group remote，并在无本地 FS 时保持显式边界', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-js-'));
    try {
      const local = join(dir, 'prefixed.txt');
      const target = join(dir, 'download.txt');
      await writeFile(local, 'hello local prefix');
      const data = bytes('hello local prefix');
      const digest = await digestHex(data);
      const client = new FakeClient();
      client.responses = {
        'group.fs.check_upload': { target_exists: false },
        'group.fs.create_upload_session': {
          upload_url: 'https://upload.example.test/local-prefix',
          session_id: 's-local',
        },
        'group.fs.complete_upload': { type: 'file', path: 'g-team.agentid.pub:/docs/prefixed.txt' },
        'group.fs.create_download_ticket': {
          download_url: 'https://download.example.test/local-prefix',
          sha256: digest,
        },
      };
      const fs = new GroupFacade(client).fs;
      fs.lowlevel.httpPut = vi.fn().mockResolvedValue(undefined);
      fs.lowlevel.httpGet = vi.fn().mockResolvedValue(data);

      await expect(fs.cp(`local:${local}`, 'g-team.agentid.pub:/docs/prefixed.txt'))
        .rejects.toMatchObject({ code: 'EUNSUPPORTED' });
      expect(client.calls).toEqual([]);

      const result = await fs.cp('g-team.agentid.pub:/docs/prefixed.txt', `local:${target}`, { force: true });

      await expect(readFile(target, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
      expect(result).toMatchObject({
        localPath: target,
        wroteLocalFile: false,
        verified: true,
      });
      expect(client.calls.map((c) => c.method)).toEqual([
        'group.fs.create_download_ticket',
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('local: 前缀优先于共享 group_id 判定', async () => {
    const data = bytes('active local prefix');
    const digest = await digestHex(data);
    const client = new FakeClient();
    client.responses = {
      'group.fs.check_upload': { instant: true, session_id: 'same-1' },
      'group.fs.complete_upload': { ok: true },
      'group.fs.create_download_ticket': {
        download_url: 'https://download.example.test/active-prefix',
        sha256: digest,
      },
    };
    const fs = new GroupFacade(client).fs;
    vi.spyOn(fs as unknown as { sourceBytes(src: unknown): Promise<{ data: Uint8Array; contentType: string }> }, 'sourceBytes')
      .mockResolvedValue({ data, contentType: 'application/octet-stream' });
    fs.lowlevel.httpGet = vi.fn().mockResolvedValue(data);

    await fs.cp('local:/tmp/active.md', '/docs/active.md', { group_id: 'group.example.test/team' });
    const result = await fs.cp('/docs/active.md', 'local:/tmp/out.md', { group_id: 'group.example.test/team', force: true });

    expect(result).toMatchObject({
      localPath: '/tmp/out.md',
      wroteLocalFile: false,
      verified: true,
    });
    expect(client.calls.map((c) => c.method)).toEqual([
      'group.fs.check_upload',
      'group.fs.complete_upload',
      'group.fs.create_download_ticket',
    ]);
    expect(client.calls[0]?.params).toMatchObject({
      path: '/docs/active.md',
      group_id: 'group.example.test/team',
    });
    expect(client.calls[2]?.params).toMatchObject({
      path: '/docs/active.md',
      group_id: 'group.example.test/team',
    });
  });

  it('裸路径支持共享 group_aid 参数', async () => {
    const data = bytes('active group aid');
    const digest = await digestHex(data);
    const client = new FakeClient();
    client.responses = {
      'group.fs.check_upload': { instant: true, session_id: 'same-aid' },
      'group.fs.complete_upload': { ok: true },
      'group.fs.create_download_ticket': {
        download_url: 'https://download.example.test/active-aid',
        sha256: digest,
      },
    };
    const fs = new GroupFacade(client).fs;
    vi.spyOn(fs as unknown as { sourceBytes(src: unknown): Promise<{ data: Uint8Array; contentType: string }> }, 'sourceBytes')
      .mockResolvedValue({ data, contentType: 'application/octet-stream' });
    fs.lowlevel.httpGet = vi.fn().mockResolvedValue(data);

    await fs.cp('local:/tmp/active-aid.md', '/docs/active-aid.md', { group_aid: 'team.agentid.pub' });
    const result = await fs.cp('/docs/active-aid.md', 'local:/tmp/out-aid.md', { group_aid: 'team.agentid.pub', force: true });

    expect(result).toMatchObject({
      localPath: '/tmp/out-aid.md',
      wroteLocalFile: false,
      verified: true,
    });
    expect(client.calls[0]?.params).toMatchObject({
      path: '/docs/active-aid.md',
      group_aid: 'team.agentid.pub',
    });
    expect(client.calls[0]?.params.group_id).toBeUndefined();
    expect(client.calls[2]?.params).toMatchObject({
      path: '/docs/active-aid.md',
      group_aid: 'team.agentid.pub',
    });
    expect(client.calls[2]?.params.group_id).toBeUndefined();
  });
});
