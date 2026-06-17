import { describe, expect, it, vi } from 'vitest';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { AUNClient } from '../../src/client.js';
import { GroupFacade } from '../../src/facades.js';
import { isGroupRemotePath } from '../../src/group-fs.js';

const GROUP_FS_POSIX_METHODS = [
  'ls',
  'find',
  'stat',
  'lstat',
  'mkdir',
  'rm',
  'cp',
  'mv',
  'df',
  'mount',
  'umount',
] as const;

const GROUP_FS_FORBIDDEN_METHODS = ['read', 'write', 'put', 'get'] as const;

class FakeLowLevel {
  puts: Array<{ url: string; data: Uint8Array; headers: Record<string, string> | undefined }> = [];
  gets: string[] = [];
  getHeaders: Array<Record<string, string> | undefined> = [];

  constructor(readonly downloadData = new Uint8Array()) {}

  async httpPut(url: string, data: Uint8Array, headers?: Record<string, string>): Promise<void> {
    this.puts.push({ url, data: new Uint8Array(data), headers });
  }

  async httpGet(url: string, headers?: Record<string, string>): Promise<Uint8Array> {
    this.gets.push(url);
    this.getHeaders.push(headers);
    return new Uint8Array(this.downloadData);
  }
}

class FakeClient {
  aid = 'alice.agentid.pub';
  _identity?: Record<string, unknown>;
  _sessionParams?: Record<string, unknown>;
  calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  responses: Record<string, Record<string, unknown>> = {};

  async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
    const callParams = params ?? {};
    this.calls.push({ method, params: callParams });
    return this.responses[method] ?? { method, params: callParams };
  }
}

function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

describe('Phase 6 GroupFSVFS TypeScript 契约', () => {
  it('client.group.fs 暴露 POSIX 方法且不暴露 read/write/put/get 主入口', () => {
    const client = new AUNClient();

    expect(client.group).toBeInstanceOf(GroupFacade);
    expect(client.group.fs).toBe(client.group.fs);
    for (const method of GROUP_FS_POSIX_METHODS) {
      expect(method in client.group.fs).toBe(true);
      expect(typeof client.group.fs[method]).toBe('function');
    }
    for (const method of GROUP_FS_FORBIDDEN_METHODS) {
      expect(method in client.group.fs).toBe(false);
    }
  });

  it('POSIX 方法调用 group.fs.* 并过滤 null/undefined', async () => {
    const client = new FakeClient();
    const fs = new GroupFacade(client).fs;

    await fs.ls('g-team.agentid.pub:/docs', { page: 1, size: 20, marker: null });
    await fs.find('g-team.agentid.pub:/docs', { pattern: '*.md' });
    await fs.stat('g-team.agentid.pub:/docs/a.md');
    await fs.lstat('g-team.agentid.pub:/docs/link');
    await fs.mkdir('g-team.agentid.pub:/docs/new', { parents: true });
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
      'group.fs.rm',
      'group.fs.cp',
      'group.fs.mv',
      'group.fs.df',
      'group.fs.mount',
      'group.fs.umount',
    ]);
    expect(client.calls[0].params).toEqual({ path: 'g-team.agentid.pub:/docs', page: 1, size: 20 });
    expect(client.calls[4].params).toEqual({ path: 'g-team.agentid.pub:/docs/new', parents: true });
    expect(client.calls[6].params).toEqual({
      src: 'g-team.agentid.pub:/docs/a.md',
      dst: 'g-team.agentid.pub:/docs/b.md',
      force: true,
    });
  });

  it('group remote 判定不会把 Windows drive 路径误判为 group 路径', () => {
    expect(isGroupRemotePath('g-team.agentid.pub:/docs/a.md')).toBe(true);
    expect(isGroupRemotePath('https://g-team.agentid.pub/docs/a.md')).toBe(true);
    expect(isGroupRemotePath('http://g-team.agentid.pub/docs/a.md')).toBe(true);

    expect(isGroupRemotePath('D:/tmp/a.md')).toBe(false);
    expect(isGroupRemotePath('D:\\tmp\\a.md')).toBe(false);
    expect(isGroupRemotePath('local:/tmp/a.md')).toBe(false);
    expect(isGroupRemotePath('relative/a.md')).toBe(false);
    expect(isGroupRemotePath('/tmp/a.md')).toBe(false);
  });

  it('cp group -> group 只调用 group.fs.cp', async () => {
    const client = new FakeClient();
    const fs = new GroupFacade(client).fs;

    await fs.cp('g-team.agentid.pub:/a.md', 'g-team.agentid.pub:/b.md', {
      overwrite: true,
      recursive: true,
      followSymlinks: false,
    });

    expect(client.calls).toEqual([{
      method: 'group.fs.cp',
      params: {
        src: 'g-team.agentid.pub:/a.md',
        dst: 'g-team.agentid.pub:/b.md',
        force: true,
        recursive: true,
        follow_symlinks: false,
      },
    }]);
  });

  it('cp local -> group 走上传控制面并执行 HTTP PUT', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-'));
    try {
      const local = join(dir, 'a.md');
      await writeFile(local, 'hello group');
      const digest = sha256Hex('hello group');
      const client = new FakeClient();
      client.responses = {
        'group.fs.check_upload': { target_exists: false },
        'group.fs.create_upload_session': {
          upload_url: 'https://upload.example.test/session-1',
          session_id: 's1',
          headers: { 'X-Upload': '1' },
        },
        'group.fs.complete_upload': {
          type: 'file',
          path: 'g-team.agentid.pub:/docs/a.md',
          size: 'hello group'.length,
          sha256: digest,
        },
      };
      const lowlevel = new FakeLowLevel();
      const fs = new GroupFacade(client).fs;
      fs.lowlevel = lowlevel;

      const result = await fs.cp(local, 'g-team.agentid.pub:/docs/a.md', {
        force: true,
        parents: true,
        contentType: 'text/markdown',
      });

      expect(result).toMatchObject({ path: 'g-team.agentid.pub:/docs/a.md', sha256: digest });
      expect(client.calls.map((c) => c.method)).toEqual([
        'group.fs.check_upload',
        'group.fs.create_upload_session',
        'group.fs.complete_upload',
      ]);
      expect(client.calls[0].params).toEqual({
        path: 'g-team.agentid.pub:/docs/a.md',
        size_bytes: 'hello group'.length,
        sha256: digest,
        content_type: 'text/markdown',
        force: true,
        parents: true,
      });
      expect(client.calls[2].params).toMatchObject({
        path: 'g-team.agentid.pub:/docs/a.md',
        session_id: 's1',
        sha256: digest,
      });
      expect(lowlevel.puts).toHaveLength(1);
      expect(lowlevel.puts[0].url).toBe('https://upload.example.test/session-1');
      expect(new TextDecoder().decode(lowlevel.puts[0].data)).toBe('hello group');
      expect(lowlevel.puts[0].headers).toEqual({ 'X-Upload': '1', 'Content-Type': 'text/markdown' });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cp local: 前缀会作为显式本地路径并在读写本地文件前剥离', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-'));
    try {
      const local = join(dir, 'prefixed.md');
      const targetDir = join(dir, 'download');
      await writeFile(local, 'hello local prefix');
      await mkdir(targetDir);
      const digest = sha256Hex('hello local prefix');
      const client = new FakeClient();
      client.responses = {
        'group.fs.check_upload': { target_exists: false },
        'group.fs.create_upload_session': {
          upload_url: 'https://upload.example.test/local-prefix',
          session_id: 's-local',
        },
        'group.fs.complete_upload': { type: 'file', path: 'g-team.agentid.pub:/docs/prefixed.md' },
        'group.fs.create_download_ticket': {
          download_url: 'https://download.example.test/local-prefix',
          sha256: digest,
          file_name: 'prefixed.md',
        },
      };
      const lowlevel = new FakeLowLevel(new TextEncoder().encode('hello local prefix'));
      const fs = new GroupFacade(client).fs;
      fs.lowlevel = lowlevel;

      await fs.cp(`local:${local}`, 'g-team.agentid.pub:/docs/prefixed.md');
      const result = await fs.cp('g-team.agentid.pub:/docs/prefixed.md', `local:${targetDir}`);

      expect(new TextDecoder().decode(lowlevel.puts[0].data)).toBe('hello local prefix');
      await expect(readFile(join(targetDir, 'prefixed.md'), 'utf8')).resolves.toBe('hello local prefix');
      expect(result).toMatchObject({ localPath: join(targetDir, 'prefixed.md'), verified: true });
      expect(client.calls.map((c) => c.method)).toEqual([
        'group.fs.check_upload',
        'group.fs.create_upload_session',
        'group.fs.complete_upload',
        'group.fs.create_download_ticket',
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cp local: 前缀优先于共享 group_id 判定', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-'));
    try {
      const local = join(dir, 'active.md');
      const target = join(dir, 'out.md');
      await writeFile(local, 'active local prefix');
      const digest = sha256Hex('active local prefix');
      const client = new FakeClient();
      client.responses = {
        'group.fs.check_upload': { target_exists: false },
        'group.fs.create_upload_session': {
          upload_url: 'https://upload.example.test/active-prefix',
          session_id: 's-active',
        },
        'group.fs.complete_upload': { type: 'file', path: '/docs/active.md' },
        'group.fs.create_download_ticket': {
          download_url: 'https://download.example.test/active-prefix',
          sha256: digest,
          file_name: 'active.md',
        },
      };
      const lowlevel = new FakeLowLevel(new TextEncoder().encode('active local prefix'));
      const fs = new GroupFacade(client).fs;
      fs.lowlevel = lowlevel;

      await fs.cp(`local:${local}`, '/docs/active.md', { group_id: 'group.example.test/team' });
      const result = await fs.cp('/docs/active.md', `local:${target}`, { group_id: 'group.example.test/team' });

      expect(new TextDecoder().decode(lowlevel.puts[0].data)).toBe('active local prefix');
      await expect(readFile(target, 'utf8')).resolves.toBe('active local prefix');
      expect(result).toMatchObject({ localPath: target, verified: true });
      expect(client.calls.map((c) => c.method)).toEqual([
        'group.fs.check_upload',
        'group.fs.create_upload_session',
        'group.fs.complete_upload',
        'group.fs.create_download_ticket',
      ]);
      expect(client.calls[0].params.group_id).toBe('group.example.test/team');
      expect(client.calls[3].params.group_id).toBe('group.example.test/team');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cp blob -> group 走同一上传控制面但不读取本地路径', async () => {
    const data = new Blob(['blob group'], { type: 'text/plain' });
    const digest = sha256Hex(new TextEncoder().encode('blob group'));
    const client = new FakeClient();
    client.responses = {
      'group.fs.check_upload': { instant: true, session_id: 'instant-1' },
      'group.fs.complete_upload': { type: 'file', path: 'g-team.agentid.pub:/blob.txt' },
    };
    const lowlevel = new FakeLowLevel();
    const fs = new GroupFacade(client).fs;
    fs.lowlevel = lowlevel;

    await fs.cp(data, 'g-team.agentid.pub:/blob.txt', { contentType: 'text/plain' });

    expect(client.calls.map((c) => c.method)).toEqual([
      'group.fs.check_upload',
      'group.fs.complete_upload',
    ]);
    expect(client.calls[0].params).toMatchObject({
      path: 'g-team.agentid.pub:/blob.txt',
      size_bytes: 10,
      sha256: digest,
      content_type: 'text/plain',
    });
    expect(client.calls[1].params).toMatchObject({
      skip_blob: true,
      session_id: 'instant-1',
    });
    expect(lowlevel.puts).toEqual([]);
  });

  it('cp local -> group 默认拒绝已存在目标，overwrite=true 才继续', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-'));
    try {
      const local = join(dir, 'a.txt');
      await writeFile(local, 'hello');
      const client = new FakeClient();
      client.responses = {
        'group.fs.check_upload': { target_exists: true, target: { path: 'g-team.agentid.pub:/a.txt' } },
        'group.fs.create_upload_session': {
          upload_url: 'https://upload.example.test/session-overwrite',
          session_id: 's-overwrite',
        },
        'group.fs.complete_upload': { type: 'file', path: 'g-team.agentid.pub:/a.txt' },
      };
      const lowlevel = new FakeLowLevel();
      const fs = new GroupFacade(client).fs;
      fs.lowlevel = lowlevel;

      await expect(fs.cp(local, 'g-team.agentid.pub:/a.txt')).rejects.toMatchObject({ code: 'EEXIST' });
      expect(client.calls.map((c) => c.method)).toEqual(['group.fs.check_upload']);

      await fs.cp(local, 'g-team.agentid.pub:/a.txt', { overwrite: true });

      expect(client.calls.map((c) => c.method)).toEqual([
        'group.fs.check_upload',
        'group.fs.check_upload',
        'group.fs.create_upload_session',
        'group.fs.complete_upload',
      ]);
      expect(client.calls[1].params.force).toBe(true);
      expect(client.calls[2].params.force).toBe(true);
      expect(lowlevel.puts).toHaveLength(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cp group -> local 写入下载文件并校验 hash', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-'));
    try {
      const data = new TextEncoder().encode('downloaded');
      const digest = sha256Hex(data);
      const target = join(dir, 'out', 'a.md');
      const client = new FakeClient();
      client.responses = {
        'group.fs.create_download_ticket': {
          download_url: 'https://download.example.test/ticket-1',
          sha256: digest,
          file_name: 'a.md',
        },
      };
      const lowlevel = new FakeLowLevel(data);
      const fs = new GroupFacade(client).fs;
      client._identity = { access_token: 'viewer-token' };
      fs.lowlevel = lowlevel;

      const result = await fs.cp('g-team.agentid.pub:/docs/a.md', target);

      await expect(readFile(target, 'utf8')).resolves.toBe('downloaded');
      expect(result).toMatchObject({
        path: 'g-team.agentid.pub:/docs/a.md',
        localPath: target,
        size: data.byteLength,
        sha256: digest,
        verified: true,
      });
      expect(client.calls).toEqual([{
        method: 'group.fs.create_download_ticket',
        params: { path: 'g-team.agentid.pub:/docs/a.md' },
      }]);
      expect(lowlevel.gets).toEqual(['https://download.example.test/ticket-1']);
      expect(lowlevel.getHeaders).toEqual([{ Authorization: 'Bearer viewer-token' }]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cp group -> blob 返回内存数据，不把目标当成本地路径', async () => {
    const data = new TextEncoder().encode('blob download');
    const digest = sha256Hex(data);
    const client = new FakeClient();
    client.responses = {
      'group.fs.create_download_ticket': {
        download_url: 'https://download.example.test/blob-1',
        sha256: digest,
        content_type: 'text/plain',
      },
    };
    const lowlevel = new FakeLowLevel(data);
    const fs = new GroupFacade(client).fs;
    fs.lowlevel = lowlevel;

    const result = await fs.cp('g-team.agentid.pub:/docs/blob.txt', { kind: 'blob' });

    expect(result).toMatchObject({
      path: 'g-team.agentid.pub:/docs/blob.txt',
      size: data.byteLength,
      sha256: digest,
      verified: true,
    });
    expect(result.data).toEqual(data);
    expect(result.blob).toBeInstanceOf(Blob);
    await expect(result.blob?.text()).resolves.toBe('blob download');
    expect(client.calls).toEqual([{
      method: 'group.fs.create_download_ticket',
      params: { path: 'g-team.agentid.pub:/docs/blob.txt' },
    }]);
  });

  it('cp group -> local 默认拒绝覆盖已有文件', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-'));
    try {
      const target = join(dir, 'a.md');
      await writeFile(target, 'exists');
      const client = new FakeClient();
      const fs = new GroupFacade(client).fs;
      fs.lowlevel = new FakeLowLevel(new TextEncoder().encode('new'));

      await expect(fs.cp('g-team.agentid.pub:/docs/a.md', target)).rejects.toMatchObject({ code: 'EEXIST' });
      await expect(readFile(target, 'utf8')).resolves.toBe('exists');
      expect(client.calls).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cp group -> local 支持 overwrite=true 覆盖已有文件', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-'));
    try {
      const target = join(dir, 'a.md');
      await writeFile(target, 'old');
      const data = new TextEncoder().encode('new');
      const digest = sha256Hex(data);
      const client = new FakeClient();
      client.responses = {
        'group.fs.create_download_ticket': {
          download_url: 'https://download.example.test/overwrite',
          sha256: digest,
        },
      };
      const fs = new GroupFacade(client).fs;
      fs.lowlevel = new FakeLowLevel(data);

      const result = await fs.cp('g-team.agentid.pub:/docs/a.md', target, { overwrite: true });

      await expect(readFile(target, 'utf8')).resolves.toBe('new');
      expect(result).toMatchObject({ localPath: target, verified: true });
      expect(client.calls).toEqual([{
        method: 'group.fs.create_download_ticket',
        params: { path: 'g-team.agentid.pub:/docs/a.md' },
      }]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('cp group -> local 校验 sha256 失败时不写入目标文件', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-'));
    try {
      const target = join(dir, 'bad.md');
      const client = new FakeClient();
      client.responses = {
        'group.fs.create_download_ticket': {
          download_url: 'https://download.example.test/bad',
          sha256: '0'.repeat(64),
        },
      };
      const fs = new GroupFacade(client).fs;
      fs.lowlevel = new FakeLowLevel(new TextEncoder().encode('bad'));

      await expect(fs.cp('g-team.agentid.pub:/docs/bad.md', target)).rejects.toMatchObject({ code: 'ECONFLICT' });
      await expect(readFile(target, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('mv 只允许 group remote 路径，Windows drive 不触发 group remote 分支', async () => {
    const client = new FakeClient();
    const fs = new GroupFacade(client).fs;

    await expect(fs.mv('D:/tmp/a.md', 'g-team.agentid.pub:/a.md')).rejects.toMatchObject({ code: 'EINVAL' });
    await expect(fs.mv('g-team.agentid.pub:/a.md', 'D:/tmp/a.md')).rejects.toMatchObject({ code: 'EINVAL' });
    expect(client.calls).toEqual([]);
  });

  it('memberdata 路径原样传递，SDK 不做服务端存储路径映射', async () => {
    const client = new FakeClient();
    const fs = new GroupFacade(client).fs;
    const mappedStoragePrefix = ['group', 'data'].join('');

    await fs.stat('g-team.agentid.pub:/memberdata/me/logs/a.md');
    await fs.cp('g-team.agentid.pub:/memberdata/me/a.md', 'g-team.agentid.pub:/memberdata/me/b.md');

    expect(client.calls).toEqual([
      {
        method: 'group.fs.stat',
        params: { path: 'g-team.agentid.pub:/memberdata/me/logs/a.md' },
      },
      {
        method: 'group.fs.cp',
        params: {
          src: 'g-team.agentid.pub:/memberdata/me/a.md',
          dst: 'g-team.agentid.pub:/memberdata/me/b.md',
        },
      },
    ]);
    expect(JSON.stringify(client.calls)).not.toContain(mappedStoragePrefix);

    const source = readFileSync(new URL('../../src/group-fs.ts', import.meta.url), 'utf8');
    expect(source).not.toContain(mappedStoragePrefix);
  });
});
