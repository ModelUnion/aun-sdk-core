// @vitest-environment node

import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import { GroupFSVFS } from '../../src/group-fs.js';
import type { RpcParams } from '../../src/types.js';

class FakeClient {
  calls: Array<{ method: string; params: Record<string, unknown> }> = [];

  async call(method: string, params?: RpcParams): Promise<unknown> {
    const merged = params ?? {};
    this.calls.push({ method, params: merged });
    if (method === 'group.fs.check_upload') {
      return { target_exists: false };
    }
    if (method === 'group.fs.create_upload_session') {
      return {
        upload_url: 'https://upload.example.test/session',
        session_id: 's1',
      };
    }
    if (method === 'group.fs.complete_upload') {
      return { type: 'file', path: merged.path };
    }
    return {
      download_url: 'https://download.example.test/existing',
      sha256: '',
    };
  }
}

describe('GroupFSVFS Node local download parity', () => {
  it('group -> local 目标已存在时先拒绝，不创建下载 ticket', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-node-'));
    try {
      const target = join(dir, 'a.txt');
      await writeFile(target, 'old');
      const client = new FakeClient();
      const fs = new GroupFSVFS(client);
      fs.lowlevel.httpGet = vi.fn().mockResolvedValue(new TextEncoder().encode('new'));

      await expect(fs.cp('g-team.agentid.pub:/a.txt', target)).rejects.toMatchObject({ code: 'EEXIST' });

      expect(client.calls).toEqual([]);
      expect(fs.lowlevel.httpGet).not.toHaveBeenCalled();
      await expect(readFile(target, 'utf8')).resolves.toBe('old');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('string 源显式 sourceType=path 时才读取 Node 本地文件', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aun-group-fs-node-'));
    try {
      const local = join(dir, 'source.md');
      await writeFile(local, 'node local path');
      const client = new FakeClient();
      const fs = new GroupFSVFS(client);
      fs.lowlevel.httpPut = vi.fn().mockResolvedValue(undefined);

      await fs.cp(local, 'g-team.agentid.pub:/docs/source.md', { sourceType: 'path' });

      expect(client.calls.map((c) => c.method)).toEqual([
        'group.fs.check_upload',
        'group.fs.create_upload_session',
        'group.fs.complete_upload',
      ]);
      expect(client.calls[0]?.params).toMatchObject({
        path: 'g-team.agentid.pub:/docs/source.md',
        size_bytes: 'node local path'.length,
        content_type: 'text/markdown',
        parents: true,
      });
      const putCall = vi.mocked(fs.lowlevel.httpPut).mock.calls[0];
      expect(new TextDecoder().decode(putCall?.[1] as Uint8Array)).toBe('node local path');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
