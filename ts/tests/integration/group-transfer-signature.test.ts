// F07 / F18：跨语言互操作——TS 生成的旧群主转让授权签名能被 Python 服务端验通。
//
// 在 kite-ts-tester 容器内运行：
//   docker exec kite-ts-tester bash -lc "cd /workspace/ts && npx vitest run tests/integration/group-transfer-signature.test.ts"
//
// 覆盖 F07 三方签名链的 TS 侧：createGroup 落 group_aid 私钥 →
// startGroupTransfer 用该私钥签 canonical payload → 服务端验签放行 pending_rekey。
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { AUNClient } from '../../src/client.js';
import { createTestClient, createAIDStore, createAIDStoreForClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 10);
}

function isNotImplemented(e: any): boolean {
  const msg = (e?.message ?? '').toLowerCase();
  return msg.includes('not implement') || msg.includes('method not found') || msg.includes('unknown method');
}

describe('F07 跨语言：TS 旧群主转让签名被服务端验通', () => {
  it('createGroup → startGroupTransfer 返回 pending_rekey', async () => {
    const rid = runId();
    const ownerAid = `gtx-own-${rid}.${ISSUER}`;
    const newOwnerAid = `gtx-new-${rid}.${ISSUER}`;
    const ownerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gtx-'));
    const owner = createTestClient({ aunPath: ownerDir, debug: false, requireForwardSecrecy: false });
    const newOwner = createTestClient({
      aunPath: fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gtx-')),
      debug: false, requireForwardSecrecy: false,
    });
    const store = createAIDStore({ aunPath: ownerDir });
    let groupId = '';

    try {
      await registerAndLoadIdentity(owner, ownerAid);
      await owner.connect();
      await registerAndLoadIdentity(newOwner, newOwnerAid);
      await newOwner.connect();

      let created: any;
      try {
        created = await owner.createGroup(
          { name: `gtx-${rid}`, group_name: `gtx${rid}`, visibility: 'private' },
          { aidStore: store },
        );
      } catch (e) {
        if (isNotImplemented(e)) { console.log('createGroup 未实现，跳过'); return; }
        throw e;
      }
      const group = (created?.group ?? {}) as Record<string, any>;
      groupId = String(group.group_id ?? '').trim();
      const groupAid = String(group.group_aid ?? '').trim();
      expect(groupId).not.toBe('');
      expect(groupAid).not.toBe('');

      await owner.call('group.add_member', { group_id: groupId, aid: newOwnerAid, role: 'member' });

      // TS 用 group_aid 私钥签名发起转让 —— 服务端（Python）必须验通
      const transfer = await owner.startGroupTransfer(
        { group_id: groupId, new_owner: newOwnerAid },
        { aidStore: store },
      ) as Record<string, any>;

      expect(transfer.status).toBe('pending_rekey');
      expect(transfer.requires_ca_rekey).toBe(true);
      expect(String(transfer.new_owner ?? '')).toBe(newOwnerAid);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* ignore */ }
      }
      try { store.close?.(); } catch { /* ignore */ }
      await newOwner.close();
      await owner.close();
    }
  }, 60000);

  it('TS 建群并写 group-storage 后，Python SDK 可读取同一资源', async () => {
    const rid = runId();
    const ownerAid = `gtx-gs-own-${rid}.${ISSUER}`;
    const readerAid = `gtx-gs-reader-${rid}.${ISSUER}`;
    const ownerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gtx-gs-owner-'));
    const readerDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-gtx-gs-reader-'));
    const owner = createTestClient({ aunPath: ownerDir, debug: false, requireForwardSecrecy: false });
    const reader = createTestClient({ aunPath: readerDir, debug: false, requireForwardSecrecy: false });
    const ownerStore = createAIDStoreForClient(owner);
    let groupId = '';

    try {
      await registerAndLoadIdentity(owner, ownerAid);
      await owner.connect();
      await registerAndLoadIdentity(reader, readerAid);
      await reader.connect();

      const created = await owner.createGroup(
        { name: `gtx-gs-${rid}`, group_name: `gtxgs${rid}`, visibility: 'private' },
        { aidStore: ownerStore } as any,
      ) as Record<string, any>;
      const group = (created.group ?? {}) as Record<string, any>;
      groupId = String(group.group_id ?? '').trim();
      const groupAid = String(group.group_aid ?? '').trim();
      expect(groupId).not.toBe('');
      expect(groupAid).not.toBe('');

      await owner.call('group.add_member', { group_id: groupId, aid: readerAid, role: 'member' });
      await owner.group.resources.initializeNamespace(
        { group_id: groupId, group_aid: groupAid },
        { aidStore: ownerStore } as any,
      );

      const resourcePath = `announce/ts-python-${rid}.txt`;
      const body = `TS_PYTHON_GROUP_STORAGE_${rid}`;
      const pending = await owner.group.resources.put({
        group_id: groupId,
        resource_path: resourcePath,
        resource_type: 'file',
        content: Buffer.from(body, 'utf8').toString('base64'),
        content_type: 'text/plain',
      }) as Record<string, any>;
      const confirmed = await owner.group.resources.executePendingOps(pending, { aidStore: ownerStore } as any) as Record<string, any>;
      expect(Boolean((confirmed.confirmed as any)?.confirmed)).toBe(true);

      const script = [
        'import asyncio, os, sys, ssl, urllib.request',
        'from pathlib import Path',
        'sys.path.insert(0, os.environ["AUN_PY_SRC"])',
        'sys.path.insert(0, os.environ["AUN_PY_TESTS"])',
        'from aun_refactor_helpers import ensure_connected_identity, make_client_for_path',
        'async def main():',
        '    c = make_client_for_path(os.environ["AUN_READER_PATH"], require_forward_secrecy=False)',
        '    try:',
        '        await ensure_connected_identity(c, os.environ["AUN_READER_AID"])',
        '        access = await c.group.resources.get_access({"group_id": os.environ["AUN_GROUP_ID"], "resource_path": os.environ["AUN_RESOURCE_PATH"]})',
        '        url = (access.get("download") or {}).get("download_url") or ""',
        '        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE',
        '        data = urllib.request.urlopen(url, timeout=20, context=ctx).read().decode("utf-8")',
        '        assert data == os.environ["AUN_EXPECT_BODY"], (data, os.environ["AUN_EXPECT_BODY"])',
        '    finally:',
        '        await c.close()',
        'asyncio.run(main())',
      ].join('\n');
      const repoRoot = path.resolve(__dirname, '..', '..', '..');
      const pythonBin = process.env.PYTHON ?? 'python3';
      const py = spawnSync(pythonBin, ['-c', script], {
        encoding: 'utf8',
        env: {
          ...process.env,
          AUN_PY_SRC: path.resolve(repoRoot, 'python', 'src'),
          AUN_PY_TESTS: path.resolve(repoRoot, 'python', 'tests'),
          AUN_READER_PATH: readerDir,
          AUN_READER_AID: readerAid,
          AUN_GROUP_ID: groupId,
          AUN_RESOURCE_PATH: resourcePath,
          AUN_EXPECT_BODY: body,
        },
      });
      expect(py.status, `${py.error ? String(py.error) : ''}\n${py.stdout}\n${py.stderr}`).toBe(0);
    } finally {
      if (groupId) {
        try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* ignore */ }
      }
      try { ownerStore.close?.(); } catch { /* ignore */ }
      await reader.close();
      await owner.close();
    }
  }, 90000);
});
