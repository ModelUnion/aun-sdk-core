// ── 客户端签名覆盖面测试 ──────────────────────────────────────
// SIGNED_METHODS 是模块私有常量，无法直接 import。
// 通过读取源文件提取方法列表，验证签名覆盖了所有关键操作。
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/** 从 client.ts 源文件中提取 SIGNED_METHODS 集合的方法名 */
function extractSignedMethods(file = '../../src/client.ts'): string[] {
  return extractMethodSet('SIGNED_METHODS', file);
}

function extractNonIdempotentMethods(file = '../../src/client.ts'): string[] {
  return extractMethodSet('NON_IDEMPOTENT_METHODS', file);
}

function extractMethodSet(name: string, file: string): string[] {
  const src = readFileSync(
    resolve(__dirname, file),
    'utf-8',
  );
  const match = src.match(
    new RegExp(`const\\s+${name}\\s*=\\s*new\\s+Set\\(\\[\\s*([\\s\\S]*?)\\]\\)`),
  );
  if (!match) throw new Error(`未找到 ${name} 定义`);
  const methods: string[] = [];
  for (const m of match[1].matchAll(/'([^']+)'/g)) {
    methods.push(m[1]);
  }
  return methods;
}

const STORAGE_MUTATION_METHODS = [
  'storage.put_object',
  'storage.delete_object',
  'storage.get_by_share',
  'storage.create_share_link',
  'storage.revoke_share_link',
  'storage.create_upload_session',
  'storage.complete_upload',
  'storage.create_folder',
  'storage.rename_folder',
  'storage.move_folder',
  'storage.delete_folder',
  'storage.move_object',
  'storage.copy_object',
  'storage.batch_delete',
  'storage.set_object_meta',
  'storage.append_object',
  'storage.set_acl',
  'storage.remove_acl',
  'storage.set_visibility',
  'storage.issue_token',
  'storage.revoke_token',
  'storage.create_symlink',
  'storage.atomic_repoint',
  'storage.rename_symlink',
  'storage.delete_symlink',
  'storage.fs.mkdir',
  'storage.fs.remove',
  'storage.fs.rename',
  'storage.fs.copy',
  'storage.fs.mount',
  'storage.fs.approve',
  'storage.fs.reject',
  'storage.fs.unmount',
  'storage.fs.invalidate_membership',
  'storage.volume.create',
  'storage.volume.renew',
  'storage.volume.expire_due',
] as const;

const COLLAB_MUTATION_METHODS = [
  'collab.create',
  'collab.commit',
  'collab.clone',
  'collab.prune',
  'collab.unregister',
  'collab.tag.create',
  'collab.tag.restore',
  'collab.tag.rm',
  'collab.tag.prune',
] as const;

const GROUP_FS_CONTROL_METHODS = [
  'group.fs.mkdir',
  'group.fs.rm',
  'group.fs.cp',
  'group.fs.mv',
  'group.fs.set_acl',
  'group.fs.remove_acl',
  'group.fs.mount',
  'group.fs.umount',
  'group.fs.check_upload',
  'group.fs.create_upload_session',
  'group.fs.complete_upload',
  'group.fs.create_download_ticket',
] as const;

/** 预期需要签名的方法 */
const EXPECTED_SIGNED_METHODS = [
  'message.send',
  'message.v2.put_peer_pk',
  'message.v2.bootstrap',
  'message.v2.group_bootstrap',
  'message.v2.pull',
  'message.v2.ack',
  'group.send',
  'group.v2.put_group_pk',
  'group.v2.bootstrap',
  'group.v2.send',
  'group.v2.pull',
  'group.v2.ack',
  'group.v2.propose_state',
  'group.v2.confirm_state',
  'group.v2.get_proposal',
  'group.kick',
  'group.add_member',
  'group.leave',
  'group.remove_member',
  'group.update_rules',
  'group.update',
  'group.update_announcement',
  'group.update_join_requirements',
  'group.set_role',
  'group.transfer_owner',
  'group.bind_group_aid',
  'group.renew_group_aid',
  'group.complete_transfer',
  'group.review_join_request',
  'group.batch_review_join_request',
  'group.request_join',
  'group.use_invite_code',
  'group.thought.put',
  'message.thought.put',
  'group.set_settings',
  'group.commit_state',
  'group.ban',
  'group.unban',
  'group.dissolve',
  'group.suspend',
  'group.resume',
  'storage.check_access',
  ...GROUP_FS_CONTROL_METHODS,
  ...COLLAB_MUTATION_METHODS,
  ...STORAGE_MUTATION_METHODS,
] as const;

describe('SIGNED_METHODS 签名覆盖面', () => {
  const actual = extractSignedMethods();

  it('应包含全部预期方法', () => {
    expect(actual).toHaveLength(EXPECTED_SIGNED_METHODS.length);
  });

  it('每个预期方法都应在 SIGNED_METHODS 中', () => {
    for (const method of EXPECTED_SIGNED_METHODS) {
      expect(actual, `缺少方法: ${method}`).toContain(method);
    }
  });

  it('不应包含预期之外的方法', () => {
    const expectedSet = new Set<string>(EXPECTED_SIGNED_METHODS);
    const unexpected = actual.filter((m) => !expectedSet.has(m));
    expect(unexpected, `意外的签名方法: ${unexpected.join(', ')}`).toHaveLength(0);
  });

  it('不应包含已移除的 V1 E2EE 控制面方法', () => {
    expect(actual.some((m) => m.startsWith('message.e2ee.') || m.startsWith('group.e2ee.'))).toBe(false);
    expect(actual).not.toContain('group.rotate_epoch');
  });

  it('storage 写操作和有副作用读操作应进入非幂等长超时集合', () => {
    const nonIdempotent = extractNonIdempotentMethods();
    for (const method of STORAGE_MUTATION_METHODS) {
      expect(nonIdempotent, `缺少非幂等方法: ${method}`).toContain(method);
    }
  });

  it('collab 写操作应进入签名和非幂等长超时集合', () => {
    const signed = extractSignedMethods();
    const runtimeSigned = extractSignedMethods('../../src/client/rpc-pipeline.ts');
    const nonIdempotent = extractNonIdempotentMethods();
    const runtimeNonIdempotent = extractNonIdempotentMethods('../../src/client/rpc-pipeline.ts');
    for (const method of COLLAB_MUTATION_METHODS) {
      expect(signed, `缺少签名方法: ${method}`).toContain(method);
      expect(runtimeSigned, `运行时签名集合缺少: ${method}`).toContain(method);
      expect(nonIdempotent, `缺少非幂等方法: ${method}`).toContain(method);
      expect(runtimeNonIdempotent, `运行时非幂等集合缺少: ${method}`).toContain(method);
    }
  });

  it('运行时 RpcPipeline 应覆盖同一组 storage 签名和非幂等方法', () => {
    const signed = extractSignedMethods('../../src/client/rpc-pipeline.ts');
    const nonIdempotent = extractNonIdempotentMethods('../../src/client/rpc-pipeline.ts');
    for (const method of STORAGE_MUTATION_METHODS) {
      expect(signed, `运行时签名集合缺少: ${method}`).toContain(method);
      expect(nonIdempotent, `运行时非幂等集合缺少: ${method}`).toContain(method);
    }
    expect(signed, '运行时签名集合缺少: storage.check_access').toContain('storage.check_access');
    expect(nonIdempotent, 'storage.check_access 不应进入非幂等集合').not.toContain('storage.check_access');
  });
  it('group.fs 写侧和 ticket/session 控制面应进入签名和非幂等长超时集合', () => {
    const signed = extractSignedMethods();
    const runtimeSigned = extractSignedMethods('../../src/client/rpc-pipeline.ts');
    const nonIdempotent = extractNonIdempotentMethods();
    const runtimeNonIdempotent = extractNonIdempotentMethods('../../src/client/rpc-pipeline.ts');
    for (const method of GROUP_FS_CONTROL_METHODS) {
      expect(signed, `缺少签名方法: ${method}`).toContain(method);
      expect(runtimeSigned, `运行时签名集合缺少: ${method}`).toContain(method);
      expect(nonIdempotent, `缺少非幂等方法: ${method}`).toContain(method);
      expect(runtimeNonIdempotent, `运行时非幂等集合缺少: ${method}`).toContain(method);
    }
  });
});
