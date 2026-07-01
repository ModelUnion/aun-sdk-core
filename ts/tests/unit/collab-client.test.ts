import { describe, expect, it } from 'vitest';

import { AUNClient } from '../../src/client.js';
import { AUNError } from '../../src/errors.js';
import { CollabClient, CollabConflictError } from '../../src/collab/index.js';

class FakeClient {
  calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  responses = new Map<string, unknown>();

  async call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    this.calls.push({ method, params: params ?? {} });
    const response = this.responses.get(method) ?? { ok: true, method };
    if (response instanceof Error) throw response;
    return response;
  }
}

describe('CollabClient TypeScript 契约', () => {
  it('commit 调用裸 collab.commit 并透传精确参数', async () => {
    const client = new FakeClient();
    const collab = new CollabClient(client);

    const result = await collab.commit('alice.aid.com:/proj', 'd.md', 'BASE64', 3);

    expect(result.method).toBe('collab.commit');
    expect(client.calls).toEqual([
      {
        method: 'collab.commit',
        params: {
          collab_root: 'alice.aid.com:/proj',
          doc: 'd.md',
          source: 'BASE64',
          onto: 3,
          message: '',
        },
      },
    ]);
  });

  it('所有方法只映射到服务端 collab.* RPC', async () => {
    const client = new FakeClient();
    const collab = new CollabClient(client);

    await collab.lsFiles('alice.aid.com:/proj');
    await collab.create('alice.aid.com:/proj', 'd.md', 'S');
    await collab.show('alice.aid.com:/proj', 'd.md');
    await collab.commit('alice.aid.com:/proj', 'd.md', 'S', 1);
    await collab.merge('alice.aid.com:/proj', 'd.md', 'S', 1);
    await collab.log('alice.aid.com:/proj', 'd.md');
    await collab.show('alice.aid.com:/proj', 'd.md', 1);
    await collab.diff('alice.aid.com:/proj', 'd.md', 1, 2);
    await collab.clone('alice.aid.com:/proj', 'alice.aid.com:/copy', false);
    await collab.clone('alice.aid.com:/proj', 'alice.aid.com:/new', true);
    await collab.prune('alice.aid.com:/proj', 'd.md');
    await collab.gc('alice.aid.com:/proj', false);
    await collab.reflog('alice.aid.com:/proj', 'd.md', 5);
    await collab.revert('alice.aid.com:/proj', 'd.md', 1, 'revert');
    await collab.lsRemote('g-team.aid.com');
    await collab.unregister('g-team.aid.com', 'g-team.aid.com:/proj');
    await collab.setAcl('alice.aid.com:/proj', 'bob1.aid.com', { perms: 'w', expiresAt: 123, maxUses: 2 });
    await collab.removeAcl('alice.aid.com:/proj', 'bob1.aid.com');
    await collab.tag.create('alice.aid.com:/proj', { message: 'm', major: true });
    await collab.tag.list('alice.aid.com:/proj');
    await collab.tag.show('alice.aid.com:/proj', '1.0.0');
    await collab.tag.diff('alice.aid.com:/proj', '1.0.0', '1.0.1');
    await collab.tag.restore('alice.aid.com:/proj', '1.0.0', { message: 'r' });
    await collab.tag.rm('alice.aid.com:/proj', '1.0.0');
    await collab.tag.prune('alice.aid.com:/proj', { before: 123, keep_last: 2 });

    expect(client.calls.map((c) => c.method)).toEqual([
      'collab.ls-files',
      'collab.create',
      'collab.show',
      'collab.commit',
      'collab.merge',
      'collab.log',
      'collab.show',
      'collab.diff',
      'collab.clone',
      'collab.clone',
      'collab.prune',
      'collab.gc',
      'collab.reflog',
      'collab.revert',
      'collab.ls-remote',
      'collab.unregister',
      'collab.set_acl',
      'collab.remove_acl',
      'collab.tag.create',
      'collab.tag.list',
      'collab.tag.show',
      'collab.tag.diff',
      'collab.tag.restore',
      'collab.tag.rm',
      'collab.tag.prune',
    ]);
    expect(client.calls.every((c) => c.method.startsWith('collab.'))).toBe(true);
    expect(client.calls.every((c) => !c.method.startsWith('storage.collab.'))).toBe(true);
    expect(client.calls.at(-1)?.params).toEqual({
      collab_root: 'alice.aid.com:/proj',
      before: 123,
      keep_last: 2,
    });
    expect(client.calls[8].params).toEqual({
      src: 'alice.aid.com:/proj',
      dest: 'alice.aid.com:/copy',
      reroot: false,
    });
    expect(client.calls[9].params).toEqual({
      src: 'alice.aid.com:/proj',
      dest: 'alice.aid.com:/new',
      reroot: true,
    });
    expect(client.calls[12].params).toEqual({
      collab_root: 'alice.aid.com:/proj',
      doc: 'd.md',
      limit: 5,
    });
    expect(client.calls[13].params).toEqual({
      collab_root: 'alice.aid.com:/proj',
      doc: 'd.md',
      rev: 1,
      message: 'revert',
    });
    expect(client.calls[16].params).toEqual({
      collab_root: 'alice.aid.com:/proj',
      grantee_aid: 'bob1.aid.com',
      perms: 'w',
      expires_at: 123,
      max_uses: 2,
    });
    expect(client.calls[17].params).toEqual({
      collab_root: 'alice.aid.com:/proj',
      grantee_aid: 'bob1.aid.com',
    });
  });

  it('AUNClient 暴露惰性 collab 入口', () => {
    const client = new AUNClient();

    expect(client.collab).toBeInstanceOf(CollabClient);
    expect(client.collab).toBe(client.collab);
  });

  it('冲突错误映射保留服务端 current_version/current_target/hint 字段', async () => {
    const client = new FakeClient();
    client.responses.set('collab.commit', new AUNError('提交失败', {
      code: -32009,
      data: {
        current_version: 4,
        current_target: 'alice.aid.com:/proj/v4',
        hint: 'merge first',
      },
    }));
    const collab = new CollabClient(client);

    await expect(collab.commit('alice.aid.com:/proj', 'd.md', 'S', 3)).rejects.toMatchObject({
      name: 'CollabConflictError',
      current_version: 4,
      current_target: 'alice.aid.com:/proj/v4',
      hint: 'merge first',
    });

    await expect(collab.commit('alice.aid.com:/proj', 'd.md', 'S', 3)).rejects.toBeInstanceOf(CollabConflictError);
  });

  it('TS collab SDK 不实现 diff3', () => {
    expect(CollabClient.prototype).not.toHaveProperty('diff3');
  });
});
