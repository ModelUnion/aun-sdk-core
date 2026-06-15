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
  it('submit 调用裸 collab.submit 并透传精确参数', async () => {
    const client = new FakeClient();
    const collab = new CollabClient(client);

    const result = await collab.submit('alice.aid.com:/proj', 'd.md', 'BASE64', 3);

    expect(result.method).toBe('collab.submit');
    expect(client.calls).toEqual([
      {
        method: 'collab.submit',
        params: {
          collab_root: 'alice.aid.com:/proj',
          doc: 'd.md',
          source: 'BASE64',
          base_version: 3,
        },
      },
    ]);
  });

  it('所有方法只映射到服务端 collab.* RPC', async () => {
    const client = new FakeClient();
    const collab = new CollabClient(client);

    await collab.ls('alice.aid.com:/proj');
    await collab.create('alice.aid.com:/proj', 'd.md', 'S');
    await collab.read('alice.aid.com:/proj', 'd.md');
    await collab.submit('alice.aid.com:/proj', 'd.md', 'S', 1);
    await collab.merge('alice.aid.com:/proj', 'd.md', 'S', 1);
    await collab.history('alice.aid.com:/proj', 'd.md');
    await collab.get('alice.aid.com:/proj', 'd.md', 1);
    await collab.diff('alice.aid.com:/proj', 'd.md', 1, 2);
    await collab.export('alice.aid.com:/proj', 'alice.aid.com:/copy');
    await collab.adopt('alice.aid.com:/proj', 'alice.aid.com:/new');
    await collab.prune('alice.aid.com:/proj', 'd.md');
    await collab.discover('g-team.aid.com');
    await collab.unregister('g-team.aid.com', 'g-team.aid.com:/proj');
    await collab.snapshot.create('alice.aid.com:/proj', { message: 'm', major: true });
    await collab.snapshot.list('alice.aid.com:/proj');
    await collab.snapshot.show('alice.aid.com:/proj', '1.0.0');
    await collab.snapshot.diff('alice.aid.com:/proj', '1.0.0', '1.0.1');
    await collab.snapshot.restore('alice.aid.com:/proj', '1.0.0', { message: 'r' });
    await collab.snapshot.rm('alice.aid.com:/proj', '1.0.0');
    await collab.snapshot.prune('alice.aid.com:/proj', { before: 123, keep_last: 2 });

    expect(client.calls.map((c) => c.method)).toEqual([
      'collab.ls',
      'collab.create',
      'collab.read',
      'collab.submit',
      'collab.merge',
      'collab.history',
      'collab.get',
      'collab.diff',
      'collab.export',
      'collab.adopt',
      'collab.prune',
      'collab.discover',
      'collab.unregister',
      'collab.snapshot.create',
      'collab.snapshot.list',
      'collab.snapshot.show',
      'collab.snapshot.diff',
      'collab.snapshot.restore',
      'collab.snapshot.rm',
      'collab.snapshot.prune',
    ]);
    expect(client.calls.every((c) => c.method.startsWith('collab.'))).toBe(true);
    expect(client.calls.every((c) => !c.method.startsWith('storage.collab.'))).toBe(true);
    expect(client.calls.at(-1)?.params).toEqual({
      collab_root: 'alice.aid.com:/proj',
      before: 123,
      keep_last: 2,
    });
    expect(client.calls[9].params).toEqual({
      src: 'alice.aid.com:/proj',
      new_root: 'alice.aid.com:/new',
    });
  });

  it('AUNClient 暴露惰性 collab 入口', () => {
    const client = new AUNClient();

    expect(client.collab).toBeInstanceOf(CollabClient);
    expect(client.collab).toBe(client.collab);
  });

  it('冲突错误映射保留服务端 current_version/current_target/hint 字段', async () => {
    const client = new FakeClient();
    client.responses.set('collab.submit', new AUNError('提交失败', {
      code: -32009,
      data: {
        current_version: 4,
        current_target: 'alice.aid.com:/proj/v4',
        hint: 'merge first',
      },
    }));
    const collab = new CollabClient(client);

    await expect(collab.submit('alice.aid.com:/proj', 'd.md', 'S', 3)).rejects.toMatchObject({
      name: 'CollabConflictError',
      current_version: 4,
      current_target: 'alice.aid.com:/proj/v4',
      hint: 'merge first',
    });

    await expect(collab.submit('alice.aid.com:/proj', 'd.md', 'S', 3)).rejects.toBeInstanceOf(CollabConflictError);
  });

  it('TS collab SDK 不实现 diff3', () => {
    expect(CollabClient.prototype).not.toHaveProperty('diff3');
  });
});
