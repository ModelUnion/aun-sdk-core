import { describe, expect, it } from 'vitest';

import { AUNClient } from '../../src/client.js';
import { AUNError } from '../../src/errors.js';
import { CollabClient, CollabConflictError } from '../../src/collab/index.js';

class FakeClient {
  calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  responses: Record<string, unknown> = {};

  async call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    const actualParams = params ?? {};
    this.calls.push({ method, params: actualParams });
    const response = this.responses[method] ?? { ok: true, method };
    if (response instanceof Error) throw response;
    return response;
  }
}

describe('CollabClient Browser SDK 契约', () => {
  it('submit 调用裸 collab.submit RPC 并使用精确参数名', async () => {
    const client = new FakeClient();
    const collab = new CollabClient(client);

    const result = await collab.submit('alice.aid.com:/proj', 'd.md', 'BASE64', 3);

    expect(result).toMatchObject({ method: 'collab.submit' });
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

  it('所有方法与服务端 collab.* RPC 契约 1:1 对齐', async () => {
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

    expect(client.calls.map((call) => call.method)).toEqual([
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
    expect(client.calls.every((call) => call.method.startsWith('collab.'))).toBe(true);
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

  it('snapshot.prune 会剔除空值参数并支持 keepLast 别名', async () => {
    const client = new FakeClient();
    const collab = new CollabClient(client);

    await collab.snapshot.prune('alice.aid.com:/proj', { before: null, keepLast: 3 });

    expect(client.calls).toEqual([
      {
        method: 'collab.snapshot.prune',
        params: {
          collab_root: 'alice.aid.com:/proj',
          keep_last: 3,
        },
      },
    ]);
  });

  it('AUNClient 暴露惰性 collab 入口', () => {
    const client = new AUNClient();

    expect(client.collab).toBeInstanceOf(CollabClient);
    expect(client.collab).toBe(client.collab);
  });

  it('冲突错误映射保留 current_version/current_target/hint', async () => {
    const client = new FakeClient();
    client.responses['collab.submit'] = new AUNError('提交失败', {
      code: -32009,
      data: {
        current_version: 4,
        current_target: 'alice.aid.com:/proj/v4',
        hint: 'merge first',
      },
    });
    const collab = new CollabClient(client);

    await expect(collab.submit('alice.aid.com:/proj', 'd.md', 'S', 3))
      .rejects
      .toMatchObject({
        name: 'CollabConflictError',
        current_version: 4,
        current_target: 'alice.aid.com:/proj/v4',
        hint: 'merge first',
      });
  });

  it('collab 子模块不实现 diff3', async () => {
    const collabModules = import.meta.glob('../../src/collab/**/*.ts');
    expect(Object.keys(collabModules).some((path) => path.toLowerCase().includes('diff3'))).toBe(false);
  });
});
