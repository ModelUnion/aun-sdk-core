import { describe, expect, it } from 'vitest';

import { StorageLowLevel, StorageVFS } from '../../src/storage/vfs.js';

class FakeClient {
  aid = 'member.agentid.pub';
  calls: Array<{ method: string; params: Record<string, unknown> }> = [];

  async call(method: string, params?: Record<string, unknown>): Promise<Record<string, unknown>> {
    this.calls.push({ method, params: params ?? {} });
    if (method === 'storage.fs.mount') {
      return {
        type: 'mount',
        path: params?.mount_path,
        owner_aid: params?.owner_aid,
        bucket: params?.bucket,
        source_aid: params?.source_aid,
        source_path: params?.source_path,
      };
    }
    if (method === 'storage.fs.approve') return { approved: true, path: params?.mount_path };
    if (method === 'storage.fs.reject') return { rejected: true, path: params?.mount_path };
    if (method === 'storage.fs.unmount') return { unmounted: true };
    return { ok: true };
  }
}

describe('P6 StorageVFS Browser SDK mount 契约', () => {
  it('mount 使用 storage.fs.mount 并把 aid:/path 解析为 RPC 参数', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    const node = await storage.mount(
      'alice.agentid.pub:/group-data/g',
      'group.agentid.pub:/memberdata/alice',
      { readonly: true, expiresAt: 123456, requireApproval: true },
    );
    const approved = await storage.approveMount('group.agentid.pub:/memberdata/alice', { requestId: 'req-1' });
    const rejected = await storage.rejectMount('group.agentid.pub:/memberdata/alice', { requestId: 'req-2' });

    expect(node.type).toBe('mount');
    expect(approved.approved).toBe(true);
    expect(rejected.rejected).toBe(true);
    expect(node.path).toBe('/memberdata/alice');
    expect(node.owner).toBe('group.agentid.pub');
    expect(node.mountSource).toBe('alice.agentid.pub:/group-data/g');
    expect(client.calls).toEqual([
      {
        method: 'storage.fs.mount',
        params: {
          owner_aid: 'group.agentid.pub',
          bucket: 'default',
          mount_path: 'memberdata/alice',
          source_aid: 'alice.agentid.pub',
          source_path: 'group-data/g',
          readonly: true,
          expires_at: 123456,
          require_approval: true,
        },
      },
      {
        method: 'storage.fs.approve',
        params: {
          owner_aid: 'group.agentid.pub',
          bucket: 'default',
          mount_path: 'memberdata/alice',
          request_id: 'req-1',
        },
      },
      {
        method: 'storage.fs.reject',
        params: {
          owner_aid: 'group.agentid.pub',
          bucket: 'default',
          mount_path: 'memberdata/alice',
          request_id: 'req-2',
        },
      },
    ]);
  });

  it('mountVolume 使用 volume_id 分支', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    const node = await storage.mountVolume('vol-1', 'alice.agentid.pub:/mnt/vol-1', { readonly: true });

    expect(node.type).toBe('mount');
    expect(client.calls).toEqual([
      {
        method: 'storage.fs.mount',
        params: {
          owner_aid: 'alice.agentid.pub',
          bucket: 'default',
          mount_path: 'mnt/vol-1',
          readonly: true,
          require_approval: false,
          volume_id: 'vol-1',
        },
      },
    ]);
  });

  it('mount/unmount 支持对象路径引用和 bucket 透传', async () => {
    const client = new FakeClient();
    const storage = new StorageVFS(client);

    await storage.mount(
      { owner: 'alice.agentid.pub', path: '/src' },
      { owner: 'group.agentid.pub', path: '/dst' },
      { bucket: 'team', sourceBucket: 'src-bucket', expires: 456 },
    );
    await storage.approveMount({ owner: 'group.agentid.pub', path: '/dst' }, { bucket: 'team', requestId: 'req-3' });
    await storage.rejectMount({ owner: 'group.agentid.pub', path: '/dst' }, { bucket: 'team', requestId: 'req-4' });
    const unmounted = await storage.unmount({ owner: 'group.agentid.pub', path: '/dst' }, { bucket: 'team' });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.fs.mount',
      'storage.fs.approve',
      'storage.fs.reject',
      'storage.fs.unmount',
    ]);
    expect(client.calls[0].params).toMatchObject({
      owner_aid: 'group.agentid.pub',
      bucket: 'team',
      mount_path: 'dst',
      source_aid: 'alice.agentid.pub',
      source_bucket: 'src-bucket',
      source_path: 'src',
      readonly: true,
      expires_at: 456,
    });
    expect(client.calls[1].params).toEqual({
      owner_aid: 'group.agentid.pub',
      bucket: 'team',
      mount_path: 'dst',
      request_id: 'req-3',
    });
    expect(client.calls[2].params).toEqual({
      owner_aid: 'group.agentid.pub',
      bucket: 'team',
      mount_path: 'dst',
      request_id: 'req-4',
    });
    expect(client.calls[3].params).toEqual({
      owner_aid: 'group.agentid.pub',
      bucket: 'team',
      mount_path: 'dst',
    });
    expect(unmounted).toEqual({
      unmounted: true,
      owner: 'group.agentid.pub',
      bucket: 'team',
      path: '/dst',
      mountPath: '/dst',
    });
  });
});

describe('P6 StorageLowLevel Browser SDK mount 契约', () => {
  it('fsMount/fsUnmount 调用真实 P6 RPC 名称', async () => {
    const client = new FakeClient();
    const low = new StorageLowLevel(client);

    await low.fsMount({
      owner: 'group.agentid.pub',
      bucket: 'team',
      mountPath: 'dst',
      sourceAid: 'alice.agentid.pub',
      sourcePath: 'src',
    });
    await low.fsApprove({ owner: 'group.agentid.pub', bucket: 'team', mountPath: 'dst' });
    await low.fsReject({ owner: 'group.agentid.pub', bucket: 'team', mountPath: 'dst' });
    await low.fsUnmount({ owner: 'group.agentid.pub', bucket: 'team', mountPath: 'dst' });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.fs.mount',
      'storage.fs.approve',
      'storage.fs.reject',
      'storage.fs.unmount',
    ]);
    expect(client.calls[0].params).toMatchObject({
      owner_aid: 'group.agentid.pub',
      bucket: 'team',
      mount_path: 'dst',
      source_aid: 'alice.agentid.pub',
      source_path: 'src',
      readonly: true,
    });
  });

  it('暴露 volume lifecycle 和 membership invalidate RPC 薄封装', async () => {
    const client = new FakeClient();
    const low = new StorageLowLevel(client);

    await low.volumeCreate({
      owner: 'alice.agentid.pub',
      bucket: 'team',
      volumeId: 'vol-1',
      sizeBytes: 4096,
      mountPoint: 'volumes/vol-1',
      expiresAt: 123,
    });
    await low.volumeRenew({
      owner: 'alice.agentid.pub',
      bucket: 'team',
      volumeId: 'vol-1',
      expiresAt: 999,
      status: 'active',
    });
    await low.volumeExpireDue({ owner: 'alice.agentid.pub', bucket: 'team', now: 1000 });
    await low.fsInvalidateMembership({
      groupId: 'g-team.agentid.pub',
      groupOwnerAid: 'owner.agentid.pub',
      memberAid: 'alice.agentid.pub',
      reason: 'left',
    });

    expect(client.calls).toEqual([
      {
        method: 'storage.volume.create',
        params: {
          owner_aid: 'alice.agentid.pub',
          bucket: 'team',
          volume_id: 'vol-1',
          size_bytes: 4096,
          mount_point: 'volumes/vol-1',
          expires_at: 123,
        },
      },
      {
        method: 'storage.volume.renew',
        params: {
          owner_aid: 'alice.agentid.pub',
          bucket: 'team',
          volume_id: 'vol-1',
          expires_at: 999,
          status: 'active',
        },
      },
      {
        method: 'storage.volume.expire_due',
        params: {
          owner_aid: 'alice.agentid.pub',
          bucket: 'team',
          now: 1000,
        },
      },
      {
        method: 'storage.fs.invalidate_membership',
        params: {
          group_id: 'g-team.agentid.pub',
          group_owner_aid: 'owner.agentid.pub',
          member_aid: 'alice.agentid.pub',
          reason: 'left',
        },
      },
    ]);
  });

  it('暴露分享、元数据、追加和目录树 RPC 薄封装', async () => {
    const client = new FakeClient();
    const low = new StorageLowLevel(client);

    await low.createShareLink({
      owner: 'alice.agentid.pub',
      bucket: 'team',
      objectKey: 'docs/a.txt',
      allowedAids: ['bob.agentid.pub'],
      expireInSeconds: 60,
      maxUses: 2,
    });
    await low.listShareLinks({ owner: 'alice.agentid.pub', bucket: 'team', objectKey: 'docs/a.txt' });
    await low.revokeShareLink({ shareId: 'share-1' });
    await low.getByShare({ shareId: 'share-1' });
    await low.setObjectMeta({
      owner: 'alice.agentid.pub',
      bucket: 'team',
      objectKey: 'docs/a.txt',
      metadata: { k: 'v' },
      contentType: 'text/plain',
      merge: false,
      expectedVersion: 3,
    });
    await low.appendObject({
      owner: 'alice.agentid.pub',
      bucket: 'team',
      objectKey: 'docs/a.txt',
      content: new TextEncoder().encode('tail'),
      contentType: 'text/plain',
      metadata: { part: 'tail' },
      expectedVersion: 4,
      isPublic: true,
    });
    await low.listChildren({
      owner: 'alice.agentid.pub',
      bucket: 'team',
      path: 'docs',
      nodeType: 'file',
      page: 2,
      size: 10,
      orderBy: 'name',
      order: 'asc',
      includeMetadata: true,
      includeUrls: false,
    });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.create_share_link',
      'storage.list_share_links',
      'storage.revoke_share_link',
      'storage.get_by_share',
      'storage.set_object_meta',
      'storage.append_object',
      'storage.list_children',
    ]);
    expect(client.calls[0].params).toMatchObject({
      owner_aid: 'alice.agentid.pub',
      bucket: 'team',
      object_key: 'docs/a.txt',
      allowed_aids: ['bob.agentid.pub'],
      expire_in_seconds: 60,
      max_uses: 2,
    });
    expect(client.calls[2].params).toEqual({ share_id: 'share-1' });
    expect(client.calls[5].params).toMatchObject({
      content: 'dGFpbA==',
      is_private: false,
      expected_version: 4,
    });
    expect(client.calls[6].params).toMatchObject({
      path: 'docs',
      type: 'file',
      page: 2,
      size: 10,
      include_metadata: true,
      include_urls: false,
    });
  });

  it('暴露 legacy tree RPC 薄封装', async () => {
    const client = new FakeClient();
    const low = new StorageLowLevel(client);

    await low.listObjects({ owner: 'alice.agentid.pub', prefix: 'docs', marker: 'm1' });
    await low.listPrefixes({ owner: 'alice.agentid.pub', prefix: 'docs', size: 20 });
    await low.deleteObject({ owner: 'alice.agentid.pub', objectKey: 'docs/a.txt' });
    await low.batchDelete({ owner: 'alice.agentid.pub', items: [{ object_key: 'docs/a.txt' }], recursive: true });
    await low.moveObject({
      owner: 'alice.agentid.pub',
      path: 'docs/a.txt',
      dstParentPath: 'archive',
      newName: 'a.txt',
      overwrite: true,
      expectedVersion: 5,
    });
    await low.copyObject({ owner: 'alice.agentid.pub', srcPath: 'archive/a.txt', dstPath: 'copy/a.txt' });
    await low.createFolder({ owner: 'alice.agentid.pub', path: 'docs', parents: true });
    await low.getFolder({ owner: 'alice.agentid.pub', path: 'docs' });
    await low.moveFolder({ owner: 'alice.agentid.pub', path: 'docs', dstParentPath: 'archive', newName: 'docs2' });
    await low.deleteFolder({ owner: 'alice.agentid.pub', path: 'archive/docs2', recursive: true });
    await low.resolvePath({ owner: 'alice.agentid.pub', path: 'link', expectedType: 'file', followSymlinks: false });

    expect(client.calls.map((c) => c.method)).toEqual([
      'storage.list_objects',
      'storage.list_prefixes',
      'storage.delete_object',
      'storage.batch_delete',
      'storage.move_object',
      'storage.copy_object',
      'storage.create_folder',
      'storage.get_folder',
      'storage.move_folder',
      'storage.delete_folder',
      'storage.resolve_path',
    ]);
    expect(client.calls[4].params).toMatchObject({
      path: 'docs/a.txt',
      dst_parent_path: 'archive',
      new_name: 'a.txt',
      conflict_policy: 'replace',
      expected_version: 5,
    });
    expect(client.calls[5].params).toMatchObject({ conflict_policy: 'reject' });
    expect(client.calls[6].params).toMatchObject({ path: 'docs', mkdirs: true });
    expect(client.calls[10].params).toMatchObject({
      path: 'link',
      expected_type: 'file',
      follow_symlinks: false,
    });
  });
});
