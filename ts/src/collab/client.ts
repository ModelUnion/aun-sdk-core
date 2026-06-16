import type { RpcParams } from '../types.js';
import { mapCollabError } from './errors.js';
import type {
  CollabDiffResult,
  CollabDocumentEntry,
  CollabDocumentResult,
  CollabGCResult,
  CollabHistoryEntry,
  CollabRaw,
  CollabReflogEntry,
  CollabRegistryEntry,
  CollabRpcClient,
  CollabSnapshot,
  CollabSnapshotDiffResult,
  CollabSnapshotPruneOptions,
  CollabSnapshotRestoreResult,
} from './types.js';

function stripNil(params: RpcParams): RpcParams {
  const out: RpcParams = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out;
}

export class CollabSnapshotClient {
  private readonly parent: CollabClient;

  constructor(parent: CollabClient) {
    this.parent = parent;
  }

  create(collabRoot: string, options: { message?: string; major?: boolean } = {}): Promise<CollabRaw> {
    return this.parent._call('collab.snapshot.create', {
      collab_root: collabRoot,
      message: options.message ?? '',
      major: options.major ?? false,
    });
  }

  list(collabRoot: string): Promise<CollabSnapshot[]> {
    return this.parent._call('collab.snapshot.list', { collab_root: collabRoot });
  }

  show(collabRoot: string, version: string): Promise<CollabSnapshot> {
    return this.parent._call('collab.snapshot.show', { collab_root: collabRoot, version });
  }

  diff(collabRoot: string, versionA: string, versionB: string): Promise<CollabSnapshotDiffResult> {
    return this.parent._call('collab.snapshot.diff', {
      collab_root: collabRoot,
      version_a: versionA,
      version_b: versionB,
    });
  }

  restore(collabRoot: string, version: string, options: { message?: string } = {}): Promise<CollabSnapshotRestoreResult> {
    return this.parent._call('collab.snapshot.restore', {
      collab_root: collabRoot,
      version,
      message: options.message ?? '',
    });
  }

  rm(collabRoot: string, version: string): Promise<CollabRaw> {
    return this.parent._call('collab.snapshot.rm', { collab_root: collabRoot, version });
  }

  prune(collabRoot: string, options: CollabSnapshotPruneOptions = {}): Promise<CollabRaw> {
    return this.parent._call('collab.snapshot.prune', stripNil({
      collab_root: collabRoot,
      before: options.before,
      keep_last: options.keep_last ?? options.keepLast,
    }));
  }
}

export class CollabClient {
  readonly snapshot: CollabSnapshotClient;
  private readonly client: CollabRpcClient;

  constructor(client: CollabRpcClient) {
    this.client = client;
    this.snapshot = new CollabSnapshotClient(this);
  }

  async _call<T = unknown>(method: string, params: RpcParams = {}): Promise<T> {
    try {
      return await this.client.call(method, params) as T;
    } catch (exc) {
      const mapped = mapCollabError(exc);
      throw mapped === exc ? exc : mapped;
    }
  }

  ls(collabRoot: string): Promise<CollabDocumentEntry[]> {
    return this._call('collab.ls', { collab_root: collabRoot });
  }

  create(collabRoot: string, doc: string, source: string): Promise<CollabDocumentResult> {
    return this._call('collab.create', { collab_root: collabRoot, doc, source });
  }

  read(collabRoot: string, doc: string): Promise<CollabDocumentResult> {
    return this._call('collab.read', { collab_root: collabRoot, doc });
  }

  submit(collabRoot: string, doc: string, source: string, baseVersion: number, message = ''): Promise<CollabDocumentResult> {
    return this._call('collab.submit', {
      collab_root: collabRoot,
      doc,
      source,
      base_version: baseVersion,
      message,
    });
  }

  merge(collabRoot: string, doc: string, source: string, baseVersion: number): Promise<CollabDocumentResult> {
    return this._call('collab.merge', { collab_root: collabRoot, doc, source, base_version: baseVersion });
  }

  history(collabRoot: string, doc: string): Promise<CollabHistoryEntry[]> {
    return this._call('collab.history', { collab_root: collabRoot, doc });
  }

  get(collabRoot: string, doc: string, version: number): Promise<CollabDocumentResult> {
    return this._call('collab.get', { collab_root: collabRoot, doc, version });
  }

  diff(collabRoot: string, doc: string, fromVersion: number, toVersion: number): Promise<CollabDiffResult> {
    return this._call('collab.diff', { collab_root: collabRoot, doc, from: fromVersion, to: toVersion });
  }

  export(collabRoot: string, dest: string): Promise<CollabRaw> {
    return this._call('collab.export', { collab_root: collabRoot, dest });
  }

  adopt(src: string, newRoot: string): Promise<CollabRaw> {
    return this._call('collab.adopt', { src, new_root: newRoot });
  }

  prune(collabRoot: string, doc: string): Promise<CollabRaw> {
    return this._call('collab.prune', { collab_root: collabRoot, doc });
  }

  gc(collabRoot: string, dryRun = true): Promise<CollabGCResult> {
    return this._call('collab.gc', { collab_root: collabRoot, dry_run: dryRun });
  }

  reflog(collabRoot: string, doc?: string, limit = 100): Promise<CollabReflogEntry[]> {
    const params: RpcParams = { collab_root: collabRoot, limit };
    if (doc) params.doc = doc;
    return this._call('collab.reflog', params);
  }

  reset(collabRoot: string, doc: string, version: number, message = ''): Promise<CollabDocumentResult> {
    return this._call('collab.reset', { collab_root: collabRoot, doc, version, message });
  }

  discover(groupAid: string): Promise<CollabRegistryEntry[]> {
    return this._call('collab.discover', { group_aid: groupAid });
  }

  unregister(groupAid: string, collabRoot: string): Promise<CollabRaw> {
    return this._call('collab.unregister', { group_aid: groupAid, collab_root: collabRoot });
  }
}
