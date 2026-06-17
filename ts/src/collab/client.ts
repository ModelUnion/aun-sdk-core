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
  CollabTag,
  CollabTagDiffResult,
  CollabTagPruneOptions,
  CollabTagRestoreResult,
} from './types.js';

function stripNil(params: RpcParams): RpcParams {
  const out: RpcParams = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) out[key] = value;
  }
  return out;
}

export class CollabTagClient {
  private readonly parent: CollabClient;

  constructor(parent: CollabClient) {
    this.parent = parent;
  }

  create(collabRoot: string, options: { message?: string; major?: boolean } = {}): Promise<CollabRaw> {
    return this.parent._call('collab.tag.create', {
      collab_root: collabRoot,
      message: options.message ?? '',
      major: options.major ?? false,
    });
  }

  list(collabRoot: string): Promise<CollabTag[]> {
    return this.parent._call('collab.tag.list', { collab_root: collabRoot });
  }

  show(collabRoot: string, version: string): Promise<CollabTag> {
    return this.parent._call('collab.tag.show', { collab_root: collabRoot, version });
  }

  diff(collabRoot: string, versionA: string, versionB: string): Promise<CollabTagDiffResult> {
    return this.parent._call('collab.tag.diff', {
      collab_root: collabRoot,
      version_a: versionA,
      version_b: versionB,
    });
  }

  restore(collabRoot: string, version: string, options: { message?: string } = {}): Promise<CollabTagRestoreResult> {
    return this.parent._call('collab.tag.restore', {
      collab_root: collabRoot,
      version,
      message: options.message ?? '',
    });
  }

  rm(collabRoot: string, version: string): Promise<CollabRaw> {
    return this.parent._call('collab.tag.rm', { collab_root: collabRoot, version });
  }

  prune(collabRoot: string, options: CollabTagPruneOptions = {}): Promise<CollabRaw> {
    return this.parent._call('collab.tag.prune', stripNil({
      collab_root: collabRoot,
      before: options.before,
      keep_last: options.keep_last ?? options.keepLast,
    }));
  }
}

export class CollabClient {
  readonly tag: CollabTagClient;
  private readonly client: CollabRpcClient;

  constructor(client: CollabRpcClient) {
    this.client = client;
    this.tag = new CollabTagClient(this);
  }

  async _call<T = unknown>(method: string, params: RpcParams = {}): Promise<T> {
    try {
      return await this.client.call(method, params) as T;
    } catch (exc) {
      const mapped = mapCollabError(exc);
      throw mapped === exc ? exc : mapped;
    }
  }

  lsFiles(collabRoot: string): Promise<CollabDocumentEntry[]> {
    return this._call('collab.ls-files', { collab_root: collabRoot });
  }

  create(collabRoot: string, doc: string, source: string): Promise<CollabDocumentResult> {
    return this._call('collab.create', { collab_root: collabRoot, doc, source });
  }

  show(collabRoot: string, doc: string, rev?: number): Promise<CollabDocumentResult> {
    const params: RpcParams = { collab_root: collabRoot, doc };
    if (rev !== undefined) params.rev = rev;
    return this._call('collab.show', params);
  }

  commit(collabRoot: string, doc: string, source: string, onto: number, message = ''): Promise<CollabDocumentResult> {
    return this._call('collab.commit', {
      collab_root: collabRoot,
      doc,
      source,
      onto,
      message,
    });
  }

  merge(collabRoot: string, doc: string, source: string, onto: number): Promise<CollabDocumentResult> {
    return this._call('collab.merge', { collab_root: collabRoot, doc, source, onto });
  }

  log(collabRoot: string, doc: string): Promise<CollabHistoryEntry[]> {
    return this._call('collab.log', { collab_root: collabRoot, doc });
  }

  diff(collabRoot: string, doc: string, fromVersion: number, toVersion: number): Promise<CollabDiffResult> {
    return this._call('collab.diff', { collab_root: collabRoot, doc, from: fromVersion, to: toVersion });
  }

  clone(src: string, dest: string, reroot = false): Promise<CollabRaw> {
    return this._call('collab.clone', { src, dest, reroot });
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

  revert(collabRoot: string, doc: string, rev: number, message = ''): Promise<CollabDocumentResult> {
    return this._call('collab.revert', { collab_root: collabRoot, doc, rev, message });
  }

  lsRemote(groupAid: string): Promise<CollabRegistryEntry[]> {
    return this._call('collab.ls-remote', { group_aid: groupAid });
  }

  unregister(groupAid: string, collabRoot: string): Promise<CollabRaw> {
    return this._call('collab.unregister', { group_aid: groupAid, collab_root: collabRoot });
  }
}
