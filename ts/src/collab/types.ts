import type { JsonObject, JsonValue, RpcParams } from '../types.js';

export type CollabRaw = JsonObject;

export interface CollabRpcClient {
  call(method: string, params?: RpcParams): Promise<unknown>;
}

export interface CollabDocumentEntry extends JsonObject {
  collab_root?: string;
  doc?: string;
  anchor?: string;
  version?: number;
  author?: string;
  target?: string;
  current_target?: string;
  updated_at?: number;
}

export interface CollabDocumentResult extends JsonObject {
  ok?: boolean;
  collab_root?: string;
  doc?: string;
  anchor?: string;
  source?: string;
  content?: string;
  version?: number;
  author?: string;
  current_target?: string;
  conflicts?: boolean;
}

export interface CollabHistoryEntry extends JsonObject {
  version?: number;
  target?: string;
  author?: string;
  message?: string;
  time?: number;
}

export interface CollabDiffResult extends JsonObject {
  collab_root?: string;
  doc?: string;
  from?: number;
  to?: number;
  diff?: JsonValue;
}

export interface CollabRegistryEntry extends JsonObject {
  group_aid?: string;
  authority_aid?: string;
  collab_root?: string;
}

export interface CollabTagEntry extends JsonObject {
  doc?: string;
  anchor?: string;
  version?: number;
  author?: string;
  current_target?: string;
  target?: string;
}

export interface CollabTag extends JsonObject {
  collab_root?: string;
  version?: string;
  message?: string;
  created_at?: number;
  major?: boolean;
  bump?: string;
  changed?: string[];
  entries?: CollabTagEntry[];
}

export interface CollabTagDiffResult extends JsonObject {
  collab_root?: string;
  version_a?: string;
  version_b?: string;
  added?: string[];
  removed?: string[];
  changed?: string[];
}

export interface CollabTagPruneOptions {
  before?: number | string | null;
  keep_last?: number | null;
  keepLast?: number | null;
}

export interface CollabTagRestoreResult extends JsonObject {
  restored_from?: string;
  new_snapshot_version?: string;
  warnings?: string[];
  partial?: boolean;
  restored_docs?: string[];
}

export type CollabSnapshotEntry = CollabTagEntry;
export type CollabSnapshot = CollabTag;
export type CollabSnapshotDiffResult = CollabTagDiffResult;
export type CollabSnapshotPruneOptions = CollabTagPruneOptions;
export type CollabSnapshotRestoreResult = CollabTagRestoreResult;

export interface CollabGCResult extends JsonObject {
  scanned?: number;
  reachable?: number;
  garbage?: number;
  deleted?: number;
  freed_bytes?: number;
}

export interface CollabReflogEntry extends JsonObject {
  seq?: number;
  action?: string;
  requester?: string;
  doc?: string;
  version?: number;
  base_version?: number;
  target?: string;
  status?: string;
  error_code?: number;
  error_msg?: string;
  metadata?: JsonObject;
  timestamp?: number;
}
