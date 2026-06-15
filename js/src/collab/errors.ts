import { AUNError } from '../errors.js';
import { isJsonObject, type JsonValue } from '../types.js';

export class CollabError extends AUNError {
  constructor(message: string, opts: ConstructorParameters<typeof AUNError>[1] = {}) {
    super(message, opts);
    this.name = 'CollabError';
  }
}

export class CollabConflictError extends CollabError {
  readonly current_version: number | null;
  readonly current_target: string;
  readonly hint: string;

  constructor(
    message: string,
    opts: ConstructorParameters<typeof CollabError>[1] & {
      current_version?: number | null;
      current_target?: string;
      hint?: string;
    } = {},
  ) {
    super(message, { ...opts, code: opts.code ?? -32009 });
    this.name = 'CollabConflictError';
    this.current_version = opts.current_version ?? null;
    this.current_target = opts.current_target ?? '';
    this.hint = opts.hint ?? '';
  }
}

function errorMessage(exc: unknown): string {
  if (exc instanceof Error) return exc.message || exc.name;
  return String(exc || 'collab error');
}

function errorCode(exc: unknown): number | undefined {
  const code = (exc && typeof exc === 'object') ? (exc as { code?: unknown }).code : undefined;
  const parsed = Number(code);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function errorData(exc: unknown): JsonValue | null {
  const data = (exc && typeof exc === 'object') ? (exc as { data?: unknown }).data : undefined;
  return data === undefined ? null : data as JsonValue;
}

function errorTraceId(exc: unknown): string | undefined {
  const direct = (exc && typeof exc === 'object') ? (exc as { traceId?: unknown; trace_id?: unknown }) : {};
  const value = direct.traceId ?? direct.trace_id;
  return typeof value === 'string' ? value : undefined;
}

export function mapCollabError(exc: unknown): unknown {
  if (exc instanceof CollabError) return exc;
  const code = errorCode(exc);
  const data = errorData(exc);
  const message = errorMessage(exc);
  if (code === -32009) {
    const payload = isJsonObject(data) ? data : {};
    const currentVersion = Number(payload.current_version);
    return new CollabConflictError(message, {
      code: code ?? -32009,
      data,
      traceId: errorTraceId(exc),
      current_version: Number.isFinite(currentVersion) ? currentVersion : null,
      current_target: String(payload.current_target ?? ''),
      hint: String(payload.hint ?? ''),
    });
  }
  return exc;
}
