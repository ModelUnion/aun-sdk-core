export class StorageError extends Error {
  code: number | string;
  path: string;
  data: unknown;

  constructor(message: string, code: number | string = 'ESTORAGE', path = '', data: unknown = undefined) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.path = path;
    this.data = data;
  }
}

export class StorageNotFoundError extends StorageError {}
export class StorageExistsError extends StorageError {}
export class StorageAccessDeniedError extends StorageError {}
export class StorageConflictError extends StorageError {}
export class StorageQuotaError extends StorageError {}
export class StorageSessionExpiredError extends StorageError {}
export class StorageLoopError extends StorageError {}
export class StorageDanglingSymlinkError extends StorageError {}
export class StorageNotADirectoryError extends StorageError {}
export class StorageIsADirectoryError extends StorageError {}

export function mapStorageError(exc: unknown, path = ''): StorageError {
  if (exc instanceof StorageError) return exc;
  const record = (exc && typeof exc === 'object') ? exc as Record<string, unknown> : {};
  const code = record.code as number | string | undefined;
  const data = record.data;
  const message = exc instanceof Error ? exc.message : String(exc || 'storage error');
  const lowered = message.toLowerCase();

  if (code === -32008 || code === 404 || code === 4040) return new StorageNotFoundError(message, 'ENOENT', path, data);
  if (code === -32009 || lowered.includes('version conflict')) return new StorageConflictError(message, 'ECONFLICT', path, data);
  if (code === -32004 || code === 403 || code === 4030) return new StorageAccessDeniedError(message, 'EACCES', path, data);
  if (code === -32031 || lowered.includes('eloop') || message.includes('循环')) return new StorageLoopError(message, 'ELOOP', path, data);
  if (code === -32032 || lowered.includes('dangling') || message.includes('软链目标不存在')) return new StorageDanglingSymlinkError(message, 'EDANGLING', path, data);
  if (code === -32010 || code === -32011 || code === -32013 || (lowered.includes('session') && lowered.includes('expired'))) return new StorageSessionExpiredError(message, 'ESESSIONEXPIRED', path, data);
  if (lowered.includes('quota') || message.includes('配额')) return new StorageQuotaError(message, 'EQUOTA', path, data);
  if (lowered.includes('already exists') || message.includes('已存在')) return new StorageExistsError(message, 'EEXIST', path, data);
  if (lowered.includes('not a directory') || message.includes('不是目录')) return new StorageNotADirectoryError(message, 'ENOTDIR', path, data);
  if (lowered.includes('is a directory') || message.includes('是目录')) return new StorageIsADirectoryError(message, 'EISDIR', path, data);
  if (code === -32602 && (message.includes('不存在') || lowered.includes('not found') || lowered.includes('no such'))) return new StorageNotFoundError(message, 'ENOENT', path, data);
  return new StorageError(message, code ?? 'ESTORAGE', path, data);
}
