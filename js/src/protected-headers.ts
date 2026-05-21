import { E2EEError } from './errors.js';

const METADATA_AUTH_FIELD = '_auth';

export type ProtectedHeadersInput = ProtectedHeaders | Record<string, unknown> | null | undefined;

/** 端到端保护的信封元数据，语义接近 HTTP headers。 */
export class ProtectedHeaders {
  private _items: Record<string, string> = {};

  constructor(values?: Record<string, unknown> | null) {
    if (values) {
      for (const [key, value] of Object.entries(values)) {
        this.set(key, value);
      }
    }
  }

  private static normalizeKey(key: unknown): string {
    const value = String(key ?? '').trim().toLowerCase();
    if (!value || !/^[a-z0-9_-]+$/.test(value)) {
      throw new E2EEError('protected header key must match [a-z0-9_-]+');
    }
    if (value === METADATA_AUTH_FIELD) {
      throw new E2EEError('protected header key is reserved');
    }
    return value;
  }

  set(key: string, value: unknown): this {
    this._items[ProtectedHeaders.normalizeKey(key)] = value == null ? '' : String(value);
    return this;
  }

  get(key: string, defaultValue: string | null = null): string | null {
    const normalized = ProtectedHeaders.normalizeKey(key);
    return Object.prototype.hasOwnProperty.call(this._items, normalized)
      ? this._items[normalized]
      : defaultValue;
  }

  remove(key: string): this {
    delete this._items[ProtectedHeaders.normalizeKey(key)];
    return this;
  }

  toObject(): Record<string, string> {
    return { ...this._items };
  }

  toJSON(): Record<string, string> {
    return this.toObject();
  }

  static from(values?: Record<string, unknown> | null): ProtectedHeaders {
    return new ProtectedHeaders(values ?? {});
  }
}
