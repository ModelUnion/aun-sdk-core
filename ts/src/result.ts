/**
 * 统一结果类型 — 对齐 Python SDK result.py
 */

export interface ErrorInfo {
  code: string;
  message: string;
  cause?: unknown;
}

export type Result<T> =
  | { ok: true; data: T }
  | { ok: false; error: ErrorInfo };

export function resultOk<T>(data: T): Result<T> {
  return { ok: true, data };
}

export function resultErr(code: string, message: string, cause?: unknown): Result<never> {
  return { ok: false, error: { code, message, cause } };
}
