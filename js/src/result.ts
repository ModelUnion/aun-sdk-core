// ── Result 类型（统一结果字典）──────────────────────────────

/** 错误信息 */
export interface ErrorInfo {
  code: string;
  message: string;
  cause?: unknown;
}

/** 统一结果类型：成功时 ok=true + data，失败时 ok=false + error */
export type Result<T> =
  | { ok: true; data: T }
  | { ok: false; error: ErrorInfo };

/** 构造成功结果 */
export function resultOk<T>(data: T): Result<T> {
  return { ok: true, data };
}

/** 构造失败结果 */
export function resultErr(code: string, message: string, cause?: unknown): Result<never> {
  return { ok: false, error: { code, message, ...(cause !== undefined ? { cause } : {}) } };
}
