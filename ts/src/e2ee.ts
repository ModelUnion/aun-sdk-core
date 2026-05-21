/**
 * E2EE V2-only 兼容入口。
 *
 * 旧版 manager 已移除；这里仅保留应用层可能直接使用的
 * protected headers helper。
 */

export { ProtectedHeaders } from './protected-headers.js';
export type { ProtectedHeadersInput } from './protected-headers.js';
