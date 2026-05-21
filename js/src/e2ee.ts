/**
 * E2EE V2-only 兼容入口。
 *
 * 旧版 P2P E2EEManager 已移除；这里仅保留应用层可能直接使用的
 * protected headers helper，和 TS SDK 的 V2-only 入口保持一致。
 */

export { ProtectedHeaders } from './protected-headers.js';
export type { ProtectedHeadersInput } from './protected-headers.js';
