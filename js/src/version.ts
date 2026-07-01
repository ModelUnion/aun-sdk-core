// AUN SDK 版本号（单一事实来源）。
// 所有引用点（index.ts / auth.ts / v2/e2ee/encrypt-p2p.ts）统一从此导入，
// 避免多处独立定义导致版本号不一致。
export const VERSION = '0.5.1';
