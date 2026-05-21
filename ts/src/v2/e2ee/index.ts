/**
 * AUN E2EE V2: 加解密引擎导出。
 */
export { encryptP2PMessage } from './encrypt-p2p.js';
export { encryptGroupMessage } from './encrypt-group.js';
export { decryptMessage } from './decrypt.js';
export { withMetadataAuth, PROTECTED_HEADERS_DOMAIN, PROTECTED_CONTEXT_DOMAIN, METADATA_KEY_DOMAIN } from './metadata-auth.js';
export type { Sender, Target, TargetSet, EncryptOptions, StateCommitmentAAD } from './types.js';
export { SUITE_NAME } from './types.js';
