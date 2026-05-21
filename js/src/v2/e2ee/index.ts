/**
 * AUN E2EE V2: e2ee 模块统一导出
 */
export * from './types';
export { encryptP2PMessage } from './encrypt-p2p';
export { encryptGroupMessage } from './encrypt-group';
export { decryptMessage } from './decrypt';
export {
  withMetadataAuth,
  METADATA_KEY_DOMAIN,
  PROTECTED_HEADERS_DOMAIN,
  PROTECTED_CONTEXT_DOMAIN,
} from './metadata-auth';
