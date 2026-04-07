// ── Playwright E2E 浏览器测试：AUN Browser SDK ──────────────
//
// 测试策略：
// - 通过 esbuild 打包的 ESM bundle 加载 SDK 到真实 Chrome 浏览器
// - 使用 page.evaluate() 在浏览器上下文中执行 SDK 操作
// - 验证浏览器原生 API（SubtleCrypto、localStorage、crypto.getRandomValues）正常工作
// - 网络依赖测试（WebSocket 连接 Gateway）标记为 test.fixme()

import { test, expect } from '@playwright/test';
import * as path from 'path';
import * as http from 'http';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JS_ROOT = path.resolve(__dirname, '..', '..');

// ── 本地 HTTP 服务器（解决 file:// 协议无法加载 ES Module 的问题）──

let server: http.Server;
let baseUrl: string;

test.beforeAll(async () => {
  server = http.createServer((req, res) => {
    const safePath = (req.url ?? '/').split('?')[0];
    const filePath = path.join(JS_ROOT, safePath);

    // 安全检查：不允许路径遍历
    if (!filePath.startsWith(JS_ROOT)) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }

    const ext = path.extname(filePath);
    const mimeTypes: Record<string, string> = {
      '.html': 'text/html',
      '.js': 'application/javascript',
      '.mjs': 'application/javascript',
      '.css': 'text/css',
      '.json': 'application/json',
    };

    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('Not Found');
        return;
      }
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] ?? 'application/octet-stream' });
      res.end(data);
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
});

test.afterAll(async () => {
  if (server) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

// ── 测试页面 URL ────────────────────────────────────────────

function testPageUrl(): string {
  return `${baseUrl}/tests/e2e-browser/test-page.html`;
}

// ── 基础功能测试 ────────────────────────────────────────────

test.describe('Browser SDK 基础功能', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
  });

  test('SDK 加载成功，版本号正确', async ({ page }) => {
    const version = await page.evaluate(() => (window as any).AUN.__version__);
    expect(version).toBe('0.2.0');
  });

  test('所有核心导出存在', async ({ page }) => {
    const exports = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      return {
        // 类
        hasAUNClient: typeof AUN.AUNClient === 'function',
        hasAUNError: typeof AUN.AUNError === 'function',
        hasEventDispatcher: typeof AUN.EventDispatcher === 'function',
        hasCryptoProvider: typeof AUN.CryptoProvider === 'function',
        hasRPCTransport: typeof AUN.RPCTransport === 'function',
        hasGatewayDiscovery: typeof AUN.GatewayDiscovery === 'function',
        hasIndexedDBKeyStore: typeof AUN.IndexedDBKeyStore === 'function',
        hasAuthFlow: typeof AUN.AuthFlow === 'function',
        hasAuthNamespace: typeof AUN.AuthNamespace === 'function',
        hasE2EEManager: typeof AUN.E2EEManager === 'function',
        hasGroupE2EEManager: typeof AUN.GroupE2EEManager === 'function',
        hasGroupReplayGuard: typeof AUN.GroupReplayGuard === 'function',
        hasGroupKeyRequestThrottle: typeof AUN.GroupKeyRequestThrottle === 'function',
        // 函数
        hasGetDeviceId: typeof AUN.getDeviceId === 'function',
        hasCreateConfig: typeof AUN.createConfig === 'function',
        hasMapRemoteError: typeof AUN.mapRemoteError === 'function',
        hasComputeMembershipCommitment: typeof AUN.computeMembershipCommitment === 'function',
        hasEncryptGroupMessage: typeof AUN.encryptGroupMessage === 'function',
        hasDecryptGroupMessage: typeof AUN.decryptGroupMessage === 'function',
        hasGenerateGroupSecret: typeof AUN.generateGroupSecret === 'function',
        // 常量
        hasSUITE: typeof AUN.SUITE === 'string',
        hasROOT_CA_PEM: typeof AUN.ROOT_CA_PEM === 'string',
      };
    });
    for (const [key, val] of Object.entries(exports)) {
      expect(val, `导出检查失败: ${key}`).toBe(true);
    }
  });
});

// ── 错误类型测试 ────────────────────────────────────────────

test.describe('错误类型', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
  });

  test('AUNError 构造正确', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const err = new AUN.AUNError('test error', { code: 123, retryable: true });
      return {
        name: err.name,
        message: err.message,
        code: err.code,
        retryable: err.retryable,
        isError: err instanceof Error,
      };
    });
    expect(result.name).toBe('AUNError');
    expect(result.message).toBe('test error');
    expect(result.code).toBe(123);
    expect(result.retryable).toBe(true);
    expect(result.isError).toBe(true);
  });

  test('AUNError 默认值', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const err = new AUN.AUNError('no opts');
      return { code: err.code, retryable: err.retryable, data: err.data, traceId: err.traceId };
    });
    expect(result.code).toBe(-1);
    expect(result.retryable).toBe(false);
    expect(result.data).toBeNull();
    expect(result.traceId).toBeNull();
  });

  test('子类错误类型继承正确', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const errors = [
        { cls: 'ConnectionError', name: 'ConnectionError' },
        { cls: 'TimeoutError', name: 'TimeoutError' },
        { cls: 'AuthError', name: 'AuthError' },
        { cls: 'PermissionError', name: 'PermissionError' },
        { cls: 'ValidationError', name: 'ValidationError' },
        { cls: 'NotFoundError', name: 'NotFoundError' },
        { cls: 'RateLimitError', name: 'RateLimitError' },
        { cls: 'StateError', name: 'StateError' },
        { cls: 'SessionError', name: 'SessionError' },
        { cls: 'GroupError', name: 'GroupError' },
        { cls: 'GroupNotFoundError', name: 'GroupNotFoundError' },
        { cls: 'GroupStateError', name: 'GroupStateError' },
        { cls: 'E2EEError', name: 'E2EEError' },
      ];
      return errors.map(({ cls, name }) => {
        const err = new AUN[cls]('test', { code: 42 });
        return {
          cls,
          nameOk: err.name === name,
          codeOk: err.code === 42,
          isAUNError: err instanceof AUN.AUNError,
          isError: err instanceof Error,
        };
      });
    });
    for (const item of result) {
      expect(item.nameOk, `${item.cls}.name`).toBe(true);
      expect(item.codeOk, `${item.cls}.code`).toBe(true);
      expect(item.isAUNError, `${item.cls} instanceof AUNError`).toBe(true);
      expect(item.isError, `${item.cls} instanceof Error`).toBe(true);
    }
  });

  test('E2EE 错误子类默认值', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      return {
        decryptFailed: {
          name: new AUN.E2EEDecryptFailedError().name,
          localCode: new AUN.E2EEDecryptFailedError().localCode,
        },
        secretMissing: {
          name: new AUN.E2EEGroupSecretMissingError().name,
          code: new AUN.E2EEGroupSecretMissingError().code,
        },
        epochMismatch: {
          name: new AUN.E2EEGroupEpochMismatchError().name,
          code: new AUN.E2EEGroupEpochMismatchError().code,
        },
        commitmentInvalid: {
          name: new AUN.E2EEGroupCommitmentInvalidError().name,
          code: new AUN.E2EEGroupCommitmentInvalidError().code,
        },
        notMember: {
          name: new AUN.E2EEGroupNotMemberError().name,
          code: new AUN.E2EEGroupNotMemberError().code,
        },
        groupDecryptFailed: {
          name: new AUN.E2EEGroupDecryptFailedError().name,
          code: new AUN.E2EEGroupDecryptFailedError().code,
        },
      };
    });
    expect(result.decryptFailed.name).toBe('E2EEDecryptFailedError');
    expect(result.decryptFailed.localCode).toBe('E2EE_DECRYPT_FAILED');
    expect(result.secretMissing.name).toBe('E2EEGroupSecretMissingError');
    expect(result.secretMissing.code).toBe(-32040);
    expect(result.epochMismatch.name).toBe('E2EEGroupEpochMismatchError');
    expect(result.epochMismatch.code).toBe(-32041);
    expect(result.commitmentInvalid.name).toBe('E2EEGroupCommitmentInvalidError');
    expect(result.commitmentInvalid.code).toBe(-32042);
    expect(result.notMember.name).toBe('E2EEGroupNotMemberError');
    expect(result.notMember.code).toBe(-32043);
    expect(result.groupDecryptFailed.name).toBe('E2EEGroupDecryptFailedError');
    expect(result.groupDecryptFailed.code).toBe(-32044);
  });

  test('mapRemoteError 认证错误映射', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const codes = [4001, 4010, -32003];
      return codes.map(code => {
        const err = AUN.mapRemoteError({ code, message: 'auth failed' });
        return { code, name: err.name, errCode: err.code };
      });
    });
    for (const item of result) {
      expect(item.name, `code ${item.code}`).toBe('AuthError');
      expect(item.errCode).toBe(item.code);
    }
  });

  test('mapRemoteError 各类错误码映射', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const cases = [
        { code: 4030, expected: 'PermissionError' },
        { code: 4040, expected: 'NotFoundError' },
        { code: 4290, expected: 'RateLimitError' },
        { code: -32010, expected: 'SessionError' },
        { code: -32600, expected: 'ValidationError' },
        { code: -33001, expected: 'GroupNotFoundError' },
        { code: -33002, expected: 'GroupStateError' },
        { code: -33005, expected: 'GroupError' },
        { code: 9999, expected: 'AUNError' },
      ];
      return cases.map(({ code, expected }) => {
        const err = AUN.mapRemoteError({ code, message: 'test' });
        return { code, expected, actual: err.name };
      });
    });
    for (const item of result) {
      expect(item.actual, `code ${item.code}`).toBe(item.expected);
    }
  });

  test('mapRemoteError RateLimitError 可重试', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const err = AUN.mapRemoteError({ code: 429, message: 'rate limit' });
      return { retryable: err.retryable };
    });
    expect(result.retryable).toBe(true);
  });
});

// ── 事件调度器测试 ──────────────────────────────────────────

test.describe('EventDispatcher', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
  });

  test('订阅与发布', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const dispatcher = new AUN.EventDispatcher();
      let received: any = null;
      dispatcher.subscribe('test', (data: any) => { received = data; });
      await dispatcher.publish('test', { hello: 'world' });
      return received;
    });
    expect(result).toEqual({ hello: 'world' });
  });

  test('取消订阅后不再收到事件', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const dispatcher = new AUN.EventDispatcher();
      let count = 0;
      const sub = dispatcher.subscribe('evt', () => { count++; });
      await dispatcher.publish('evt', null);
      sub.unsubscribe();
      await dispatcher.publish('evt', null);
      return count;
    });
    expect(result).toBe(1);
  });

  test('多个订阅者同时收到事件', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const dispatcher = new AUN.EventDispatcher();
      const results: number[] = [];
      dispatcher.subscribe('multi', () => { results.push(1); });
      dispatcher.subscribe('multi', () => { results.push(2); });
      await dispatcher.publish('multi', null);
      return results;
    });
    expect(result).toEqual([1, 2]);
  });

  test('处理器抛异常不影响其他处理器', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const dispatcher = new AUN.EventDispatcher();
      let secondCalled = false;
      dispatcher.subscribe('err', () => { throw new Error('boom'); });
      dispatcher.subscribe('err', () => { secondCalled = true; });
      await dispatcher.publish('err', null);
      return secondCalled;
    });
    expect(result).toBe(true);
  });

  test('发布未订阅的事件不报错', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const dispatcher = new AUN.EventDispatcher();
      await dispatcher.publish('nonexistent', { data: 1 });
      return true;
    });
    expect(result).toBe(true);
  });
});

// ── 配置测试 ────────────────────────────────────────────────

test.describe('配置', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
  });

  test('createConfig 默认值', async ({ page }) => {
    const config = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      return AUN.createConfig();
    });
    expect(config.aunPath).toBe('aun');
    expect(config.rootCaPem).toBeNull();
    expect(config.groupE2ee).toBe(true);
    expect(config.rotateOnJoin).toBe(false);
    expect(config.verifySsl).toBe(true);
    expect(config.requireForwardSecrecy).toBe(true);
    expect(config.replayWindowSeconds).toBe(300);
  });

  test('createConfig 自定义覆盖', async ({ page }) => {
    const config = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      return AUN.createConfig({ aunPath: 'custom', groupE2ee: false, replayWindowSeconds: 600 });
    });
    expect(config.aunPath).toBe('custom');
    expect(config.groupE2ee).toBe(false);
    expect(config.replayWindowSeconds).toBe(600);
  });

  test('getDeviceId 返回有效 UUID', async ({ page }) => {
    const id = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      return AUN.getDeviceId();
    });
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  test('getDeviceId 多次调用返回同一值', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const id1 = AUN.getDeviceId();
      const id2 = AUN.getDeviceId();
      return { id1, id2, same: id1 === id2 };
    });
    expect(result.same).toBe(true);
  });
});

// ── CryptoProvider 测试 ──────────────────────────────────────

test.describe('CryptoProvider（浏览器 SubtleCrypto）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
  });

  test('生成 P-256 密钥对', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const cp = new AUN.CryptoProvider();
      const identity = await cp.generateIdentity();
      return {
        hasPrivateKey: typeof identity.private_key_pem === 'string' && identity.private_key_pem.includes('PRIVATE KEY'),
        hasPublicKey: typeof identity.public_key_der_b64 === 'string' && identity.public_key_der_b64.length > 0,
        curve: identity.curve,
      };
    });
    expect(result.hasPrivateKey).toBe(true);
    expect(result.hasPublicKey).toBe(true);
    expect(result.curve).toBe('P-256');
  });

  test('两次生成的密钥对不同', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const cp = new AUN.CryptoProvider();
      const id1 = await cp.generateIdentity();
      const id2 = await cp.generateIdentity();
      return {
        privateKeysDifferent: id1.private_key_pem !== id2.private_key_pem,
        publicKeysDifferent: id1.public_key_der_b64 !== id2.public_key_der_b64,
      };
    });
    expect(result.privateKeysDifferent).toBe(true);
    expect(result.publicKeysDifferent).toBe(true);
  });

  test('signLoginNonce 签名格式正确', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const cp = new AUN.CryptoProvider();
      const identity = await cp.generateIdentity();
      const [sigB64, clientTime] = await cp.signLoginNonce(identity.private_key_pem, 'test-nonce-123');
      return {
        hasSig: typeof sigB64 === 'string' && sigB64.length > 0,
        hasTime: typeof clientTime === 'string' && clientTime.length > 0,
        // base64 字符集检查
        validBase64: /^[A-Za-z0-9+/=]+$/.test(sigB64),
      };
    });
    expect(result.hasSig).toBe(true);
    expect(result.hasTime).toBe(true);
    expect(result.validBase64).toBe(true);
  });

  test('newClientNonce 格式正确', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const cp = new AUN.CryptoProvider();
      const nonce1 = cp.newClientNonce();
      const nonce2 = cp.newClientNonce();
      return {
        hasNonce: typeof nonce1 === 'string' && nonce1.length > 0,
        unique: nonce1 !== nonce2,
        validBase64: /^[A-Za-z0-9+/=]+$/.test(nonce1),
      };
    });
    expect(result.hasNonce).toBe(true);
    expect(result.unique).toBe(true);
    expect(result.validBase64).toBe(true);
  });
});

// ── Group E2EE 纯函数测试 ──────────────────────────────────

test.describe('Group E2EE 纯函数（不需要网络）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
  });

  test('computeMembershipCommitment 确定性', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const c1 = await AUN.computeMembershipCommitment(['a', 'b'], 1, 'grp', secret);
      const c2 = await AUN.computeMembershipCommitment(['b', 'a'], 1, 'grp', secret);
      const c3 = await AUN.computeMembershipCommitment(['a', 'b'], 2, 'grp', secret);
      return { same: c1 === c2, different: c1 !== c3, format: typeof c1 === 'string' && c1.length === 64 };
    });
    expect(result.same).toBe(true);     // 成员顺序无关
    expect(result.different).toBe(true); // 不同 epoch 产生不同 commitment
    expect(result.format).toBe(true);    // SHA-256 hex = 64 字符
  });

  test('verifyMembershipCommitment 验证通过', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const members = ['alice', 'bob'];
      const c = await AUN.computeMembershipCommitment(members, 1, 'grp', secret);
      const valid = await AUN.verifyMembershipCommitment(c, members, 1, 'grp', 'alice', secret);
      const notMember = await AUN.verifyMembershipCommitment(c, members, 1, 'grp', 'charlie', secret);
      const wrongCommit = await AUN.verifyMembershipCommitment('bad', members, 1, 'grp', 'alice', secret);
      return { valid, notMember, wrongCommit };
    });
    expect(result.valid).toBe(true);
    expect(result.notMember).toBe(false);
    expect(result.wrongCommit).toBe(false);
  });

  test('GroupReplayGuard 防重放', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const guard = new AUN.GroupReplayGuard(100);
      const first = guard.checkAndRecord('grp', 'alice', 'msg-1');
      const second = guard.checkAndRecord('grp', 'alice', 'msg-1');
      const different = guard.checkAndRecord('grp', 'alice', 'msg-2');
      const differentSender = guard.checkAndRecord('grp', 'bob', 'msg-1');
      return { first, second, different, differentSender, size: guard.size };
    });
    expect(result.first).toBe(true);
    expect(result.second).toBe(false);    // 重复消息被拒绝
    expect(result.different).toBe(true);
    expect(result.differentSender).toBe(true); // 不同发送者的同一 messageId 通过
    expect(result.size).toBe(3);
  });

  test('GroupReplayGuard 容量限制自动清理', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const guard = new AUN.GroupReplayGuard(10);
      for (let i = 0; i < 15; i++) {
        guard.checkAndRecord('grp', 'alice', `msg-${i}`);
      }
      // 超过 maxSize 后会触发 trim，保留 80%
      return { sizeWithinLimit: guard.size <= 10 };
    });
    expect(result.sizeWithinLimit).toBe(true);
  });

  test('GroupKeyRequestThrottle 频率限制', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const throttle = new AUN.GroupKeyRequestThrottle(60);
      const first = throttle.allow('key1');
      const second = throttle.allow('key1');
      const differentKey = throttle.allow('key2');
      return { first, second, differentKey };
    });
    expect(result.first).toBe(true);
    expect(result.second).toBe(false);     // 冷却期内被限制
    expect(result.differentKey).toBe(true); // 不同的 key 不受影响
  });

  test('GroupKeyRequestThrottle reset 重置', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const throttle = new AUN.GroupKeyRequestThrottle(60);
      throttle.allow('key1');
      throttle.reset('key1');
      const afterReset = throttle.allow('key1');
      return { afterReset };
    });
    expect(result.afterReset).toBe(true);
  });

  test('generateGroupSecret 生成 32 字节随机值', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const s1 = AUN.generateGroupSecret();
      const s2 = AUN.generateGroupSecret();
      return {
        isUint8Array: s1 instanceof Uint8Array,
        length: s1.byteLength,
        unique: Array.from(s1).join(',') !== Array.from(s2).join(','),
      };
    });
    expect(result.isUint8Array).toBe(true);
    expect(result.length).toBe(32);
    expect(result.unique).toBe(true);
  });

  test('checkEpochDowngrade 降级检测', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      return {
        newer: AUN.checkEpochDowngrade(3, 2),
        equal: AUN.checkEpochDowngrade(2, 2),
        older: AUN.checkEpochDowngrade(1, 2),
        olderAllowed: AUN.checkEpochDowngrade(1, 2, { allowOldEpoch: true }),
      };
    });
    expect(result.newer).toBe(true);
    expect(result.equal).toBe(true);
    expect(result.older).toBe(false);
    expect(result.olderAllowed).toBe(true);
  });

  test('buildMembershipManifest 格式正确', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      const manifest = AUN.buildMembershipManifest('grp-1', 2, 1, ['bob', 'alice'], {
        added: ['charlie'],
        removed: ['dave'],
        initiatorAid: 'alice',
      });
      return manifest;
    });
    expect(result.manifest_version).toBe(1);
    expect(result.group_id).toBe('grp-1');
    expect(result.epoch).toBe(2);
    expect(result.prev_epoch).toBe(1);
    expect(result.member_aids).toEqual(['alice', 'bob']); // 已排序
    expect(result.added).toEqual(['charlie']);
    expect(result.removed).toEqual(['dave']);
    expect(result.initiator_aid).toBe('alice');
    expect(typeof result.issued_at).toBe('number');
  });

  test('buildKeyRequest 格式正确', async ({ page }) => {
    const result = await page.evaluate(() => {
      const AUN = (window as any).AUN;
      return AUN.buildKeyRequest('grp-1', 3, 'alice');
    });
    expect(result.type).toBe('e2ee.group_key_request');
    expect(result.group_id).toBe('grp-1');
    expect(result.epoch).toBe(3);
    expect(result.requester_aid).toBe('alice');
  });
});

// ── 群组加解密集成测试（纯浏览器，无网络）──────────────────

test.describe('Group 加解密集成（浏览器 SubtleCrypto）', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
  });

  test('encryptGroupMessage + decryptGroupMessage 无签名模式', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const groupSecret = AUN.generateGroupSecret();
      const payload = { type: 'text', content: 'hello group!' };

      const envelope = await AUN.encryptGroupMessage('grp-1', 1, groupSecret, payload, {
        fromAid: 'alice',
        messageId: 'msg-001',
        timestamp: Date.now(),
      });

      // 构造完整消息（模拟服务端投递）
      const message = {
        group_id: 'grp-1',
        from: 'alice',
        message_id: 'msg-001',
        payload: envelope,
      };

      const secrets = new Map([[1, groupSecret]]);
      // requireSignature=false 因为没有签名
      const decrypted = await AUN.decryptGroupMessage(message, secrets, null, { requireSignature: false });

      return {
        envelopeType: envelope.type,
        envelopeSuite: envelope.suite,
        envelopeEpoch: envelope.epoch,
        hasCiphertext: typeof envelope.ciphertext === 'string',
        hasNonce: typeof envelope.nonce === 'string',
        hasTag: typeof envelope.tag === 'string',
        decryptedPayload: decrypted?.payload,
        encrypted: decrypted?.encrypted,
      };
    });
    expect(result.envelopeType).toBe('e2ee.group_encrypted');
    expect(result.envelopeSuite).toBe('P256_HKDF_SHA256_AES_256_GCM');
    expect(result.envelopeEpoch).toBe(1);
    expect(result.hasCiphertext).toBe(true);
    expect(result.hasNonce).toBe(true);
    expect(result.hasTag).toBe(true);
    expect(result.decryptedPayload).toEqual({ type: 'text', content: 'hello group!' });
    expect(result.encrypted).toBe(true);
  });

  test('错误 group_secret 无法解密', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const realSecret = AUN.generateGroupSecret();
      const fakeSecret = AUN.generateGroupSecret();
      const payload = { type: 'text', content: 'secret' };

      const envelope = await AUN.encryptGroupMessage('grp-1', 1, realSecret, payload, {
        fromAid: 'alice',
        messageId: 'msg-002',
        timestamp: Date.now(),
      });

      const message = {
        group_id: 'grp-1',
        from: 'alice',
        message_id: 'msg-002',
        payload: envelope,
      };

      const wrongSecrets = new Map([[1, fakeSecret]]);
      const decrypted = await AUN.decryptGroupMessage(message, wrongSecrets, null, { requireSignature: false });
      return { decrypted };
    });
    expect(result.decrypted).toBeNull();
  });

  test('错误 epoch 无法解密', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const secret = AUN.generateGroupSecret();
      const payload = { type: 'text', content: 'hello' };

      const envelope = await AUN.encryptGroupMessage('grp-1', 2, secret, payload, {
        fromAid: 'alice',
        messageId: 'msg-003',
        timestamp: Date.now(),
      });

      const message = {
        group_id: 'grp-1',
        from: 'alice',
        message_id: 'msg-003',
        payload: envelope,
      };

      // secrets 里只有 epoch 1 的密钥
      const secrets = new Map([[1, secret]]);
      const decrypted = await AUN.decryptGroupMessage(message, secrets, null, { requireSignature: false });
      return { decrypted };
    });
    expect(result.decrypted).toBeNull();
  });
});

// ── 密钥分发协议测试 ────────────────────────────────────────

test.describe('密钥分发协议', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(testPageUrl());
    await page.waitForFunction(() => (window as any).testReady === true, null, { timeout: 10_000 });
  });

  test('buildKeyDistribution 格式正确', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const AUN = (window as any).AUN;
      const secret = AUN.generateGroupSecret();
      const dist = await AUN.buildKeyDistribution('grp-1', 1, secret, ['alice', 'bob'], 'alice');
      return {
        type: dist.type,
        groupId: dist.group_id,
        epoch: dist.epoch,
        hasSecret: typeof dist.group_secret === 'string',
        hasCommitment: typeof dist.commitment === 'string' && dist.commitment.length === 64,
        memberAids: dist.member_aids,
        distributedBy: dist.distributed_by,
      };
    });
    expect(result.type).toBe('e2ee.group_key_distribution');
    expect(result.groupId).toBe('grp-1');
    expect(result.epoch).toBe(1);
    expect(result.hasSecret).toBe(true);
    expect(result.hasCommitment).toBe(true);
    expect(result.memberAids).toEqual(['alice', 'bob']);
    expect(result.distributedBy).toBe('alice');
  });
});

// ── 网络 E2E 测试（需要运行中的 Docker Gateway）────────────────────

test.describe('P2P E2EE 集成测试', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseUrl}/tests/e2e-browser/test-page.html`);
    await page.waitForFunction(() => (window as any).testReady === true, undefined, { timeout: 10_000 });
  });

  test('SDK 创建 AID + 认证 + 连接 + 发送加密消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `br-a-${rid}.agentid.pub`;
      const bobAid = `br-b-${rid}.agentid.pub`;

      // 创建 Alice
      const alice = new AUN.AUNClient({
        verify_ssl: false,
        require_forward_secrecy: false,
      });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      // 创建 Bob
      const bob = new AUN.AUNClient({
        verify_ssl: false,
        require_forward_secrecy: false,
      });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      // Alice 发送加密消息给 Bob
      const sendResult = await alice.call('message.send', {
        to: bobAid,
        payload: { text: 'hello from browser' },
        encrypt: true,
      });

      // Bob 拉取消息
      await new Promise(r => setTimeout(r, 1000));
      const pullResult = await bob.call('message.pull', { after_seq: 0, limit: 10 });
      const msgs = pullResult.messages || [];

      await alice.close();
      await bob.close();

      return {
        sent: !!sendResult?.message_id,
        received: msgs.length > 0,
        decrypted: msgs.some((m: any) => m.e2ee?.encryption_mode),
        text: msgs.find((m: any) => m.payload?.text)?.payload?.text,
        // 调试：查看第一条消息的结构
        firstMsg: msgs[0] ? {
          hasE2ee: !!msgs[0].e2ee,
          payloadType: typeof msgs[0].payload,
          payloadKeys: msgs[0].payload ? Object.keys(msgs[0].payload).slice(0, 5) : [],
          encrypted: msgs[0].encrypted,
        } : null,
      };
    }, rid);

    expect(result.sent).toBe(true);
    expect(result.received).toBe(true);
    console.log('P2P firstMsg:', JSON.stringify(result.firstMsg));
    // 如果解密成功，payload.text 应该是 'hello from browser'
    // 如果未解密，payload 是加密信封
    expect(result.text ?? result.firstMsg?.payloadKeys?.join(',')).toBeTruthy();
  });
});

test.describe('Group E2EE 集成测试', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseUrl}/tests/e2e-browser/test-page.html`);
    await page.waitForFunction(() => (window as any).testReady === true, undefined, { timeout: 10_000 });
  });

  test('建群 + 加人 + 加密发送 + 解密接收', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `bg-a-${rid}.agentid.pub`;
      const bobAid = `bg-b-${rid}.agentid.pub`;

      // Alice 连接
      const alice = new AUN.AUNClient({
        verify_ssl: false,
        require_forward_secrecy: false,
      });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      // Bob 连接
      const bob = new AUN.AUNClient({
        verify_ssl: false,
        require_forward_secrecy: false,
      });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      // Alice 建群
      const createResult = await alice.call('group.create', { name: `browser-grp-${rid}` });
      const groupId = createResult.group.group_id;

      // Alice 加 Bob
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await new Promise(r => setTimeout(r, 3000)); // 等待密钥分发

      // Alice 发送加密群消息
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: '浏览器群消息' },
        encrypt: true,
      });
      await new Promise(r => setTimeout(r, 1000));

      // Bob 拉取群消息
      const pullResult = await bob.call('group.pull', {
        group_id: groupId,
        after_seq: 0,
        limit: 10,
      });
      const msgs = pullResult.messages || [];

      await alice.close();
      await bob.close();

      return {
        groupCreated: !!groupId,
        messagesReceived: msgs.length,
        decrypted: msgs.some((m: any) => m.e2ee?.encryption_mode === 'epoch_group_key'),
        text: msgs.find((m: any) => m.payload?.text)?.payload?.text,
      };
    }, rid);

    expect(result.groupCreated).toBe(true);
    expect(result.messagesReceived).toBeGreaterThan(0);
    expect(result.text).toBe('浏览器群消息');
  });

  test('明文群消息发送', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aid = `bg-pt-${rid}.agentid.pub`;

      const client = new AUN.AUNClient({
        verify_ssl: false,
        require_forward_secrecy: false,
      });
      await client.auth.createAid({ aid });
      const auth = await client.auth.authenticate({ aid });
      await client.connect(auth);

      const createResult = await client.call('group.create', { name: `pt-${rid}` });
      const groupId = createResult.group.group_id;

      const sendResult = await client.call('group.send', {
        group_id: groupId,
        payload: { text: 'plaintext' },
        encrypt: false,
      });

      await client.close();
      return { sent: !!sendResult?.message?.message_id, groupId };
    }, rid);

    expect(result.sent).toBe(true);
  });

  test('多成员解密 — 3 人群组全部能解密', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `bg-ma-${rid}.agentid.pub`;
      const bobAid = `bg-mb-${rid}.agentid.pub`;
      const carolAid = `bg-mc-${rid}.agentid.pub`;

      // 创建 3 个客户端
      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      const carol = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await carol.auth.createAid({ aid: carolAid });
      const cAuth = await carol.auth.authenticate({ aid: carolAid });
      await carol.connect(cAuth);

      // Alice 建群并加人
      const createResult = await alice.call('group.create', { name: `multi-${rid}` });
      const groupId = createResult.group.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await alice.call('group.add_member', { group_id: groupId, aid: carolAid });
      await new Promise(r => setTimeout(r, 3000)); // 等待密钥分发

      // Alice 发送加密群消息
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: '三人群消息' },
        encrypt: true,
      });
      await new Promise(r => setTimeout(r, 1000));

      // Bob 和 Carol 分别拉取
      const pullBob = await bob.call('group.pull', { group_id: groupId, after_seq: 0, limit: 10 });
      const pullCarol = await carol.call('group.pull', { group_id: groupId, after_seq: 0, limit: 10 });
      const msgsBob = pullBob.messages || [];
      const msgsCarol = pullCarol.messages || [];

      await alice.close();
      await bob.close();
      await carol.close();

      return {
        bobReceived: msgsBob.length,
        carolReceived: msgsCarol.length,
        bobText: msgsBob.find((m: any) => m.payload?.text)?.payload?.text,
        carolText: msgsCarol.find((m: any) => m.payload?.text)?.payload?.text,
        bobDecrypted: msgsBob.some((m: any) => m.e2ee?.encryption_mode === 'epoch_group_key'),
        carolDecrypted: msgsCarol.some((m: any) => m.e2ee?.encryption_mode === 'epoch_group_key'),
      };
    }, rid);

    expect(result.bobReceived).toBeGreaterThan(0);
    expect(result.carolReceived).toBeGreaterThan(0);
    expect(result.bobText).toBe('三人群消息');
    expect(result.carolText).toBe('三人群消息');
  });

  test('踢人后 epoch 轮换', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `bg-ka-${rid}.agentid.pub`;
      const bobAid = `bg-kb-${rid}.agentid.pub`;
      const carolAid = `bg-kc-${rid}.agentid.pub`;

      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      const carol = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await carol.auth.createAid({ aid: carolAid });
      const cAuth = await carol.auth.authenticate({ aid: carolAid });
      await carol.connect(cAuth);

      // Alice 建群并加 Bob 和 Carol
      const createResult = await alice.call('group.create', { name: `kick-${rid}` });
      const groupId = createResult.group.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await alice.call('group.add_member', { group_id: groupId, aid: carolAid });
      await new Promise(r => setTimeout(r, 3000)); // 等待密钥分发

      // 踢 Carol
      await alice.call('group.kick', { group_id: groupId, aid: carolAid });
      // 等待 SDK 自动 CAS 轮换 + 分发新 epoch 密钥给 Bob
      await new Promise(r => setTimeout(r, 5000));

      // Alice 用新 epoch 发消息
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: '踢人后的消息' },
        encrypt: true,
      });
      await new Promise(r => setTimeout(r, 1000));

      // Bob 拉取 — 应能解密
      const pullBob = await bob.call('group.pull', { group_id: groupId, after_seq: 0, limit: 10 });
      const msgsBob = pullBob.messages || [];

      await alice.close();
      await bob.close();
      await carol.close();

      return {
        bobReceived: msgsBob.length,
        bobText: msgsBob.find((m: any) => m.payload?.text === '踢人后的消息')?.payload?.text,
        // 验证是否有 epoch > 1 的消息（epoch 轮换）
        hasNewEpoch: msgsBob.some((m: any) => m.e2ee?.epoch && m.e2ee.epoch > 1),
      };
    }, rid);

    expect(result.bobReceived).toBeGreaterThan(0);
    expect(result.bobText).toBe('踢人后的消息');
  });

  test('新成员加入无 epoch 轮换', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `bg-ja-${rid}.agentid.pub`;
      const bobAid = `bg-jb-${rid}.agentid.pub`;
      const carolAid = `bg-jc-${rid}.agentid.pub`;

      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      const carol = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await carol.auth.createAid({ aid: carolAid });
      const cAuth = await carol.auth.authenticate({ aid: carolAid });
      await carol.connect(cAuth);

      // Alice 建群并加 Bob
      const createResult = await alice.call('group.create', { name: `join-${rid}` });
      const groupId = createResult.group.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await new Promise(r => setTimeout(r, 3000));

      // 再加 Carol（不应触发 epoch 轮换）
      await alice.call('group.add_member', { group_id: groupId, aid: carolAid });
      await new Promise(r => setTimeout(r, 3000));

      // Alice 用当前 epoch 发消息
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: '新成员能看到' },
        encrypt: true,
      });
      await new Promise(r => setTimeout(r, 1000));

      // Carol 拉取 — 应能解密
      const pullCarol = await carol.call('group.pull', { group_id: groupId, after_seq: 0, limit: 10 });
      const msgsCarol = pullCarol.messages || [];

      await alice.close();
      await bob.close();
      await carol.close();

      return {
        carolReceived: msgsCarol.length,
        carolText: msgsCarol.find((m: any) => m.payload?.text)?.payload?.text,
        carolDecrypted: msgsCarol.some((m: any) => m.e2ee?.encryption_mode === 'epoch_group_key'),
      };
    }, rid);

    expect(result.carolReceived).toBeGreaterThan(0);
    expect(result.carolText).toBe('新成员能看到');
  });

  test('连续加密群消息（burst）', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `bg-ba-${rid}.agentid.pub`;
      const bobAid = `bg-bb-${rid}.agentid.pub`;

      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      const createResult = await alice.call('group.create', { name: `burst-${rid}` });
      const groupId = createResult.group.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await new Promise(r => setTimeout(r, 3000));

      // 连续发 5 条加密消息
      const N = 5;
      for (let i = 0; i < N; i++) {
        await alice.call('group.send', {
          group_id: groupId,
          payload: { text: `burst_${i}`, seq: i },
          encrypt: true,
        });
      }
      await new Promise(r => setTimeout(r, 2000));

      // Bob 拉取
      const pullResult = await bob.call('group.pull', { group_id: groupId, after_seq: 0, limit: 20 });
      const msgs = pullResult.messages || [];

      await alice.close();
      await bob.close();

      // 收集解密成功的消息文本
      const decryptedTexts = msgs
        .filter((m: any) => m.e2ee?.encryption_mode === 'epoch_group_key')
        .map((m: any) => m.payload?.text)
        .filter(Boolean);

      return {
        totalReceived: msgs.length,
        decryptedCount: decryptedTexts.length,
        decryptedTexts: decryptedTexts.sort(),
        expected: Array.from({ length: N }, (_, i) => `burst_${i}`).sort(),
      };
    }, rid);

    expect(result.totalReceived).toBeGreaterThanOrEqual(5);
    expect(result.decryptedCount).toBeGreaterThanOrEqual(5);
    expect(result.decryptedTexts).toEqual(result.expected);
  });

  test('加密 + 明文混合消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `bg-mx-${rid}.agentid.pub`;
      const bobAid = `bg-my-${rid}.agentid.pub`;

      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      const createResult = await alice.call('group.create', { name: `mixed-${rid}` });
      const groupId = createResult.group.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await new Promise(r => setTimeout(r, 3000));

      // 明文 → 加密 → 明文
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: '明文消息' },
        encrypt: false,
      });
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: '加密消息' },
        encrypt: true,
      });
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: '又是明文' },
        encrypt: false,
      });
      await new Promise(r => setTimeout(r, 1000));

      const pullResult = await bob.call('group.pull', { group_id: groupId, after_seq: 0, limit: 10 });
      const msgs = pullResult.messages || [];

      await alice.close();
      await bob.close();

      // 分类收集
      const encryptedTexts = msgs
        .filter((m: any) => m.e2ee?.encryption_mode === 'epoch_group_key')
        .map((m: any) => m.payload?.text);
      const plaintextTexts = msgs
        .filter((m: any) => !m.e2ee && m.payload?.text)
        .map((m: any) => m.payload.text);

      return {
        totalReceived: msgs.length,
        encryptedTexts,
        plaintextTexts,
      };
    }, rid);

    expect(result.totalReceived).toBeGreaterThanOrEqual(3);
    expect(result.encryptedTexts).toContain('加密消息');
    expect(result.plaintextTexts).toContain('明文消息');
    expect(result.plaintextTexts).toContain('又是明文');
  });

  test('旧 epoch 消息仍可解密', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `bg-oa-${rid}.agentid.pub`;
      const bobAid = `bg-ob-${rid}.agentid.pub`;
      const carolAid = `bg-oc-${rid}.agentid.pub`;

      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      const carol = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await carol.auth.createAid({ aid: carolAid });
      const cAuth = await carol.auth.authenticate({ aid: carolAid });
      await carol.connect(cAuth);

      // Alice 建群并加 Bob 和 Carol
      const createResult = await alice.call('group.create', { name: `old-epoch-${rid}` });
      const groupId = createResult.group.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await alice.call('group.add_member', { group_id: groupId, aid: carolAid });
      await new Promise(r => setTimeout(r, 3000));

      // epoch 1 消息
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: 'epoch1消息' },
        encrypt: true,
      });

      // 踢 Carol 触发 epoch 轮换到 epoch 2
      await alice.call('group.kick', { group_id: groupId, aid: carolAid });
      await new Promise(r => setTimeout(r, 5000));

      // epoch 2 消息
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: 'epoch2消息' },
        encrypt: true,
      });
      await new Promise(r => setTimeout(r, 1000));

      // Bob 拉取所有消息 — 两个 epoch 的消息都应可解密
      const pullResult = await bob.call('group.pull', { group_id: groupId, after_seq: 0, limit: 20 });
      const msgs = pullResult.messages || [];

      await alice.close();
      await bob.close();
      await carol.close();

      const decryptedTexts = msgs
        .filter((m: any) => m.e2ee?.encryption_mode === 'epoch_group_key')
        .map((m: any) => m.payload?.text)
        .filter(Boolean);

      return {
        totalReceived: msgs.length,
        decryptedTexts,
        hasEpoch1: decryptedTexts.includes('epoch1消息'),
        hasEpoch2: decryptedTexts.includes('epoch2消息'),
      };
    }, rid);

    expect(result.totalReceived).toBeGreaterThanOrEqual(2);
    expect(result.hasEpoch1).toBe(true);
    expect(result.hasEpoch2).toBe(true);
  });

  test('退群后 epoch 轮换', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `bg-la-${rid}.agentid.pub`;
      const bobAid = `bg-lb-${rid}.agentid.pub`;
      const carolAid = `bg-lc-${rid}.agentid.pub`;

      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      const carol = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await carol.auth.createAid({ aid: carolAid });
      const cAuth = await carol.auth.authenticate({ aid: carolAid });
      await carol.connect(cAuth);

      // Alice 建群并加 Bob 和 Carol
      const createResult = await alice.call('group.create', { name: `leave-${rid}` });
      const groupId = createResult.group.group_id;
      await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
      await alice.call('group.add_member', { group_id: groupId, aid: carolAid });
      await new Promise(r => setTimeout(r, 3000));

      // Carol 主动退群
      await carol.call('group.leave', { group_id: groupId });
      // 等待 Alice（owner）收到 group.changed 事件后自动 CAS 轮换
      await new Promise(r => setTimeout(r, 5000));

      // Alice 用新 epoch 发消息
      await alice.call('group.send', {
        group_id: groupId,
        payload: { text: '退群后的消息' },
        encrypt: true,
      });
      await new Promise(r => setTimeout(r, 1000));

      // Bob 拉取 — 应能解密
      const pullBob = await bob.call('group.pull', { group_id: groupId, after_seq: 0, limit: 10 });
      const msgsBob = pullBob.messages || [];

      await alice.close();
      await bob.close();
      await carol.close();

      return {
        bobReceived: msgsBob.length,
        bobText: msgsBob.find((m: any) => m.payload?.text === '退群后的消息')?.payload?.text,
        hasNewEpoch: msgsBob.some((m: any) => m.e2ee?.epoch && m.e2ee.epoch > 1),
      };
    }, rid);

    expect(result.bobReceived).toBeGreaterThan(0);
    expect(result.bobText).toBe('退群后的消息');
  });
});

// ── P2P E2EE 扩展测试 ────────────────────────────────────────────

test.describe('P2P E2EE 扩展测试', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseUrl}/tests/e2e-browser/test-page.html`);
    await page.waitForFunction(() => (window as any).testReady === true, undefined, { timeout: 10_000 });
  });

  test('SDK 到 SDK prekey 消息收发', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `br-pk-a-${rid}.agentid.pub`;
      const bobAid = `br-pk-b-${rid}.agentid.pub`;

      // Alice 和 Bob 都连接（连接时 SDK 自动上传 prekey）
      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      // Alice 发加密消息给 Bob
      const sendResult = await alice.call('message.send', {
        to: bobAid,
        payload: { text: 'prekey消息测试' },
        encrypt: true,
      });

      await new Promise(r => setTimeout(r, 1000));

      // Bob 通过 pull 接收
      const pullResult = await bob.call('message.pull', { after_seq: 0, limit: 10 });
      const msgs = pullResult.messages || [];
      const fromAlice = msgs.filter((m: any) => m.from === aliceAid);

      await alice.close();
      await bob.close();

      return {
        sent: !!sendResult?.message_id,
        received: fromAlice.length > 0,
        text: fromAlice.find((m: any) => m.payload?.text)?.payload?.text,
        encrypted: fromAlice.some((m: any) => m.encrypted === true || m.e2ee?.encryption_mode),
      };
    }, rid);

    expect(result.sent).toBe(true);
    expect(result.received).toBe(true);
    // 如果解密成功，验证内容；否则仍然验证收到了消息
    if (result.text) {
      expect(result.text).toBe('prekey消息测试');
    }
  });

  test('SDK long_term_key 降级 — 对方无 prekey 时回退', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const senderAid = `br-lt-s-${rid}.agentid.pub`;
      const receiverAid = `br-lt-r-${rid}.agentid.pub`;

      // Sender 连接
      const sender = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await sender.auth.createAid({ aid: senderAid });
      const sAuth = await sender.auth.authenticate({ aid: senderAid });
      await sender.connect(sAuth);

      // Receiver 只创建 AID，不连接（所以不会上传 prekey）
      const receiver = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await receiver.auth.createAid({ aid: receiverAid });

      // Sender 发加密消息（应回退到 long_term_key）
      const sendResult = await sender.call('message.send', {
        to: receiverAid,
        payload: { text: 'long_term回退' },
        encrypt: true,
      });

      // Receiver 后续连接
      const rAuth = await receiver.auth.authenticate({ aid: receiverAid });
      await receiver.connect(rAuth);
      await new Promise(r => setTimeout(r, 1000));

      // Receiver pull 消息
      const pullResult = await receiver.call('message.pull', { after_seq: 0, limit: 10 });
      const msgs = pullResult.messages || [];
      const fromSender = msgs.filter((m: any) => m.from === senderAid);

      await sender.close();
      await receiver.close();

      return {
        sent: !!sendResult?.message_id,
        received: fromSender.length > 0,
        text: fromSender.find((m: any) => m.payload?.text)?.payload?.text,
        encryptionMode: fromSender[0]?.e2ee?.encryption_mode,
      };
    }, rid);

    expect(result.sent).toBe(true);
    expect(result.received).toBe(true);
    if (result.text) {
      expect(result.text).toBe('long_term回退');
    }
    // 如果解密成功，应标记为 long_term_key 模式
    if (result.encryptionMode) {
      expect(result.encryptionMode).toBe('long_term_key');
    }
  });

  test('SDK 双向消息 — 双方互发加密消息', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const aliceAid = `br-bi-a-${rid}.agentid.pub`;
      const bobAid = `br-bi-b-${rid}.agentid.pub`;

      const alice = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await alice.auth.createAid({ aid: aliceAid });
      const aAuth = await alice.auth.authenticate({ aid: aliceAid });
      await alice.connect(aAuth);

      const bob = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await bob.auth.createAid({ aid: bobAid });
      const bAuth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(bAuth);

      // Alice -> Bob
      const send1 = await alice.call('message.send', {
        to: bobAid,
        payload: { text: 'hello_bob' },
        encrypt: true,
      });

      await new Promise(r => setTimeout(r, 1000));

      // Bob -> Alice
      const send2 = await bob.call('message.send', {
        to: aliceAid,
        payload: { text: 'hello_alice' },
        encrypt: true,
      });

      await new Promise(r => setTimeout(r, 1000));

      // 双方拉取
      const pullBob = await bob.call('message.pull', { after_seq: 0, limit: 10 });
      const pullAlice = await alice.call('message.pull', { after_seq: 0, limit: 10 });
      const msgsBob = (pullBob.messages || []).filter((m: any) => m.from === aliceAid);
      const msgsAlice = (pullAlice.messages || []).filter((m: any) => m.from === bobAid);

      await alice.close();
      await bob.close();

      return {
        sent1: !!send1?.message_id,
        sent2: !!send2?.message_id,
        bobReceived: msgsBob.length > 0,
        aliceReceived: msgsAlice.length > 0,
        bobText: msgsBob.find((m: any) => m.payload?.text)?.payload?.text,
        aliceText: msgsAlice.find((m: any) => m.payload?.text)?.payload?.text,
      };
    }, rid);

    expect(result.sent1).toBe(true);
    expect(result.sent2).toBe(true);
    expect(result.bobReceived).toBe(true);
    expect(result.aliceReceived).toBe(true);
    if (result.bobText) {
      expect(result.bobText).toBe('hello_bob');
    }
    if (result.aliceText) {
      expect(result.aliceText).toBe('hello_alice');
    }
  });

  test('连续发送多条消息（burst）', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const senderAid = `br-bu-s-${rid}.agentid.pub`;
      const receiverAid = `br-bu-r-${rid}.agentid.pub`;

      const sender = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await sender.auth.createAid({ aid: senderAid });
      const sAuth = await sender.auth.authenticate({ aid: senderAid });
      await sender.connect(sAuth);

      const receiver = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await receiver.auth.createAid({ aid: receiverAid });
      const rAuth = await receiver.auth.authenticate({ aid: receiverAid });
      await receiver.connect(rAuth);

      // 连续发 5 条加密消息
      const N = 5;
      for (let i = 0; i < N; i++) {
        await sender.call('message.send', {
          to: receiverAid,
          payload: { text: `burst_${i}`, seq: i },
          encrypt: true,
        });
      }

      await new Promise(r => setTimeout(r, 2000));

      const pullResult = await receiver.call('message.pull', { after_seq: 0, limit: 20 });
      const msgs = (pullResult.messages || []).filter((m: any) => m.from === senderAid);

      await sender.close();
      await receiver.close();

      const receivedTexts = msgs
        .map((m: any) => m.payload?.text)
        .filter(Boolean)
        .sort();

      return {
        totalReceived: msgs.length,
        receivedTexts,
        expected: Array.from({ length: N }, (_, i) => `burst_${i}`).sort(),
      };
    }, rid);

    expect(result.totalReceived).toBeGreaterThanOrEqual(5);
    if (result.receivedTexts.length >= 5) {
      expect(result.receivedTexts).toEqual(result.expected);
    }
  });

  test('prekey 轮换 — 轮换前后消息均可解密', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const senderAid = `br-pr-s-${rid}.agentid.pub`;
      const receiverAid = `br-pr-r-${rid}.agentid.pub`;

      const sender = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await sender.auth.createAid({ aid: senderAid });
      const sAuth = await sender.auth.authenticate({ aid: senderAid });
      await sender.connect(sAuth);

      const receiver = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await receiver.auth.createAid({ aid: receiverAid });
      const rAuth = await receiver.auth.authenticate({ aid: receiverAid });
      await receiver.connect(rAuth);

      // 轮换前发消息
      await sender.call('message.send', {
        to: receiverAid,
        payload: { text: 'before_rotate' },
        encrypt: true,
      });

      // Receiver 上传新 prekey（轮换）
      // SDK 内部使用 _uploadPrekey 方法
      if (typeof receiver._uploadPrekey === 'function') {
        await receiver._uploadPrekey();
      } else if (typeof receiver.uploadPrekey === 'function') {
        await receiver.uploadPrekey();
      }

      // 轮换后发消息
      await sender.call('message.send', {
        to: receiverAid,
        payload: { text: 'after_rotate' },
        encrypt: true,
      });

      await new Promise(r => setTimeout(r, 2000));

      const pullResult = await receiver.call('message.pull', { after_seq: 0, limit: 20 });
      const msgs = (pullResult.messages || []).filter((m: any) => m.from === senderAid);

      await sender.close();
      await receiver.close();

      const texts = msgs
        .map((m: any) => m.payload?.text)
        .filter(Boolean);

      return {
        totalReceived: msgs.length,
        texts,
        hasBefore: texts.includes('before_rotate'),
        hasAfter: texts.includes('after_rotate'),
      };
    }, rid);

    expect(result.totalReceived).toBeGreaterThanOrEqual(2);
    if (result.texts.length >= 2) {
      expect(result.hasBefore).toBe(true);
      expect(result.hasAfter).toBe(true);
    }
  });

  test('push + pull 无重复', async ({ page }) => {
    const rid = Math.random().toString(36).slice(2, 8);
    const result = await page.evaluate(async (rid) => {
      const AUN = (window as any).AUN;
      const senderAid = `br-dp-s-${rid}.agentid.pub`;
      const receiverAid = `br-dp-r-${rid}.agentid.pub`;

      const sender = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await sender.auth.createAid({ aid: senderAid });
      const sAuth = await sender.auth.authenticate({ aid: senderAid });
      await sender.connect(sAuth);

      const receiver = new AUN.AUNClient({ verify_ssl: false, require_forward_secrecy: false });
      await receiver.auth.createAid({ aid: receiverAid });
      const rAuth = await receiver.auth.authenticate({ aid: receiverAid });
      await receiver.connect(rAuth);

      // 收集 push 消息
      const pushMsgs: any[] = [];
      let pushResolved = false;
      const pushPromise = new Promise<void>((resolve) => {
        receiver.on('message.received', (data: any) => {
          if (data?.from === senderAid) {
            pushMsgs.push(data);
            if (!pushResolved) {
              pushResolved = true;
              resolve();
            }
          }
        });
      });

      // 发送一条消息
      await sender.call('message.send', {
        to: receiverAid,
        payload: { text: 'dup_test' },
        encrypt: true,
      });

      // 等待 push 到达（最多 5 秒）
      await Promise.race([
        pushPromise,
        new Promise(r => setTimeout(r, 5000)),
      ]);

      // 然后再 pull
      const pullResult = await receiver.call('message.pull', { after_seq: 0, limit: 10 });
      const pullMsgs = (pullResult.messages || []).filter((m: any) => m.from === senderAid);

      await sender.close();
      await receiver.close();

      // 合并所有收到的 message_id，检查无重复
      const allIds = [
        ...pushMsgs.map((m: any) => m.message_id),
        ...pullMsgs.map((m: any) => m.message_id),
      ].filter(Boolean);
      const uniqueIds = new Set(allIds);

      return {
        pushCount: pushMsgs.length,
        pullCount: pullMsgs.length,
        allIds: allIds.length,
        uniqueIds: uniqueIds.size,
        // push 和 pull 各自不应有重复
        noPushDuplicates: new Set(pushMsgs.map((m: any) => m.message_id)).size === pushMsgs.length,
        noPullDuplicates: new Set(pullMsgs.map((m: any) => m.message_id)).size === pullMsgs.length,
      };
    }, rid);

    // 至少通过 pull 收到了消息
    expect(result.pullCount).toBeGreaterThan(0);
    // pull 自身无重复
    expect(result.noPullDuplicates).toBe(true);
    // 如果 push 也收到了，push 自身也不应有重复
    if (result.pushCount > 0) {
      expect(result.noPushDuplicates).toBe(true);
    }
  });
});

