import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';

vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof fs>('fs');
  return {
    ...actual,
    mkdirSync: vi.fn(),
    appendFileSync: vi.fn(),
    readdirSync: vi.fn().mockReturnValue([]),
    statSync: vi.fn(),
    unlinkSync: vi.fn(),
  };
});

import { AUNLogger } from '../../src/logger.js';

const FMT = /^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\]\[(ERROR|WARN|INFO|DEBUG)\]\[aun_core\.[a-z0-9-]+\] /;

describe('AUNLogger 新格式', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.mocked(fs.appendFileSync).mockClear();
    vi.mocked(fs.mkdirSync).mockClear();
    logSpy  = vi.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    errSpy  = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    logSpy.mockRestore();
    warnSpy.mockRestore();
    errSpy.mockRestore();
  });

  it('INFO 行符合规范格式', () => {
    const logger = new AUNLogger({ debug: false, aunPath: '/tmp/aun' });
    logger.for('aun_core.auth').info('login succeeded');
    expect(logSpy).toHaveBeenCalledTimes(1);
    const line = String(logSpy.mock.calls[0][0]);
    expect(line).toMatch(FMT);
    expect(line).toContain('[INFO]');
    expect(line).toContain('[aun_core.auth]');
    expect(line).toContain('login succeeded');
  });

  it('bindAid 前后 message 差异', () => {
    const logger = new AUNLogger({ debug: false, aunPath: '/tmp/aun' });
    logger.for('aun_core.client').info('before');
    logger.bindAid('alice.com');
    logger.for('aun_core.client').info('after');
    const l0 = String(logSpy.mock.calls[0][0]);
    const l1 = String(logSpy.mock.calls[1][0]);
    expect(l0).not.toContain('[alice.com]');
    expect(l0).toMatch(/\[aun_core\.client\] before$/);
    expect(l1).toContain('[alice.com]');
    expect(l1).toMatch(/\[aun_core\.client\] \[alice\.com\] after$/);
  });

  it('ERROR 带 Error：控制台只单行，文件追加 Traceback', () => {
    const logger = new AUNLogger({ debug: true, aunPath: '/tmp/aun' });
    const err = new Error('boom');
    err.stack = 'Error: boom\n    at foo (bar.ts:1:1)';
    logger.for('aun_core.e2ee').error('decrypt failed', err);

    expect(errSpy).toHaveBeenCalledTimes(1);
    const consoleLine = String(errSpy.mock.calls[0][0]);
    expect(consoleLine).not.toContain('Traceback');
    expect(consoleLine).not.toContain('    at foo');

    expect(fs.appendFileSync).toHaveBeenCalledTimes(1);
    const payload = String(vi.mocked(fs.appendFileSync).mock.calls[0][1]);
    expect(payload).toContain('decrypt failed');
    expect(payload).toContain('Traceback:');
    expect(payload).toContain('    Error: boom');
    expect(payload).toContain('    at foo (bar.ts:1:1)');
    logger.close();
  });

  it('文件路径为 {aunPath}/logs/ts-sdk-{yyyy-mm-dd}.log', () => {
    const logger = new AUNLogger({ debug: true, aunPath: '/custom/aun' });
    logger.for('aun_core.client').info('hello');
    expect(fs.appendFileSync).toHaveBeenCalledTimes(1);
    const path = String(vi.mocked(fs.appendFileSync).mock.calls[0][0]);
    expect(path).toMatch(/[\\/]custom[\\/]aun[\\/]logs[\\/]ts-sdk-\d{4}-\d{2}-\d{2}\.log$/);
    logger.close();
  });

  it('debug=false 时不建 logs 目录、不写文件', () => {
    vi.mocked(fs.mkdirSync).mockClear();
    const logger = new AUNLogger({ debug: false, aunPath: '/tmp/aun' });
    logger.for('aun_core.client').info('hello');
    expect(fs.mkdirSync).not.toHaveBeenCalled();
    expect(fs.appendFileSync).not.toHaveBeenCalled();
    logger.close();
  });
});
