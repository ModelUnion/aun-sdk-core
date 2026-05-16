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
    // 测试隔离：避免读真实 ~/.aun/log.ini 影响行为
    existsSync: vi.fn().mockReturnValue(false),
    readFileSync: vi.fn(),
  };
});

import { AUNLogger } from '../../src/logger.js';

describe('AUNLogger 输出矩阵', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.mocked(fs.appendFileSync).mockClear();
    logSpy  = vi.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    errSpy  = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    logSpy.mockRestore();
    warnSpy.mockRestore();
    errSpy.mockRestore();
  });

  it('debug=OFF: ERROR/WARN/INFO 到控制台，DEBUG 不输出', () => {
    const logger = new AUNLogger({ debug: false, aunPath: '/tmp/aun' });
    const l = logger.for('aun_core.client');
    l.error('e'); l.warn('w'); l.info('i'); l.debug('d');
    expect(errSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(logSpy).toHaveBeenCalledTimes(1); // only INFO
    expect(logSpy.mock.calls[0][0]).toContain('[INFO]');
    expect(fs.appendFileSync).not.toHaveBeenCalled();
  });

  it('debug=ON: 4 级别全部进控制台 + 文件', () => {
    const logger = new AUNLogger({ debug: true, aunPath: '/tmp/aun' });
    const l = logger.for('aun_core.client');
    l.error('e'); l.warn('w'); l.info('i'); l.debug('d');
    expect(errSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(logSpy).toHaveBeenCalledTimes(2); // INFO + DEBUG
    expect(fs.appendFileSync).toHaveBeenCalledTimes(4);
    logger.close();
  });

  it('ERROR 进 console.error，WARN 进 console.warn，INFO/DEBUG 进 console.log', () => {
    const logger = new AUNLogger({ debug: true, aunPath: '/tmp/aun' });
    const l = logger.for('aun_core.transport');
    l.info('i');
    l.debug('d');
    l.warn('w');
    l.error('e');
    expect(logSpy).toHaveBeenCalledTimes(2);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(errSpy).toHaveBeenCalledTimes(1);
    logger.close();
  });
});

describe('AUNLogger 文件清理', () => {
  let errSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    vi.mocked(fs.readdirSync).mockReset();
    vi.mocked(fs.statSync).mockReset();
    vi.mocked(fs.unlinkSync).mockReset();
    vi.mocked(fs.mkdirSync).mockClear();
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    errSpy.mockRestore();
  });

  it('7 天外的 ts-sdk-*.log 被删除，7 天内的保留，非 ts-sdk- 文件忽略', () => {
    const now = Date.now();
    const week = 7 * 24 * 60 * 60 * 1000;

    vi.mocked(fs.readdirSync).mockReturnValue([
      'ts-sdk-2026-05-01.log',
      'ts-sdk-2026-05-12.log',
      'other.log',
      'ts-sdk-broken',
    ] as any);

    vi.mocked(fs.statSync).mockImplementation(((p: string) => {
      if (p.endsWith('2026-05-01.log')) return { mtimeMs: now - week - 1 } as any;
      return { mtimeMs: now - 1000 } as any;
    }) as any);

    const logger = new AUNLogger({ debug: true, aunPath: '/tmp/aun' });
    logger.close();

    const unlinkCalls = vi.mocked(fs.unlinkSync).mock.calls.map(c => String(c[0]));
    expect(unlinkCalls).toHaveLength(1);
    expect(unlinkCalls[0]).toMatch(/ts-sdk-2026-05-01\.log$/);
  });
});
