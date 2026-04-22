/**
 * AUNLogger 单元测试 — 日志格式验证
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';

// mock fs 避免真正写文件
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

describe('AUNLogger 日志格式（TS-003）', () => {
  let logger: AUNLogger;

  beforeEach(() => {
    vi.mocked(fs.appendFileSync).mockClear();
    logger = new AUNLogger();
  });

  it('时间戳和 AID 之间应有空格分隔', () => {
    logger.setAid('test.aid.com');
    logger.log('hello world');

    expect(fs.appendFileSync).toHaveBeenCalledTimes(1);
    const line = vi.mocked(fs.appendFileSync).mock.calls[0][1] as string;

    // 格式应为：{timestamp} | [{aid}] {message}\n
    // 时间戳后应有 " | " 分隔符，AID 应被方括号包裹
    expect(line).toMatch(/^\d+ \| \[test\.aid\.com\] hello world\n$/);
  });

  it('无 AID 时不应输出空的方括号', () => {
    // 未调用 setAid，AID 为空
    logger.log('no aid message');

    expect(fs.appendFileSync).toHaveBeenCalledTimes(1);
    const line = vi.mocked(fs.appendFileSync).mock.calls[0][1] as string;

    // 无 AID 时格式应为：{timestamp} | {message}\n（不含 []）
    expect(line).toMatch(/^\d+ \| no aid message\n$/);
    expect(line).not.toContain('[]');
  });

  it('时间戳应为毫秒级 Unix 时间', () => {
    logger.log('timestamp check');

    const line = vi.mocked(fs.appendFileSync).mock.calls[0][1] as string;
    const tsStr = line.split(' ')[0];
    const ts = parseInt(tsStr, 10);

    // 应为合理的毫秒级时间戳（大于 2020-01-01 毫秒值）
    expect(ts).toBeGreaterThan(1577836800000);
  });
});
