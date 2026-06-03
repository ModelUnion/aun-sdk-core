// ── slot_id 隔离键与规范化单元测试 ──────────────────────────────
// 对标 TS 版本 ts/tests/unit/slot-id-separator.test.ts
import 'fake-indexeddb/auto';
import { describe, it, expect } from 'vitest';
import { slotIsolationKey, normalizeSlotId } from '../../src/config.js';
import { ValidationError } from '../../src/errors.js';
import { AUNClient } from '../../src/client.js';

describe('slotIsolationKey', () => {
  it('"evolclaw cli" → "evolclaw"', () => {
    expect(slotIsolationKey('evolclaw cli')).toBe('evolclaw');
  });
  it('"evolclaw/cli" → "evolclaw"', () => {
    expect(slotIsolationKey('evolclaw/cli')).toBe('evolclaw');
  });
  it('"evolclaw:daemon" → "evolclaw"', () => {
    expect(slotIsolationKey('evolclaw:daemon')).toBe('evolclaw');
  });
  it('"simple" → "simple"', () => {
    expect(slotIsolationKey('simple')).toBe('simple');
  });
  it('"a/b/c" → "a"', () => {
    expect(slotIsolationKey('a/b/c')).toBe('a');
  });
  it('"" → ""', () => {
    expect(slotIsolationKey('')).toBe('');
  });
});

describe('normalizeSlotId', () => {
  it('"evolclaw cli" 合法', () => {
    expect(normalizeSlotId('evolclaw cli')).toBe('evolclaw cli');
  });
  it('"evolclaw/cli" 合法', () => {
    expect(normalizeSlotId('evolclaw/cli')).toBe('evolclaw/cli');
  });
  it('"/invalid" 抛 ValidationError', () => {
    expect(() => normalizeSlotId('/invalid')).toThrow(ValidationError);
  });
  it('":invalid" 抛 ValidationError', () => {
    expect(() => normalizeSlotId(':invalid')).toThrow(ValidationError);
  });
  it('空值 fallback 到 "default"', () => {
    expect(normalizeSlotId('')).toBe('default');
    expect(normalizeSlotId(null)).toBe('default');
    expect(normalizeSlotId(undefined)).toBe('default');
  });
});

describe('_delivery.messageTargetsCurrentInstance', () => {
  it('同隔离键（evolclaw）→ true', () => {
    const client = new AUNClient();
    (client as any)._slotId = 'evolclaw cli';
    const result = (client as any)._delivery.messageTargetsCurrentInstance({ slot_id: 'evolclaw daemon' });
    expect(result).toBe(true);
  });
  it('不同隔离键 → false', () => {
    const client = new AUNClient();
    (client as any)._slotId = 'evolclaw cli';
    const result = (client as any)._delivery.messageTargetsCurrentInstance({ slot_id: 'other daemon' });
    expect(result).toBe(false);
  });
  it('消息无 slot_id 字段 → true', () => {
    const client = new AUNClient();
    (client as any)._slotId = 'evolclaw cli';
    const result = (client as any)._delivery.messageTargetsCurrentInstance({ text: 'hello' });
    expect(result).toBe(true);
  });
});
