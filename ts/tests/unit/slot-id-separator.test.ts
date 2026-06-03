import { describe, it, expect } from 'vitest';
import { AUNClient } from '../../src/client.js';
import { slotIsolationKey, normalizeSlotId } from '../../src/config.js';
import { ValidationError } from '../../src/errors.js';

describe('slotIsolationKey', () => {
  it.each([
    ['evolclaw cli', 'evolclaw'],
    ['evolclaw/cli', 'evolclaw'],
    ['evolclaw:daemon', 'evolclaw'],
    ['simple', 'simple'],
    ['a/b/c', 'a'],
    ['', ''],
  ])('slotIsolationKey(%j) → %j', (input, expected) => {
    expect(slotIsolationKey(input)).toBe(expected);
  });
});

describe('normalizeSlotId', () => {
  it('合法值返回原值', () => {
    expect(normalizeSlotId('evolclaw cli')).toBe('evolclaw cli');
    expect(normalizeSlotId('evolclaw/cli')).toBe('evolclaw/cli');
  });

  it('以 / 开头抛 ValidationError', () => {
    expect(() => normalizeSlotId('/invalid')).toThrow(ValidationError);
  });

  it('以 : 开头抛 ValidationError', () => {
    expect(() => normalizeSlotId(':invalid')).toThrow(ValidationError);
  });

  it('空值 fallback 到 "default"', () => {
    expect(normalizeSlotId('')).toBe('default');
  });
});

describe('_delivery.messageTargetsCurrentInstance', () => {
  it('同前缀不同后缀 → true', () => {
    const client = new AUNClient();
    (client as any)._slotId = 'evolclaw cli';
    expect((client as any)._delivery.messageTargetsCurrentInstance({ slot_id: 'evolclaw daemon' })).toBe(true);
  });

  it('不同前缀 → false', () => {
    const client = new AUNClient();
    (client as any)._slotId = 'evolclaw cli';
    expect((client as any)._delivery.messageTargetsCurrentInstance({ slot_id: 'other daemon' })).toBe(false);
  });

  it('无 slot_id 字段 → true', () => {
    const client = new AUNClient();
    (client as any)._slotId = 'evolclaw cli';
    expect((client as any)._delivery.messageTargetsCurrentInstance({})).toBe(true);
  });
});
