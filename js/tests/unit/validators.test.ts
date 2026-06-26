/**
 * 测试 AID 和 Group ID 格式校验器（对齐 Python tests/unit/test_validators.py）。
 */

import { describe, it, expect } from 'vitest';
import { ValidationError } from '../../src/errors.js';
import { validateAIDFormat, validateGroupIDFormat } from '../../src/validators.js';

describe('validateAIDFormat', () => {
  it('接受合法 AID', () => {
    expect(validateAIDFormat('alice.aid.pub')).toBe('alice.aid.pub');
    expect(validateAIDFormat('test_user.example.com')).toBe('test_user.example.com');
    expect(validateAIDFormat('user-123.aid.pub')).toBe('user-123.aid.pub');
    expect(validateAIDFormat('a1b2.test.co.uk')).toBe('a1b2.test.co.uk');
    expect(validateAIDFormat('alice.bob.aid.pub')).toBe('alice.bob.aid.pub');
  });

  it('大小写规范化', () => {
    expect(validateAIDFormat('Alice.AID.PUB')).toBe('alice.aid.pub');
    expect(validateAIDFormat('  TEST.example.com  ')).toBe('test.example.com');
  });

  it('拒绝空值', () => {
    expect(() => validateAIDFormat('')).toThrow(/cannot be empty/);
    expect(() => validateAIDFormat(null)).toThrow(/cannot be empty/);
    expect(() => validateAIDFormat('   ')).toThrow(/cannot be empty/);
  });

  it('拒绝缺少 issuer', () => {
    expect(() => validateAIDFormat('alice')).toThrow(/must be in format/);
    expect(() => validateAIDFormat('test_user')).toThrow(/must be in format/);
  });

  it('拒绝 name 太短', () => {
    expect(() => validateAIDFormat('abc.aid.pub')).toThrow(/must be 4-64 characters/);
    expect(() => validateAIDFormat('a.aid.pub')).toThrow(/must be 4-64 characters/);
  });

  it('拒绝 name 太长', () => {
    const longName = 'a'.repeat(65);
    expect(() => validateAIDFormat(`${longName}.aid.pub`)).toThrow(/must be 4-64 characters/);
  });

  it('拒绝 name 以 - 开头', () => {
    expect(() => validateAIDFormat('-test.aid.pub')).toThrow(/cannot start with '-'/);
  });

  it('拒绝 name 以 guest 开头', () => {
    expect(() => validateAIDFormat('guest.aid.pub')).toThrow(/cannot start with 'guest'/);
    expect(() => validateAIDFormat('guest123.aid.pub')).toThrow(/cannot start with 'guest'/);
    expect(() => validateAIDFormat('guestuser.aid.pub')).toThrow(/cannot start with 'guest'/);
  });

  it('拒绝非法字符', () => {
    expect(() => validateAIDFormat('alice@bob.aid.pub')).toThrow(/must be 4-64 characters/);
    expect(() => validateAIDFormat('alice bob.aid.pub')).toThrow(/must be 4-64 characters/);
    expect(() => validateAIDFormat('alice#test.aid.pub')).toThrow(/must be 4-64 characters/);
  });

  it('拒绝非法 issuer', () => {
    expect(() => validateAIDFormat('alice.')).toThrow(/issuer part cannot be empty/);
    expect(() => validateAIDFormat('alice.#invalid')).toThrow(/is not a valid domain/);
  });

  it('拒绝特殊非法情况', () => {
    expect(() => validateAIDFormat('__system__')).toThrow(ValidationError);
    expect(() => validateAIDFormat('123.aid.pub')).toThrow(ValidationError);
  });
});

describe('validateGroupIDFormat', () => {
  it('接受 legacy 格式', () => {
    expect(validateGroupIDFormat('g-abc123')).toBe('g-abc123');
    expect(validateGroupIDFormat('g-test')).toBe('g-test');
    expect(validateGroupIDFormat('g-1234')).toBe('g-1234');
    const longSlug = 'a'.repeat(32);
    expect(validateGroupIDFormat(`g-${longSlug}`)).toBe(`g-${longSlug}`);
  });

  it('接受带域名的 legacy 格式', () => {
    expect(validateGroupIDFormat('g-abc123.aid.pub')).toBe('g-abc123.aid.pub');
    expect(validateGroupIDFormat('g-test@example.com')).toBe('g-test@example.com');
  });

  it('接受新格式 base', () => {
    expect(validateGroupIDFormat('12345')).toBe('12345');
    expect(validateGroupIDFormat('abcde')).toBe('abcde');
    expect(validateGroupIDFormat('a1b2c3')).toBe('a1b2c3');
    const longBase = 'a'.repeat(100);
    expect(validateGroupIDFormat(longBase)).toBe(longBase);
  });

  it('接受 group name 格式', () => {
    expect(validateGroupIDFormat('test_group')).toBe('test_group');
    expect(validateGroupIDFormat('my-team')).toBe('my-team');
    expect(validateGroupIDFormat('team123')).toBe('team123');
  });

  it('接受 canonical 格式', () => {
    expect(validateGroupIDFormat('group.aid.pub/g-abc123')).toBe('group.aid.pub/g-abc123');
    expect(validateGroupIDFormat('group.example.com/12345')).toBe('group.example.com/12345');
    expect(validateGroupIDFormat('group.aid.pub/my_team')).toBe('group.aid.pub/my_team');
  });

  it('大小写规范化', () => {
    expect(validateGroupIDFormat('G-ABC123')).toBe('g-abc123');
    expect(validateGroupIDFormat('  G-TEST@EXAMPLE.COM  ')).toBe('g-test@example.com');
    expect(validateGroupIDFormat('MyTeam')).toBe('myteam');
  });

  it('拒绝空值', () => {
    expect(() => validateGroupIDFormat('')).toThrow(/cannot be empty/);
    expect(() => validateGroupIDFormat(null)).toThrow(/cannot be empty/);
    expect(() => validateGroupIDFormat('   ')).toThrow(/cannot be empty/);
  });

  it('拒绝太短/非法 base', () => {
    expect(() => validateGroupIDFormat('g-a')).toThrow(/must be one of/);
    expect(() => validateGroupIDFormat('ab')).toThrow(/must be one of/);
    expect(() => validateGroupIDFormat('123')).toThrow(/must be one of/);
  });

  it('拒绝 base 太长', () => {
    const longSlug = 'a'.repeat(63); // g- + 63 = 65 字符，超过 group name 上限
    expect(() => validateGroupIDFormat(`g-${longSlug}`)).toThrow(/must be one of/);
  });

  it('拒绝非法字符', () => {
    expect(() => validateGroupIDFormat('test group')).toThrow(/must be one of/);
    expect(() => validateGroupIDFormat('test#group')).toThrow(/must be one of/);
    expect(() => validateGroupIDFormat('test$abc')).toThrow(/must be one of/);
  });

  it('拒绝非法域名', () => {
    expect(() => validateGroupIDFormat('g-test@#invalid')).toThrow(/is not a valid domain/);
    expect(() => validateGroupIDFormat('g-test@in valid')).toThrow(/is not a valid domain/);
  });

  it('group name 边界情况', () => {
    expect(validateGroupIDFormat('team')).toBe('team');
    const longName = 'a' + 'b'.repeat(63);
    expect(validateGroupIDFormat(longName)).toBe(longName);
    expect(validateGroupIDFormat('my_team-01')).toBe('my_team-01');
  });
});
