import { describe, it, expect } from 'vitest';
import { validateAIDFormat, validateGroupAIDFormat, validateGroupIDFormat, ValidationError } from '../../src/index.js';

describe('validators', () => {
  describe('validateAIDFormat', () => {
    it('should accept valid AID', () => {
      expect(validateAIDFormat('alice.aid.com')).toBe('alice.aid.com');
      expect(validateAIDFormat('bob_123.example.org')).toBe('bob_123.example.org');
      expect(validateAIDFormat('test-user.domain.co')).toBe('test-user.domain.co');
    });

    it('should normalize to lowercase', () => {
      expect(validateAIDFormat('Alice.AID.COM')).toBe('alice.aid.com');
      expect(validateAIDFormat('BOB1.Example.Org')).toBe('bob1.example.org');
    });

    it('should reject empty AID', () => {
      expect(() => validateAIDFormat('')).toThrow(ValidationError);
      expect(() => validateAIDFormat(null)).toThrow(ValidationError);
      expect(() => validateAIDFormat(undefined)).toThrow(ValidationError);
    });

    it('should reject AID without issuer', () => {
      expect(() => validateAIDFormat('alice')).toThrow(ValidationError);
      expect(() => validateAIDFormat('alice.')).toThrow(ValidationError);
    });

    it('should reject AID starting with guest', () => {
      expect(() => validateAIDFormat('guest123.aid.com')).toThrow(ValidationError);
      expect(() => validateAIDFormat('guestuser.example.org')).toThrow(ValidationError);
    });

    it('should reject AID name starting with hyphen', () => {
      expect(() => validateAIDFormat('-alice.aid.com')).toThrow(ValidationError);
    });

    it('should reject AID name too short', () => {
      expect(() => validateAIDFormat('ab.aid.com')).toThrow(ValidationError);
      expect(() => validateAIDFormat('bob.aid.com')).toThrow(ValidationError);
    });

    it('should accept AID name at the 4-character minimum', () => {
      expect(validateAIDFormat('bob1.aid.com')).toBe('bob1.aid.com');
    });

    it('should reject invalid characters in name', () => {
      expect(() => validateAIDFormat('alice@bob1.aid.com')).toThrow(ValidationError);
      expect(() => validateAIDFormat('alice bob1.aid.com')).toThrow(ValidationError);
    });

    it('should reject invalid domain', () => {
      expect(() => validateAIDFormat('alice.-invalid')).toThrow(ValidationError);
      expect(() => validateAIDFormat('alice.invalid-')).toThrow(ValidationError);
    });
  });

  describe('validateGroupIDFormat', () => {
    it('should accept legacy format', () => {
      expect(validateGroupIDFormat('g-abcd1234')).toBe('g-abcd1234');
      expect(validateGroupIDFormat('g-test')).toBe('g-test');
    });

    it('should accept new base format', () => {
      expect(validateGroupIDFormat('abcde')).toBe('abcde');
      expect(validateGroupIDFormat('12345678')).toBe('12345678');
    });

    it('should accept group name format', () => {
      expect(validateGroupIDFormat('team_alpha')).toBe('team_alpha');
      expect(validateGroupIDFormat('group-beta')).toBe('group-beta');
    });

    it('should accept canonical format', () => {
      expect(validateGroupIDFormat('group.aid.com/g-test')).toBe('g-test.aid.com');
      expect(validateGroupIDFormat('group.example.org/mygroup')).toBe('mygroup.example.org');
    });

    it('should accept @ format', () => {
      expect(validateGroupIDFormat('g-test@aid.com')).toBe('g-test.aid.com');
      expect(validateGroupIDFormat('mygroup@example.org')).toBe('mygroup.example.org');
    });

    it('should accept dot format', () => {
      expect(validateGroupIDFormat('g-test.aid.com')).toBe('g-test.aid.com');
      expect(validateGroupIDFormat('mygroup.example.org')).toBe('mygroup.example.org');
    });

    it('should normalize to lowercase', () => {
      expect(validateGroupIDFormat('G-TEST')).toBe('g-test');
      expect(validateGroupIDFormat('MyGroup.EXAMPLE.ORG')).toBe('mygroup.example.org');
    });

    it('should return target group_aid format for legacy inputs', () => {
      expect(validateGroupAIDFormat('room-123.agentid.pub')).toBe('room-123.agentid.pub');
      expect(validateGroupAIDFormat('group.agentid.pub/room-123')).toBe('room-123.agentid.pub');
      expect(validateGroupAIDFormat('room-123@agentid.pub')).toBe('room-123.agentid.pub');
      expect(validateGroupAIDFormat('g-abc123', { localIssuer: 'agentid.pub' })).toBe('g-abc123.agentid.pub');
      expect(validateGroupAIDFormat('group.pub/room-123@agentid')).toBe('room-123.agentid.pub');
    });

    it('should reject empty group_id', () => {
      expect(() => validateGroupIDFormat('')).toThrow(ValidationError);
      expect(() => validateGroupIDFormat(null)).toThrow(ValidationError);
      expect(() => validateGroupIDFormat(undefined)).toThrow(ValidationError);
    });

    it('should reject invalid base format', () => {
      expect(() => validateGroupIDFormat('ab')).toThrow(ValidationError); // 太短（只有2个字符）
      expect(() => validateGroupIDFormat('123')).toThrow(ValidationError); // 太短（只有3个字符）
    });

    it('should reject invalid domain', () => {
      expect(() => validateGroupIDFormat('g-test.-invalid')).toThrow(ValidationError);
      expect(() => validateGroupIDFormat('mygroup@invalid-')).toThrow(ValidationError);
    });
  });
});
