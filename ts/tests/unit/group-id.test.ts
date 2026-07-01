import { describe, expect, it } from 'vitest';

import {
  buildDiscoveryHost,
  convertToGroupAid,
  normalizeGroupAid,
  normalizeGroupId,
  splitGroupId,
} from '../../src/group-id.js';
import { ValidationError, validateGroupAIDFormat } from '../../src/index.js';

describe('group-id', () => {
  it('将兼容输入转换为目标态 group_aid', () => {
    expect(convertToGroupAid('room-123.agentid.pub')).toBe('room-123.agentid.pub');
    expect(convertToGroupAid('group.agentid.pub/room-123')).toBe('room-123.agentid.pub');
    expect(convertToGroupAid('room-123@agentid.pub')).toBe('room-123.agentid.pub');
    expect(convertToGroupAid('g-abc123', { localIssuer: 'agentid.pub' })).toBe('g-abc123.agentid.pub');
    expect(convertToGroupAid('group.pub/room-123@agentid')).toBe('room-123.agentid.pub');
  });

  it('旧 normalizeGroupId 名称也返回 group_aid', () => {
    expect(normalizeGroupAid('group.agentid.pub/room-123')).toBe('room-123.agentid.pub');
    expect(normalizeGroupId('group.agentid.pub/room-123')).toBe('room-123.agentid.pub');
  });

  it('拆分 group_aid 时保留多级 issuer', () => {
    expect(splitGroupId('room-123.agentid.pub')).toEqual({ base: 'room-123', domain: 'agentid.pub' });
    expect(splitGroupId('group.agentid.pub/room-123')).toEqual({ base: 'room-123', domain: 'agentid.pub' });
    expect(buildDiscoveryHost('room-123.agentid.pub')).toBe('agentid.pub');
  });

  it('空串和纯斜杠不会生成默认群', () => {
    expect(convertToGroupAid('')).toBe('');
    expect(convertToGroupAid('   ')).toBe('');
    expect(convertToGroupAid('///')).toBe('');
  });

  it('validator 拒绝畸形、非法字符和超长输入', () => {
    expect(() => validateGroupAIDFormat('group.agentid.pub//room-123')).toThrow(ValidationError);
    expect(() => validateGroupAIDFormat('room#123.agentid.pub')).toThrow(ValidationError);
    expect(() => validateGroupAIDFormat(`${'a'.repeat(65)}.agentid.pub`)).toThrow(ValidationError);
  });
});
