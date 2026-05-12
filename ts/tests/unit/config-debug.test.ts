import { describe, it, expect } from 'vitest';
import { configFromMap, defaultConfig } from '../../src/config.js';

describe('AUNConfig.debug', () => {
  it('defaultConfig 返回 debug=false', () => {
    expect(defaultConfig().debug).toBe(false);
  });
  it('configFromMap 读 raw.debug', () => {
    expect(configFromMap({ debug: true }).debug).toBe(true);
    expect(configFromMap({ debug: false }).debug).toBe(false);
    expect(configFromMap({}).debug).toBe(false);
  });
});
