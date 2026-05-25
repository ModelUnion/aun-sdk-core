import { describe, expect, it, vi } from 'vitest';
import { AUNLogger } from '../../src/logger.js';

describe('AUNLogger', () => {
  it('日志行包含 aun_path 和 device_id 上下文', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    try {
      const logger = new AUNLogger({ debug: false, aunPath: 'aun-web' });
      logger.bindDeviceId('device-1');
      logger.for('aun_core.client').info('hello %s', 'world');

      const line = String(infoSpy.mock.calls[0]?.[0] ?? '');
      expect(line).toContain('[INFO][aun_core.client][aun_path=aun-web][device_id=device-1] hello world');
    } finally {
      infoSpy.mockRestore();
    }
  });
});
