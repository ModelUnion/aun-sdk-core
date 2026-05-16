import { defineConfig } from 'vitest/config';

// 单元测试环境隔离：仅 tests/unit 下的测试禁用 ~/.aun/log.ini 读取，
// 避免本机 log.ini 配置影响单元测试 mock 断言。
// integration / e2e 测试保留 ini 真实行为，可验证日志重定向到 ~/.aun/logs/。
const isUnitOnly =
  process.argv.some((a) => /tests[\\/]unit/.test(a)) ||
  process.env.npm_lifecycle_event === 'test:unit';
if (isUnitOnly) {
  process.env.AUN_LOG_INI_DISABLE = '1';
}

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    fileParallelism: false,
    globals: false,
    env: isUnitOnly ? { AUN_LOG_INI_DISABLE: '1' } : {},
  },
});
