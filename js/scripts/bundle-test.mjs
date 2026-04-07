// 将 TypeScript SDK 打包为浏览器可用的 ESM bundle（用于 Playwright E2E 测试）
import { build } from 'esbuild';

await build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  format: 'esm',
  outfile: 'dist/aun-core-browser.js',
  platform: 'browser',
  target: 'es2022',
});

console.log('Bundle 完成: dist/aun-core-browser.js');
