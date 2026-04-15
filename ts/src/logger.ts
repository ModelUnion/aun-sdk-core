import { mkdirSync, appendFileSync, readdirSync, statSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

function logDir(): string {
  return join(homedir(), '.aun', 'logs');
}

function logPath(dateStr: string): string {
  return join(logDir(), `ts-sdk-${dateStr}.log`);
}

/** 删除超过 keepDays 天的旧日志文件 */
function cleanupOldLogs(keepDays = 3): void {
  const dir = logDir();
  const cutoff = Date.now() - keepDays * 86400_000;
  try {
    for (const name of readdirSync(dir)) {
      if (!name.startsWith('ts-sdk-') || !name.endsWith('.log')) continue;
      try {
        const full = join(dir, name);
        if (statSync(full).mtimeMs < cutoff) unlinkSync(full);
      } catch {}
    }
  } catch {}
}

export class AUNLogger {
  private _aid = '';

  constructor() {
    try { mkdirSync(logDir(), { recursive: true }); } catch {}
    cleanupOldLogs();
  }

  setAid(aid: string): void { this._aid = aid; }

  log(message: string): void {
    const now = new Date();
    const tsMs = now.getTime();
    const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
    const line = `${tsMs}${this._aid} ${message}\n`;
    try {
      appendFileSync(logPath(dateStr), line, 'utf-8');
    } catch (exc) {
      // eslint-disable-next-line no-console
      console.error('[AUNLogger] 写日志文件失败:', exc);
    }
  }
}
