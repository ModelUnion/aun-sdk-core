import { mkdirSync, appendFileSync, readdirSync, statSync, unlinkSync } from 'fs';
import { join } from 'path';

export interface ModuleLogger {
  error(msg: string, err?: Error): void;
  warn(msg: string): void;
  info(msg: string): void;
  debug(msg: string): void;
}

export interface AUNLoggerOptions {
  debug: boolean;
  aunPath: string;
}

type Level = 'ERROR' | 'WARN' | 'INFO' | 'DEBUG';

const LOG_FILE_RE = /^ts-sdk-.*\.log$/;
const DAY_MS = 24 * 60 * 60 * 1000;
const RETAIN_DAYS = 7;

export class AUNLogger {
  private _debug: boolean;
  private _aunPath: string;
  private _aid: string | null = null;
  private _fileWriteFailed = false;
  private _cleanupFailed = false;
  private _mkdirFailed = false;
  private _cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(opts: AUNLoggerOptions) {
    this._debug = opts.debug;
    this._aunPath = opts.aunPath;
    if (this._debug) {
      this._ensureLogDir();
      this._cleanupOldLogs();
      this._cleanupTimer = setInterval(() => this._cleanupOldLogs(), DAY_MS);
      this._cleanupTimer.unref?.();
    }
  }

  for(module: string): ModuleLogger {
    return {
      error: (msg, err) => this._emit('ERROR', module, msg, err),
      warn:  (msg)      => this._emit('WARN',  module, msg),
      info:  (msg)      => this._emit('INFO',  module, msg),
      debug: (msg)      => this._emit('DEBUG', module, msg),
    };
  }

  bindAid(aid: string): void {
    this._aid = aid || null;
  }

  close(): void {
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer);
      this._cleanupTimer = null;
    }
  }

  private _emit(level: Level, module: string, msg: string, err?: Error): void {
    const { date, time, ms } = this._now();
    const head = `[${date} ${time}.${ms}][${level}][${module}]`;
    const aidPart = this._aid ? ` [${this._aid}]` : '';
    const line = `${head}${aidPart} ${msg}`;

    this._toConsole(level, line);
    this._toFile(date, level, line, err);
  }

  private _toConsole(level: Level, line: string): void {
    if (level === 'DEBUG' && !this._debug) return;
    switch (level) {
      case 'ERROR': console.error(line); break;
      case 'WARN':  console.warn(line);  break;
      default:      console.log(line);   break;
    }
  }

  private _toFile(date: string, level: Level, line: string, err?: Error): void {
    if (!this._debug) return;
    const path = join(this._aunPath, 'logs', `ts-sdk-${date}.log`);
    let payload = line + '\n';
    if (level === 'ERROR' && err?.stack) {
      const indented = err.stack.split('\n').map(l => '    ' + l).join('\n');
      payload += `  Traceback:\n${indented}\n`;
    }
    try {
      appendFileSync(path, payload, 'utf-8');
    } catch (exc) {
      if (!this._fileWriteFailed) {
        this._fileWriteFailed = true;
        console.error(`[AUNLogger] 写日志文件失败: ${String(exc)}`);
      }
    }
  }

  private _ensureLogDir(): void {
    try {
      mkdirSync(join(this._aunPath, 'logs'), { recursive: true });
    } catch (exc) {
      if (!this._mkdirFailed) {
        this._mkdirFailed = true;
        console.error(`[AUNLogger] 创建日志目录失败: ${String(exc)}`);
      }
    }
  }

  private _cleanupOldLogs(): void {
    const dir = join(this._aunPath, 'logs');
    const cutoff = Date.now() - RETAIN_DAYS * DAY_MS;
    try {
      for (const name of readdirSync(dir)) {
        if (!LOG_FILE_RE.test(name)) continue;
        try {
          const full = join(dir, name);
          if (statSync(full).mtimeMs < cutoff) unlinkSync(full);
        } catch (exc) {
          if (!this._cleanupFailed) {
            this._cleanupFailed = true;
            console.warn(`[AUNLogger] 清理单个日志文件失败: ${name} ${String(exc)}`);
          }
        }
      }
    } catch (exc) {
      if (!this._cleanupFailed) {
        this._cleanupFailed = true;
        console.warn(`[AUNLogger] 扫描日志目录失败: ${String(exc)}`);
      }
    }
  }

  private _now(): { date: string; time: string; ms: string } {
    const d = new Date();
    const pad = (n: number, w = 2) => String(n).padStart(w, '0');
    const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    const ms = pad(d.getMilliseconds(), 3);
    return { date, time, ms };
  }
}
