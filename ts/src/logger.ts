import { mkdirSync, appendFileSync, readdirSync, statSync, unlinkSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

export interface ModuleLogger {
  error(msg: string, err?: Error): void;
  warn(msg: string): void;
  info(msg: string): void;
  debug(msg: string): void;
  isDebugEnabled?(): boolean;
}

export interface AUNLoggerOptions {
  debug: boolean;
  aunPath: string;
}

type Level = 'ERROR' | 'WARN' | 'INFO' | 'DEBUG';

const LOG_FILE_RE = /^ts-sdk-.*\.log$/;
const DAY_MS = 24 * 60 * 60 * 1000;
const RETAIN_DAYS = 7;
const LEVEL_ORDER: Record<Level, number> = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

function parseLogIni(path: string): Record<string, string> | null {
  try {
    if (!existsSync(path)) return null;
    const content = readFileSync(path, 'utf-8');
    const result: Record<string, string> = {};
    for (const raw of content.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith(';')) continue;
      const idx = line.indexOf('=');
      if (idx <= 0) continue;
      const key = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim().toLowerCase();
      result[key] = value;
    }
    return result;
  } catch {
    return null;
  }
}

function parseBool(value: string | undefined): boolean {
  return value === '1' || value === 'true' || value === 'on' || value === 'yes';
}

export class AUNLogger {
  private _debug: boolean;
  private _aunPath: string;
  private _deviceId: string = '-';
  private _logDir: string;
  private _minLevel: number;
  private _aid: string | null = null;
  private _fileWriteFailed = false;
  private _cleanupFailed = false;
  private _mkdirFailed = false;
  private _cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(opts: AUNLoggerOptions) {
    this._aunPath = opts.aunPath || join(homedir(), '.aun');
    // ~/.aun/log.ini 存在时覆盖代码层 debug 标志，且日志目录强制为 ~/.aun/logs/
    // 测试可通过环境变量 AUN_LOG_INI_DISABLE=1 跳过读取 ini，避免真实环境干扰
    const iniDisabled = process.env.AUN_LOG_INI_DISABLE === '1' || process.env.AUN_LOG_INI_DISABLE === 'true';
    const iniPath = join(homedir(), '.aun', 'log.ini');
    const ini = iniDisabled ? null : parseLogIni(iniPath);
    let levelStr: string;
    if (ini) {
      this._debug = parseBool(ini['debug']);
      this._logDir = join(homedir(), '.aun', 'logs');
      levelStr = (ini['level'] ?? (this._debug ? 'debug' : 'info')).toLowerCase();
    } else {
      this._debug = opts.debug;
      this._logDir = join(this._aunPath, 'logs');
      levelStr = this._debug ? 'debug' : 'info';
    }
    const lvl = LEVEL_ORDER[(levelStr.toUpperCase() as Level)] ?? LEVEL_ORDER.INFO;
    this._minLevel = lvl;
    // 仅 debug=ON 时建日志目录、清理过期日志、启动定时清理
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
      isDebugEnabled: () => this.isDebugEnabled(),
    };
  }

  isDebugEnabled(): boolean {
    return this._debug && this._minLevel <= LEVEL_ORDER.DEBUG;
  }

  bindAid(aid: string): void {
    this._aid = aid || null;
  }

  bindDeviceId(deviceId: string): void {
    this._deviceId = String(deviceId || '').trim() || '-';
  }

  close(): void {
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer);
      this._cleanupTimer = null;
    }
  }

  private _emit(level: Level, module: string, msg: string, err?: Error): void {
    // 低于最低级别一律不输出（控制台 + 文件均不输出）
    if (LEVEL_ORDER[level] < this._minLevel) return;
    // debug=OFF 时 DEBUG 一律不输出（控制台 + 文件均不输出）
    if (level === 'DEBUG' && !this._debug) return;
    const { date, time, ms } = this._now();
    const head = `[${date} ${time}.${ms}][${level}][${module}][aun_path=${this._aunPath || '-'}][device_id=${this._deviceId || '-'}]`;
    const aidPart = this._aid ? ` [${this._aid}]` : '';
    const line = `${head}${aidPart} ${msg}`;

    this._toConsole(level, line);
    // debug=OFF 时不写文件（与日志规范一致：debug=OFF → 仅控制台 INFO/WARN/ERROR）
    if (this._debug) {
      this._toFile(date, level, line, err);
    }
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
    const path = join(this._logDir, `ts-sdk-${date}.log`);
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
        console.error(`[AUNLogger] failed to write log file: ${String(exc)}`);
      }
    }
  }

  private _ensureLogDir(): void {
    try {
      mkdirSync(this._logDir, { recursive: true });
    } catch (exc) {
      if (!this._mkdirFailed) {
        this._mkdirFailed = true;
        console.error(`[AUNLogger] failed to create log directory: ${String(exc)}`);
      }
    }
  }

  private _cleanupOldLogs(): void {
    const dir = this._logDir;
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
            console.warn(`[AUNLogger] failed to cleanup log file: ${name} ${String(exc)}`);
          }
        }
      }
    } catch (exc) {
      if (!this._cleanupFailed) {
        this._cleanupFailed = true;
        console.warn(`[AUNLogger] failed to scan log directory: ${String(exc)}`);
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
