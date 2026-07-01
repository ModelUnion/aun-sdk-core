/**
 * AUN SDK 浏览器环境日志记录器。
 *
 * 与 TS SDK Logger 接口对齐，但行为简化：
 * - 仅输出到控制台（浏览器环境无文件系统）
 * - 不读 ~/.aun/log.ini（浏览器无 home 目录）
 * - 格式：[yyyy-mm-dd HH:mm:ss.SSS][LEVEL][module][aun_path=...][device_id=...] message
 * - debug=OFF 时仅输出 INFO/WARN/ERROR
 * - debug=ON 时额外输出 DEBUG
 *
 * 接口风格：
 * - prefer template strings: logger.warn(`xxx failed: ${err}`)
 * - compat printf style: logger.warn('xxx %s failed: %s', name, err)
 *   占位符仅支持 %s（按 args 顺序替换，多余的 args 拼到末尾）
 * - error error level supports Error as last param: logger.error('msg', err)
 */

export interface ModuleLogger {
  error(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  info(msg: string, ...args: unknown[]): void;
  debug(msg: string, ...args: unknown[]): void;
  isDebugEnabled?(): boolean;
}

export interface AUNLoggerOptions {
  debug: boolean;
  aunPath?: string;
}

type Level = 'ERROR' | 'WARN' | 'INFO' | 'DEBUG';

const LEVEL_ORDER: Record<Level, number> = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };

function formatMessage(template: string, args: unknown[]): string {
  if (args.length === 0) return template;
  let i = 0;
  let result = '';
  let consumed = 0;
  for (let p = 0; p < template.length; p++) {
    const ch = template[p];
    if (ch === '%' && template[p + 1] === 's' && i < args.length) {
      result += String(args[i++]);
      consumed++;
      p++;
    } else {
      result += ch;
    }
  }
  // 多余的参数拼接到末尾（与 console 行为一致）
  if (i < args.length) {
    const tail = args.slice(i).map((a) => (a instanceof Error ? a.message : String(a))).join(' ');
    if (tail) result += ' ' + tail;
  }
  return result;
}

export class AUNLogger {
  private _debug: boolean;
  private _aunPath: string;
  private _deviceId: string = '-';
  private _aid: string | null = null;
  private _minLevel: number;

  constructor(opts: AUNLoggerOptions) {
    this._debug = opts.debug;
    this._aunPath = String(opts.aunPath || '-');
    this._minLevel = this._debug ? LEVEL_ORDER.DEBUG : LEVEL_ORDER.INFO;
  }

  for(module: string): ModuleLogger {
    return {
      error: (msg, ...args) => this._emit('ERROR', module, msg, args),
      warn:  (msg, ...args) => this._emit('WARN',  module, msg, args),
      info:  (msg, ...args) => this._emit('INFO',  module, msg, args),
      debug: (msg, ...args) => this._emit('DEBUG', module, msg, args),
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
    // 浏览器环境无文件清理，no-op
  }

  private _emit(level: Level, module: string, msg: string, args: unknown[]): void {
    if (LEVEL_ORDER[level] < this._minLevel) return;
    if (level === 'DEBUG' && !this._debug) return;
    const { date, time, ms } = this._now();
    const head = `[${date} ${time}.${ms}][${level}][${module}][aun_path=${this._aunPath || '-'}][device_id=${this._deviceId || '-'}]`;
    const aidPart = this._aid ? ` [${this._aid}]` : '';
    const formatted = formatMessage(msg, args);
    const line = `${head}${aidPart} ${formatted}`;
    // 取最后一个 Error 实例附加到控制台输出，便于浏览器展开 stack
    let errArg: Error | undefined;
    for (let i = args.length - 1; i >= 0; i--) {
      if (args[i] instanceof Error) {
        errArg = args[i] as Error;
        break;
      }
    }

    switch (level) {
      case 'ERROR':
        if (errArg) {
          console.error(line, errArg);
        } else {
          console.error(line);
        }
        break;
      case 'WARN':
        console.warn(line);
        break;
      case 'INFO':
        console.info(line);
        break;
      case 'DEBUG':
        console.debug(line);
        break;
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
