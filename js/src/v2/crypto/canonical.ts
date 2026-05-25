/**
 * AUN E2EE V2: Canonical JSON 序列化
 *
 * 规范引用: §10.2
 * 规则:
 * - 键递归按 Unicode code point 排序
 * - UTF-8 直出（非 ASCII 不转义）
 * - 数值无前导零、不科学计数法
 * - 字符串最小转义（仅 " \\ \b \f \n \r \t，其它控制字符 \u00XX）
 * - 无空格分隔（紧凑格式）
 * - null / true / false 字面
 * - 数组顺序保留（不排序）
 *
 * 输出: UTF-8 编码的 Uint8Array
 */

const encoder = new TextEncoder();
const MAX_SAFE_JSON_INTEGER = 9007199254740991;

/**
 * 将任意 JS 值序列化为 Canonical JSON 的 UTF-8 字节。
 * 所有 SDK 的输出必须字节级一致。
 */
export function canonicalJson(obj: unknown): Uint8Array {
  return encoder.encode(serialize(obj));
}

function serialize(obj: unknown): string {
  if (obj === null) return 'null';
  if (obj === true) return 'true';
  if (obj === false) return 'false';

  if (typeof obj === 'number') {
    return serializeNumber(obj);
  }
  if (typeof obj === 'string') {
    return serializeString(obj);
  }
  if (Array.isArray(obj)) {
    return serializeArray(obj);
  }
  if (typeof obj === 'object') {
    return serializeObject(obj as Record<string, unknown>);
  }
  throw new TypeError(`canonicalJson: unsupported type ${typeof obj}`);
}

function serializeNumber(n: number): string {
  if (!isFinite(n)) {
    throw new RangeError('canonicalJson: Infinity and NaN not allowed');
  }
  if (Object.is(n, -0)) return '0';

  if (Number.isInteger(n)) {
    if (Math.abs(n) > MAX_SAFE_JSON_INTEGER) {
      throw new RangeError(`canonicalJson: integer outside safe range ${n}`);
    }
    return String(n);
  }
  return expandExponent(String(n));
}

function expandExponent(s: string): string {
  if (!/[eE]/.test(s)) return s;

  const match = /^(-?)(\d+)(?:\.(\d+))?[eE]([+-]?\d+)$/.exec(s);
  if (!match) {
    throw new TypeError(`canonicalJson: invalid number ${s}`);
  }
  const sign = match[1] ?? '';
  const intPart = match[2] ?? '';
  const fracPart = match[3] ?? '';
  const exp = Number(match[4]);
  const digits = intPart + fracPart;
  const point = intPart.length + exp;

  if (point <= 0) {
    return `${sign}0.${'0'.repeat(-point)}${digits}`;
  }
  if (point >= digits.length) {
    return `${sign}${digits}${'0'.repeat(point - digits.length)}`;
  }
  return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
}

function serializeString(s: string): string {
  let result = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const code = s.charCodeAt(i);

    if (ch === '"') {
      result += '\\"';
    } else if (ch === '\\') {
      result += '\\\\';
    } else if (ch === '\b') {
      result += '\\b';
    } else if (ch === '\f') {
      result += '\\f';
    } else if (ch === '\n') {
      result += '\\n';
    } else if (ch === '\r') {
      result += '\\r';
    } else if (ch === '\t') {
      result += '\\t';
    } else if (code < 0x20) {
      // 其它控制字符用 \u00XX
      result += '\\u' + code.toString(16).padStart(4, '0');
    } else {
      // 非 ASCII 直出（UTF-8 直出）
      result += ch;
    }
  }
  result += '"';
  return result;
}

function serializeArray(arr: unknown[]): string {
  const items = arr.map((item) => serialize(item));
  return '[' + items.join(',') + ']';
}

function serializeObject(obj: Record<string, unknown>): string {
  const sortedKeys = Object.keys(obj).sort(compareCodePoints);
  const pairs = sortedKeys.map(
    (key) => serializeString(key) + ':' + serialize(obj[key])
  );
  return '{' + pairs.join(',') + '}';
}

function compareCodePoints(a: string, b: string): number {
  const ac = Array.from(a);
  const bc = Array.from(b);
  const n = Math.min(ac.length, bc.length);
  for (let i = 0; i < n; i++) {
    const av = ac[i].codePointAt(0) ?? 0;
    const bv = bc[i].codePointAt(0) ?? 0;
    if (av !== bv) return av - bv;
  }
  return ac.length - bc.length;
}
