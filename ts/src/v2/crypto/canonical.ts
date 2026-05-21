/**
 * Canonical JSON 序列化 — AUN E2EE V2 协议要求所有 SDK 输出字节级一致。
 *
 * 规则：
 * - 对象键递归字典序排序
 * - UTF-8 直出（非 ASCII 字符不转义）
 * - 数值：整数无小数点，浮点数无前导零、不用科学计数法
 * - 字符串最小转义：仅 " \ \b \f \n \r \t，其它控制字符 \u00XX
 * - 紧凑格式（无空格）
 * - null / true / false 字面量
 * - 数组顺序保留
 */

const encoder = new TextEncoder();

/**
 * 将任意 JSON 值序列化为 canonical JSON 的 UTF-8 字节。
 */
export function canonicalJson(obj: unknown): Uint8Array {
  return encoder.encode(canonicalStringify(obj));
}

/**
 * 将任意 JSON 值序列化为 canonical JSON 字符串。
 */
export function canonicalStringify(value: unknown): string {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';

  if (typeof value === 'number') {
    return formatNumber(value);
  }

  if (typeof value === 'string') {
    return escapeString(value);
  }

  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalStringify(item));
    return '[' + items.join(',') + ']';
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const pairs = keys.map(
      (k) =>
        escapeString(k) +
        ':' +
        canonicalStringify((value as Record<string, unknown>)[k]),
    );
    return '{' + pairs.join(',') + '}';
  }

  // undefined 等不可序列化类型 — 按 JSON 规范不应出现
  throw new Error(`canonicalJson: unsupported type ${typeof value}`);
}

function formatNumber(n: number): string {
  if (!isFinite(n)) {
    throw new Error(`canonicalJson: cannot serialize ${n}`);
  }
  // 整数输出不带小数点
  if (Number.isInteger(n)) {
    // 用 toFixed(0) 避免科学计数法（如 1e21）
    // 但 toFixed 对超大数会失败，改用条件判断
    if (Math.abs(n) < 1e21) {
      return n.toFixed(0);
    }
    // 超大整数：toString 可能用科学计数法，需要手动展开
    return bigIntegerToString(n);
  }
  // 浮点数：使用 toString 输出（不用科学计数法的范围内）
  return n.toString();
}

/**
 * 将超大整数（>= 1e21）转为不带科学计数法的字符串。
 */
function bigIntegerToString(n: number): string {
  // 利用 BigInt 来避免科学计数法
  return BigInt(n).toString();
}

/**
 * 最小转义字符串序列化。
 * 仅转义：" \ \b \f \n \r \t 和其它控制字符（U+0000..U+001F）用 \u00XX。
 * 非 ASCII 字符直接 UTF-8 输出，不转义。
 */
function escapeString(s: string): string {
  let result = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s.charCodeAt(i);
    switch (ch) {
      case 0x22: // "
        result += '\\"';
        break;
      case 0x5c: // \
        result += '\\\\';
        break;
      case 0x08: // \b
        result += '\\b';
        break;
      case 0x0c: // \f
        result += '\\f';
        break;
      case 0x0a: // \n
        result += '\\n';
        break;
      case 0x0d: // \r
        result += '\\r';
        break;
      case 0x09: // \t
        result += '\\t';
        break;
      default:
        if (ch < 0x20) {
          // 其它控制字符用 \u00XX
          result += '\\u' + ch.toString(16).padStart(4, '0');
        } else {
          // 普通字符（含非 ASCII）直接输出
          result += s[i];
        }
    }
  }
  result += '"';
  return result;
}
