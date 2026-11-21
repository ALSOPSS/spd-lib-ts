/**
 * Value (de)serialization for SPD entries — the type-tagged string form that
 * is padded, compressed and encrypted per entry (see SPEC.md §8). Pure
 * functions, no SPD state: extracted from SPD.ts so the format's value
 * encoding can be read and tested on its own.
 */
import type { SupportedDataType } from '../types.js';

export function detectType(value: unknown): SupportedDataType | undefined {
  const typeMap: Record<string, SupportedDataType> = {
    '[object Array]':          'Array',
    '[object Uint8Array]':     'Uint8Array',
    '[object Uint16Array]':    'Uint16Array',
    '[object Uint32Array]':    'Uint32Array',
    '[object BigInt64Array]':  'BigInt64Array',
    '[object BigUint64Array]': 'BigUint64Array',
    '[object Float32Array]':   'Float32Array',
    '[object Float64Array]':   'Float64Array',
    '[object Map]':            'Map',
    '[object Set]':            'Set',
    '[object Date]':           'Date',
    '[object RegExp]':         'RegExp',
    '[object Error]':          'Error',
  };
  return typeMap[Object.prototype.toString.call(value)];
}

export function isTypedArray(type: SupportedDataType): boolean {
  return ['Uint8Array','Uint16Array','Uint32Array','BigInt64Array','BigUint64Array','Float32Array','Float64Array'].includes(type);
}

export function isCollectionType(type: SupportedDataType): boolean {
  return ['Map', 'Set'].includes(type);
}

// synchronous — no real async work inside; was `async` only by signature
export function serializeValue(value: unknown): [string, SupportedDataType] {
  // null — explicit type so roundtrip is lossless
  if (value === null) {
    return ['null', 'object'];
  }

  const primitiveType = typeof value;
  if (primitiveType === 'string' || primitiveType === 'number' || primitiveType === 'boolean') {
    return [String(value), primitiveType as SupportedDataType];
  }

  if (typeof value === 'object') {
    const detectedType = detectType(value);

    if (detectedType === 'Array') {
      return [JSON.stringify(value), 'Array'];
    }

    if (detectedType && isTypedArray(detectedType)) {
      // BigInt typed arrays (BigInt64Array, BigUint64Array) cannot be JSON-serialized directly;
      // convert elements to strings to preserve full precision.
      const isBigIntArray = detectedType === 'BigInt64Array' || detectedType === 'BigUint64Array';
      const arr = Array.from(value as Iterable<unknown>);
      // JSON has no Infinity/NaN (they stringify to null and came back as 0):
      // carry non-finite floats as their string forms, which Number() restores.
      const isFloatArray = detectedType === 'Float32Array' || detectedType === 'Float64Array';
      const enc = isBigIntArray ? arr.map(String)
        : isFloatArray ? arr.map((x) => (Number.isFinite(x as number) ? x : String(x)))
        : arr;
      return [JSON.stringify(enc), detectedType];
    }

    if (detectedType && isCollectionType(detectedType)) {
      return [JSON.stringify([...(value as Iterable<unknown>)]), detectedType];
    }

    if (detectedType === 'RegExp') {
      const re = value as RegExp;
      return [JSON.stringify({ source: re.source, flags: re.flags }), 'RegExp'];
    }

    if (detectedType === 'Date') {
      return [(value as Date).toISOString(), 'Date'];
    }

    if (detectedType === 'Error') {
      return [(value as Error).message, 'Error'];
    }

    return [JSON.stringify(value), 'object'];
  }

  return [JSON.stringify(value), 'object'];
}

// synchronous — no real async work inside; was `async` only by signature
export function deserializeValue(value: string, type: SupportedDataType): unknown {
  try {
    switch (type) {
      case 'string':
        if (typeof value !== 'string') throw new Error('Expected string');
        return value;

      case 'number': {
        const num = parseFloat(value);
        if (isNaN(num)) throw new Error('Invalid number');
        return num;
      }

      case 'boolean':
        if (value !== 'true' && value !== 'false') throw new Error('Invalid boolean');
        return value === 'true';

      case 'object': {
        // 'null' is the one JSON-serialised null sentinel we store as 'object'
        const parsed = JSON.parse(value);
        if (parsed !== null && (typeof parsed !== 'object')) throw new Error('Invalid object');
        return parsed;
      }

      case 'Array': {
        const parsed = JSON.parse(value);
        if (!Array.isArray(parsed)) throw new Error('Invalid Array');
        return parsed;
      }

      case 'Uint8Array':    return new Uint8Array(JSON.parse(value));
      case 'Uint16Array':   return new Uint16Array(JSON.parse(value));
      case 'Uint32Array':   return new Uint32Array(JSON.parse(value));
      case 'BigInt64Array':  return new BigInt64Array((JSON.parse(value) as string[]).map(BigInt));
      case 'BigUint64Array': return new BigUint64Array((JSON.parse(value) as string[]).map(BigInt));
      case 'Float32Array':  return new Float32Array((JSON.parse(value) as unknown[]).map((x) => (x === null ? 0 : Number(x))));
      case 'Float64Array':  return new Float64Array((JSON.parse(value) as unknown[]).map((x) => (x === null ? 0 : Number(x))));

      case 'Map': return new Map(JSON.parse(value));
      case 'Set': return new Set(JSON.parse(value));

      case 'Date': {
        const date = new Date(value);
        if (isNaN(date.getTime())) throw new Error('Invalid Date');
        return date;
      }

      case 'RegExp': {
        const { source, flags } = JSON.parse(value) as { source: string; flags: string };
        if (typeof source !== 'string' || typeof flags !== 'string') {
          throw new Error('Invalid RegExp data');
        }
        if (!/^[dgimsuy]*$/.test(flags)) {
          throw new Error(`Invalid RegExp flags: ${flags}`);
        }
        return new RegExp(source, flags);
      }

      case 'Error':
        return new Error(value);

      default:
        throw new Error(`Unknown or unsupported type: ${type}`);
    }
  } catch (error) {
    throw new Error(
      `Failed to restore data of type "${type}": ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}
