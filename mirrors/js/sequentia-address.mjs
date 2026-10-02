// Address derivation for fixed-root contract descriptors, with no compiler.
//
// A version 1 descriptor's output is
//
//     P2TR(internal_key, TapBranch(TapLeaf_0xbe(CMR), H_TapData(param_bytes)))
//
// so an instance's address takes one hash and one curve tweak. This module
// needs only Node's built-in crypto. docs/descriptor.md is the specification.
import { createHash } from 'node:crypto';

const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
];
const LEAF_VERSION_SIMPLICITY = 0xbe;
const WIDTHS = { u8: 1, u16: 2, u32: 4, u64: 8, u128: 16, u256: 32, Pubkey: 32 };
const NUMS_KEY = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';

const sha256 = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const hex = (b) => Buffer.from(b).toString('hex');

// Lowercase hex, of exactly `width` bytes when given. Buffer.from(s, 'hex')
// stops at the first character that is not hex and drops it silently, so it
// is not used to read input.
export function unhex(s, width) {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-f]*$/.test(s)) {
    throw new Error(`not lowercase hex: ${JSON.stringify(s)}`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  if (width !== undefined && out.length !== width) {
    throw new Error(`${out.length} bytes where ${width} are needed`);
  }
  return out;
}

// The shape of a version 1 descriptor: every field, its type, and which are
// optional (a '?' suffix). Any other field is refused.
const STR = 'str';
const INT = 'int';
const TEMPLATE = {
  name: STR, version: INT, summary: STR, layout: STR, internal_key: STR, 'key_path?': STR,
  program: {
    source: STR, source_sha256: STR, cmr: STR,
    compiler: { name: STR, version: STR },
    witness: [{ name: STR, type: STR, source: STR }],
  },
  params: [{ name: STR, type: STR, role: STR, label: STR }],
  paths: [{ name: STR, who: STR, effect: STR }],
};
const DESCRIPTOR = {
  descriptor: INT, template: TEMPLATE, template_hash: STR,
  chains: [{ name: STR, genesis: 'str|null', bech32_hrp: STR }],
  'measured?': 'any',
};

const isInt = (v) => Number.isSafeInteger(v) && v >= 0;

function checkShape(value, shape, at) {
  if (shape === 'any') return;
  if (Array.isArray(shape)) {
    if (!Array.isArray(value)) throw new Error(`${at} is not an array`);
    value.forEach((item, i) => checkShape(item, shape[0], `${at}[${i}]`));
  } else if (typeof shape === 'object') {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${at} is not an object`);
    const fields = Object.fromEntries(Object.keys(shape).map((k) => [k.replace(/\?$/, ''), k]));
    for (const k of Object.keys(value)) {
      if (!(k in fields)) throw new Error(`${at}: unknown field ${k}`);
    }
    for (const [k, key] of Object.entries(fields)) {
      if (k in value) checkShape(value[k], shape[key], `${at}.${k}`);
      else if (!key.endsWith('?')) throw new Error(`${at}: missing field ${k}`);
    }
  } else if (shape === INT) {
    if (!isInt(value)) throw new Error(`${at}: ${value} is not an integer in [0, 2^53)`);
  } else if (shape === STR) {
    if (typeof value !== 'string') throw new Error(`${at} is not a string`);
  } else if (shape === 'str|null') {
    if (value !== null && typeof value !== 'string') throw new Error(`${at} is not a string or null`);
  }
}

function checkNumbers(value, at) {
  if (typeof value === 'number') {
    if (!isInt(value)) throw new Error(`${at}: ${value} is not an integer in [0, 2^53)`);
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => checkNumbers(v, `${at}[${i}]`));
  } else if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) checkNumbers(v, `${at}.${k}`);
  }
}

// Refuse a descriptor whose shape is not version 1's, that holds a number other
// than an integer in [0, 2^53), or whose key path is not declared.
export function checkDescriptor(d) {
  checkNumbers(d, 'descriptor');
  checkShape(d, DESCRIPTOR, 'descriptor');
  const t = d.template;
  if (d.descriptor !== 1) throw new Error(`descriptor version ${d.descriptor} is not 1`);
  if (t.layout !== 'fixed-root') throw new Error(`layout ${t.layout} is not fixed-root`);
  if (templateHash(t) !== d.template_hash) throw new Error('template_hash does not match the template');
  const nums = t.internal_key === NUMS_KEY;
  if (nums && 'key_path' in t) throw new Error('key_path is declared, but the internal key is the NUMS key');
  if (!nums) {
    if (!('key_path' in t)) throw new Error('the internal key is not the NUMS key and the template declares no key path');
    if (!t.paths.some((p) => p.name === t.key_path)) {
      throw new Error(`key_path ${t.key_path} is not one of the template's paths`);
    }
  }
  for (const p of t.params) {
    if (!(p.type in WIDTHS)) throw new Error(`parameter ${p.name}: type ${p.type} is not allowed`);
  }
}

// Read a descriptor from JSON text. JSON.parse reads 9007199254740993 as
// 9007199254740992 and 1.0 as 1, so every number token is checked in the text
// itself before parsing: only integers in [0, 2^53) are allowed.
export function parseDescriptor(text) {
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === '\\') i++;
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
    } else if (c === '-' || (c >= '0' && c <= '9')) {
      const m = /^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
      const token = m ? m[0] : c;
      if (!/^[0-9]+$/.test(token) || BigInt(token) >= 2n ** 53n) {
        throw new Error(`${token} is not an integer in [0, 2^53)`);
      }
      i += token.length - 1;
    }
  }
  const d = JSON.parse(text);
  checkDescriptor(d);
  return d;
}
const concat = (...parts) => new Uint8Array(Buffer.concat(parts.map((p) => Buffer.from(p))));

export function tagged(tag, msg) {
  const t = sha256(Buffer.from(tag, 'utf8'));
  return sha256(concat(t, t, msg));
}

// Object keys sorted, no whitespace. Descriptors are printable ASCII.
export function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

export function templateHash(template) {
  return hex(sha256(Buffer.from(canonicalJson(template), 'utf8')));
}

export function paramBytes(template, params) {
  if (Object.keys(params).length !== template.params.length) {
    throw new Error('wrong number of parameters');
  }
  return concat(...template.params.map((p) => {
    if (!(p.name in params)) throw new Error(`parameter ${p.name} is missing`);
    try {
      return unhex(params[p.name], WIDTHS[p.type]);
    } catch (e) {
      throw new Error(`parameter ${p.name}: ${e.message}`);
    }
  }));
}

const mod = (a, m = P) => ((a % m) + m) % m;
function inv(a) {
  let [t, newT, r, newR] = [0n, 1n, P, mod(a)];
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  return mod(t);
}
function add(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  if (a[0] === b[0] && mod(a[1] + b[1]) === 0n) return null;
  const lam = a[0] === b[0] && a[1] === b[1]
    ? mod(3n * a[0] * a[0] * inv(2n * a[1]))
    : mod((b[1] - a[1]) * inv(b[0] - a[0]));
  const x = mod(lam * lam - a[0] - b[0]);
  return [x, mod(lam * (a[0] - x) - a[1])];
}
function mul(k, pt) {
  let acc = null;
  while (k > 0n) {
    if (k & 1n) acc = add(acc, pt);
    pt = add(pt, pt);
    k >>= 1n;
  }
  return acc;
}
function pow(b, e) {
  let r = 1n;
  b = mod(b);
  while (e > 0n) {
    if (e & 1n) r = mod(r * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return r;
}
function liftX(x) {
  const c = mod(x ** 3n + 7n);
  const y = pow(c, (P + 1n) / 4n);
  if (mod(y * y) !== c) throw new Error('not a point');
  return [x, y % 2n === 0n ? y : P - y];
}
const big = (b) => BigInt('0x' + hex(b));
const bytes32 = (n) => unhex(n.toString(16).padStart(64, '0'), 32);

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(values) {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ gen[i]) >>> 0;
  }
  return chk;
}

// bech32m (BIP350), witness version 1.
export function segwitV1Address(hrp, program) {
  const data = [1];
  let acc = 0;
  let bits = 0;
  for (const b of program) {
    acc = ((acc << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data.push((acc >> bits) & 31);
    }
  }
  if (bits) data.push((acc << (5 - bits)) & 31);
  const hrpExp = [...hrp].map((c) => c.charCodeAt(0) >> 5)
    .concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
  const pm = (polymod(hrpExp.concat(data, [0, 0, 0, 0, 0, 0])) ^ 0x2bc830a3) >>> 0;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (pm >>> (5 * (5 - i))) & 31);
  return hrp + '1' + data.concat(checksum).map((d) => CHARSET[d]).join('');
}

export function derive(descriptor, params) {
  checkDescriptor(descriptor);
  const t = descriptor.template;
  const data = paramBytes(t, params);
  const cmr = unhex(t.program.cmr, 32);
  const dataLeaf = tagged('TapData', data);
  const programLeaf = tagged('TapLeaf/elements', concat([LEAF_VERSION_SIMPLICITY, cmr.length], cmr));
  const [lo, hi] = Buffer.compare(Buffer.from(dataLeaf), Buffer.from(programLeaf)) < 0
    ? [dataLeaf, programLeaf] : [programLeaf, dataLeaf];
  const root = tagged('TapBranch/elements', concat(lo, hi));
  const internal = unhex(t.internal_key, 32);
  const tweak = tagged('TapTweak/elements', concat(internal, root));
  const q = add(liftX(big(internal)), mul(big(tweak) % N, G));
  const outputKey = bytes32(q[0]);
  const address = {};
  for (const c of descriptor.chains) address[c.name] = segwitV1Address(c.bech32_hrp, outputKey);
  return {
    param_bytes: hex(data),
    data_leaf: hex(dataLeaf),
    program_leaf: hex(programLeaf),
    merkle_root: hex(root),
    tweak: hex(tweak),
    output_key: hex(outputKey),
    output_key_parity: Number(q[1] & 1n),
    script_pubkey: '5120' + hex(outputKey),
    address,
  };
}
