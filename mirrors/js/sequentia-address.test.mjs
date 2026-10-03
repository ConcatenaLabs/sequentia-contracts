// Checks the JavaScript mirror against every template's golden vectors, and
// against the refusals every reader must make (mirrors/fixtures/refusals.json).
//   node --test mirrors/js/sequentia-address.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  derive, templateHash, segwitV1Address, parseDescriptor, tagged, paramBytes, model, scriptNum,
} from './sequentia-address.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const fixtures = join(root, 'mirrors', 'fixtures');
const read = (p) => readFileSync(p, 'utf8');

const descriptorDirs = () => [join(root, 'templates'), fixtures]
  .flatMap((base) => readdirSync(base).map((d) => join(base, d)))
  .filter((d) => existsSync(join(d, 'descriptor.json')))
  .sort();

test('every template and fixture agrees with its golden vectors', () => {
  const dirs = descriptorDirs();
  assert.ok(dirs.some((d) => d.endsWith('one_key_exit')));
  for (const dir of dirs) {
    const d = parseDescriptor(read(join(dir, 'descriptor.json')));
    const v = JSON.parse(read(join(dir, 'vectors.json')));
    assert.equal(templateHash(d.template), d.template_hash, dir);
    assert.equal(v.template_hash, d.template_hash, dir);
    assert.equal(v.vectors, d.descriptor, dir);
    if (d.descriptor === 1) assert.equal(v.cmr, d.template.program.cmr, dir);
    for (const c of v.addresses) {
      const got = derive(d, c.params, c.slots ?? {});
      const want = Object.fromEntries(Object.keys(got).map((k) => [k, c[k]]));
      assert.deepEqual(got, want, `${dir}: ${c.name}`);
      const rest = Object.keys(c).filter((k) => !(k in got)).sort();
      assert.deepEqual(rest, d.descriptor === 1 ? ['name', 'params'] : ['name', 'params', 'slots'], dir);
    }
  }
});

test('bech32m matches BIP350', () => {
  const program = Buffer.from('751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6', 'hex');
  assert.equal(segwitV1Address('bc', program),
    'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y');
});

test('a version 1 template is its version 2 tree', () => {
  const v1 = JSON.parse(read(join(root, 'templates', 'one_key', 'vectors.json'))).addresses;
  const v2 = JSON.parse(read(join(fixtures, 'one_key_as_v2', 'vectors.json'))).addresses;
  assert.equal(v1.length, v2.length);
  v1.forEach((a, i) => {
    const b = v2[i];
    assert.deepEqual(a.params, b.params);
    assert.deepEqual(a.address, b.address);
    assert.equal(a.data_leaf, b.leaves.params.hash);
    assert.equal(a.program_leaf, b.leaves.program.hash);
    assert.equal(a.param_bytes, b.leaves.params.data);
  });
});

function applyEdit(doc, op) {
  let target = doc;
  for (const k of op.at.slice(0, -1)) target = target[k];
  const last = op.at[op.at.length - 1];
  if ('set' in op) {
    // A plain assignment of "__proto__" would set the prototype; define it.
    Object.defineProperty(target, last, { value: op.set, enumerable: true, writable: true, configurable: true });
  } else if ('delete' in op) {
    if (Array.isArray(target)) target.splice(last, 1);
    else delete target[last];
  } else if ('append' in op) target[last].push(op.append);
  else if ('suffix' in op) target[last] += op.suffix;
  else throw new Error(`unknown edit ${JSON.stringify(op)}`);
}

function refusalText(c) {
  let text = read(join(root, c.base, 'descriptor.json'));
  if (c.text) {
    for (const [from, to] of c.text) {
      assert.ok(text.includes(from), `${c.name}: ${from}`);
      text = text.replace(from, to);
    }
    return text;
  }
  const d = JSON.parse(text);
  for (const op of c.edit) applyEdit(d, op);
  if (c.reseal !== false) d.template_hash = templateHash(d.template);
  return JSON.stringify(d, null, 2);
}

test('every refusal is made, for its reason', () => {
  const { cases } = JSON.parse(read(join(fixtures, 'refusals.json')));
  assert.ok(cases.length > 50);
  for (const c of cases) {
    const text = refusalText(c);
    if (c.accept) {
      parseDescriptor(text);
      continue;
    }
    let error;
    try {
      const d = parseDescriptor(text);
      if (!c.derive) throw new Error(`${c.name}: ACCEPTED`);
      derive(d, c.derive.params, c.derive.slots);
      throw new Error(`${c.name}: derived`);
    } catch (e) {
      error = e.message;
    }
    assert.ok(error.includes(c.expect), `${c.name}: ${error}`);
  }
});

const X_OF_G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const oneKey = () => JSON.parse(read(join(root, 'templates', 'one_key', 'descriptor.json')));
const resealed = (edit) => {
  const d = oneKey();
  edit(d.template);
  d.template_hash = templateHash(d.template);
  return d;
};

test('a version 1 key path must be declared', () => {
  const PK = { PK: X_OF_G };
  assert.throws(() => derive(resealed((t) => { t.internal_key = X_OF_G; }), PK), /no key path/);
  derive(resealed((t) => {
    t.internal_key = X_OF_G;
    t.key_path = 'cooperative';
    t.paths.push({ name: 'cooperative', who: 'the holder of the internal key',
      effect: 'Spends the output into any transaction that key signs.' });
  }), PK);
  assert.throws(() => derive(resealed((t) => { t.internal_key = X_OF_G; t.key_path = 'cooperative'; }), PK), /paths/);
});

test('a number inside a string is text, not a number', () => {
  const text = read(join(root, 'templates', 'one_key', 'descriptor.json'));
  parseDescriptor(text.replace('"transaction": "', '"transaction": "9007199254740993 1.5 -2 \\" '));
});

test('hex with trailing junk is refused', () => {
  const d = resealed(() => {});
  for (const bad of [X_OF_G + 'zz', X_OF_G + '0', X_OF_G.toUpperCase(), X_OF_G.slice(0, -2), X_OF_G.slice(0, 62) + 'zz']) {
    assert.throws(() => derive(d, { PK: bad }), /hex|bytes/, bad);
  }
});

const unsortedRoot = (node, leaves) => (node.kind === 'branch'
  ? tagged('TapBranch/elements', Buffer.concat([unsortedRoot(node.a, leaves), unsortedRoot(node.b, leaves)]))
  : Buffer.from(leaves[node.name].hash, 'hex'));

test('the vectors catch an unsorted branch and a dropped parity', () => {
  for (const dir of descriptorDirs()) {
    const d = parseDescriptor(read(join(dir, 'descriptor.json')));
    const v = JSON.parse(read(join(dir, 'vectors.json')));
    if (d.descriptor === 1) {
      let wrong = 0;
      for (const c of v.addresses) {
        const leaf = Buffer.from(tagged('TapData', paramBytes(d.template, c.params))).toString('hex');
        const unsorted = Buffer.from(tagged('TapBranch/elements', Buffer.from(leaf + c.program_leaf, 'hex'))).toString('hex');
        if (unsorted !== c.merkle_root) wrong++;
      }
      assert.ok(wrong >= 2, `${dir}: ${wrong}`);
      continue;
    }
    const tree = model(d).tree;
    const wrong = v.addresses.filter((c) => Buffer.from(unsortedRoot(tree, c.leaves)).toString('hex') !== c.merkle_root);
    assert.ok(wrong.length >= 2, dir);
    const odd = v.addresses.filter((c) => c.output_key_parity === 1);
    assert.ok(odd.length > 0, dir);
    for (const c of odd) {
      for (const leaf of Object.values(c.leaves)) {
        if (leaf.control_block) assert.equal(parseInt(leaf.control_block.slice(0, 2), 16) & 1, 1);
      }
    }
  }
});

test('a script number is minimal', () => {
  assert.equal(Buffer.from(scriptNum(0n)).toString('hex'), '00');
  assert.equal(Buffer.from(scriptNum(16n)).toString('hex'), '60');
  assert.equal(Buffer.from(scriptNum(17n)).toString('hex'), '0111');
  assert.equal(Buffer.from(scriptNum(0x80n)).toString('hex'), '028000');
  assert.equal(Buffer.from(scriptNum(0x400002n)).toString('hex'), '03020040');
});
