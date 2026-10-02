// Checks the JavaScript mirror against every template's golden vectors.
//   node --test mirrors/js/sequentia-address.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { derive, templateHash, segwitV1Address, parseDescriptor, tagged, paramBytes } from './sequentia-address.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const templates = join(root, 'templates');

test('every template agrees with its golden vectors', () => {
  const dirs = readdirSync(templates).filter((d) => existsSync(join(templates, d, 'descriptor.json')));
  assert.ok(dirs.length > 0);
  for (const dir of dirs) {
    const d = parseDescriptor(readFileSync(join(templates, dir, 'descriptor.json'), 'utf8'));
    const v = JSON.parse(readFileSync(join(templates, dir, 'vectors.json'), 'utf8'));
    assert.equal(templateHash(d.template), d.template_hash, dir);
    assert.equal(v.template_hash, d.template_hash, dir);
    assert.equal(v.cmr, d.template.program.cmr, dir);
    for (const c of v.addresses) {
      const got = derive(d, c.params);
      const want = Object.fromEntries(Object.keys(got).map((k) => [k, c[k]]));
      assert.deepEqual(got, want, `${dir}: ${c.name}`);
    }
  }
});

test('bech32m matches BIP350', () => {
  const program = Buffer.from('751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6', 'hex');
  assert.equal(segwitV1Address('bc', program),
    'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y');
});

const oneKeyText = () => readFileSync(join(templates, 'one_key', 'descriptor.json'), 'utf8');
const resealed = (edit) => {
  const d = JSON.parse(oneKeyText());
  edit(d.template);
  d.template_hash = templateHash(d.template);
  return d;
};
const X_OF_G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const PK = { PK: X_OF_G };

test('a key path must be declared', () => {
  assert.throws(() => derive(resealed((t) => { t.internal_key = X_OF_G; }), PK), /no key path/);
  derive(resealed((t) => {
    t.internal_key = X_OF_G;
    t.key_path = 'cooperative';
    t.paths.push({ name: 'cooperative', who: 'the holder of the internal key',
      effect: 'Spends the output into any transaction that key signs.' });
  }), PK);
  assert.throws(() => derive(resealed((t) => { t.internal_key = X_OF_G; t.key_path = 'cooperative'; }), PK), /paths/);
  assert.throws(() => derive(resealed((t) => { t.key_path = 'spend'; }), PK), /NUMS/);
});

test('unknown fields are refused', () => {
  assert.throws(() => derive(resealed((t) => { t.expiry = 5; }), PK), /unknown field expiry/);
  assert.throws(() => derive(resealed((t) => { t.program.note = 'x'; }), PK), /unknown field note/);
});

test('integers of 2^53 or more are refused, in the text as well', () => {
  derive(resealed((t) => { t.version = 2 ** 53 - 1; }), PK);
  assert.throws(() => derive(resealed((t) => { t.version = 2 ** 53; }), PK), /2\^53/);
  const text = oneKeyText();
  for (const bad of ['"descriptor": 9007199254740993', '"descriptor": 1.0', '"descriptor": -1', '"descriptor": 1e0']) {
    assert.throws(() => parseDescriptor(text.replace('"descriptor": 1', bad)), /2\^53/, bad);
  }
  // A number inside a string is text, not a number.
  parseDescriptor(text.replace('"transaction": "', '"transaction": "9007199254740993 1.5 -2 \\" '));
});

test('hex with trailing junk is refused', () => {
  const d = resealed(() => {});
  for (const bad of [X_OF_G + 'zz', X_OF_G + '0', X_OF_G.toUpperCase(), X_OF_G.slice(0, -2), X_OF_G.slice(0, 62) + 'zz']) {
    assert.throws(() => derive(d, { PK: bad }), /hex|bytes/, bad);
  }
});

test('the vectors catch an unsorted branch', () => {
  const d = resealed(() => {});
  const v = JSON.parse(readFileSync(join(templates, 'one_key', 'vectors.json'), 'utf8'));
  let wrong = 0;
  for (const c of v.addresses) {
    const leaf = Buffer.from(tagged('TapData', paramBytes(d.template, c.params))).toString('hex');
    const unsorted = Buffer.from(tagged('TapBranch/elements', Buffer.from(leaf + c.program_leaf, 'hex'))).toString('hex');
    if (unsorted !== c.merkle_root) wrong++;
  }
  assert.ok(wrong >= 2, `${wrong}`);
});
