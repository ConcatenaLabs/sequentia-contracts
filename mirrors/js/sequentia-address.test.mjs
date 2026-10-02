// Checks the JavaScript mirror against every template's golden vectors.
//   node --test mirrors/js/sequentia-address.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { derive, templateHash, segwitV1Address } from './sequentia-address.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const templates = join(root, 'templates');

test('every template agrees with its golden vectors', () => {
  const dirs = readdirSync(templates).filter((d) => existsSync(join(templates, d, 'descriptor.json')));
  assert.ok(dirs.length > 0);
  for (const dir of dirs) {
    const d = JSON.parse(readFileSync(join(templates, dir, 'descriptor.json'), 'utf8'));
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
