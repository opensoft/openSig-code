// SPDX-License-Identifier: Apache-2.0
//
// VB-01: the shipped verifier imports only node:* and src/verifier/**, so it
// shares no code with the signer (src/cryptograph/) or the parser (src/pdf/),
// and never imports the oracle. T014's tests reach the oracle only through the
// seven public exports of the T012 line.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { listFiles, readSpecifiers, scanFile } from './helpers/import-scan.mjs';

const VERIFIER_ROOT = fileURLToPath(new URL('../../../src/verifier/', import.meta.url));
const TESTS_ROOT = fileURLToPath(new URL('./', import.meta.url));

const ORACLE_EXPORTS = Object.freeze({
  '../../oracle/lib/oracle.mjs': ['ORACLE', 'checkPdf'],
  '../../oracle/lib/corpus.mjs': ['buildCorpus', 'loadCaseManifest', 'prepareMaterial'],
  '../../oracle/lib/openssl.mjs': ['createWorkDir', 'removeWorkDir'],
});

test('[VB-01] src/verifier imports only node:* and src/verifier/**, from the allowlist node:buffer, node:crypto, node:zlib', () => {
  const files = listFiles(VERIFIER_ROOT);
  assert.ok(files.length >= 8, 'the verifier module is present');
  assert.ok(files.includes(join(VERIFIER_ROOT, 'index.ts')), 'index.ts is the public surface');
  const strays = files.filter((file) => !file.endsWith('.ts')).map((file) => relative(VERIFIER_ROOT, file));
  assert.deepEqual(strays, [], 'src/verifier holds only .ts modules');
  const violations = files.flatMap((file) => scanFile(file, readFileSync(file, 'utf8'), VERIFIER_ROOT));
  assert.deepEqual(violations, []);
  const seen = new Set(files.flatMap((file) => readSpecifiers(readFileSync(file, 'utf8')).specifiers));
  assert.ok([...seen].some((s) => s.startsWith('./')), 'the scanner read the relative imports');
  assert.ok(seen.has('node:crypto'), 'the scanner read the node: imports');
});

test('[VB-01] the boundary scanner flags every forbidden form (negative control)', () => {
  const probe = join(VERIFIER_ROOT, 'probe.ts');
  const forbidden = [
    "import { buildDetachedSignedData } from '../cryptograph/cms/index.ts';",
    "import { composeSealRevision } from '../cryptograph/compose/index.ts';",
    "import { parsePdf } from '../pdf/service.ts';",
    "import {\n  canonicalize,\n} from '../domain/canonical/index.ts';",
    // Split so the self-scan in the third test never reads these as statements.
    "export * from '../../tests/integrity/" + "oracle/lib/oracle.mjs';",
    "export { checkPdf } from '../../tests/integrity/" + "oracle/lib/oracle.mjs';",
    "import tls from 'node:tls';",
    "import { spawnSync } from 'node:child_process';",
    "import { readFileSync } from 'node:fs';",
    "import crypto from 'crypto';",
    "import x from './der.js';",
    "import './side-effect.ts';",
    "const m = await import('node:crypto');",
    "const r = createRequire(import.meta.url);",
    "const roots = tls.rootCertificates;",
    "const roots = getCACertificates('system');",
    "const now = Date.now();",
    "const home = process.env.HOME;",
  ];
  for (const source of forbidden) {
    assert.ok(scanFile(probe, source, VERIFIER_ROOT).length > 0, `not flagged: ${source}`);
  }
  const allowed = "import { createHash } from 'node:crypto';\nimport { readTlv, type Tlv } from './der.ts';\nexport { VERIFIER } from './report.ts';\n";
  assert.deepEqual(scanFile(probe, allowed, VERIFIER_ROOT), []);
  const commented = "// import tls from 'node:tls';\n/* import { x } from '../pdf/service.ts'; */\nimport { createHash } from 'node:crypto';\n";
  assert.deepEqual(scanFile(probe, commented, VERIFIER_ROOT), []);
});

test('[VB-01] T014 tests reach the T012 oracle only through its seven public exports', () => {
  const files = listFiles(TESTS_ROOT).filter((file) => file.endsWith('.mjs'));
  const gateway = join(TESTS_ROOT, 'helpers', 'oracle.mjs');
  assert.ok(files.includes(gateway));
  for (const file of files) {
    if (file === gateway) continue;
    const { specifiers } = readSpecifiers(readFileSync(file, 'utf8'));
    const reaching = specifiers.filter((s) => s.includes('/oracle/') || s.includes('integrity/oracle'));
    assert.deepEqual(reaching, [], `${relative(TESTS_ROOT, file)} names the oracle directly`);
  }
  const gatewaySource = readFileSync(gateway, 'utf8');
  const exportsFound = {};
  for (const match of gatewaySource.matchAll(/export\s*\{([^}]*)\}\s*from\s*'([^']+)'/g)) {
    exportsFound[match[2]] = match[1].split(',').map((name) => name.trim()).filter(Boolean).sort();
  }
  const expected = Object.fromEntries(Object.entries(ORACLE_EXPORTS).map(([k, v]) => [k, [...v].sort()]));
  assert.deepEqual(exportsFound, expected);
  const { specifiers } = readSpecifiers(gatewaySource);
  assert.deepEqual([...specifiers].sort(), Object.keys(ORACLE_EXPORTS).sort());
});
