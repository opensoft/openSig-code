// SPDX-License-Identifier: Apache-2.0
//
// no-secrets gate (T026), cases NS-01..NS-07.
//
// Every positive sample is generated at test runtime inside a temporary Git
// repository (keys from node:crypto, a database from node:sqlite, image and
// PKCS#12 bytes built from their structural descriptions). No sample exists in
// the source tree; the last test scans this repository and requires it clean.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { crc32, deflateSync } from 'node:zlib';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCANNER = join(REPO_ROOT, 'scripts', 'no-secrets.mjs');
const RULE_NAMES = ['private-key-pem', 'pkcs12-content', 'sqlite-database', 'fixture-image', 'env-file', 'secret-assignment'];

// Git runs isolated from the developer's global and system configuration.
const GIT_ENV = (() => {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('GIT_')) delete env[key];
  return {
    ...env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Synthetic Author',
    GIT_AUTHOR_EMAIL: 'author@example.test',
    GIT_COMMITTER_NAME: 'Synthetic Committer',
    GIT_COMMITTER_EMAIL: 'committer@example.test',
  };
})();

const scratch = [];
after(() => {
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

function git(repo, ...args) {
  const run = spawnSync('git', args, { cwd: repo, env: GIT_ENV, encoding: 'utf8' });
  assert.equal(run.status, 0, `git ${args.join(' ')} failed: ${run.stderr}`);
  return run.stdout;
}

function newRepo() {
  const repo = mkdtempSync(join(tmpdir(), 'opensig-no-secrets-'));
  scratch.push(repo);
  git(repo, 'init', '-q');
  return repo;
}

function put(repo, rel, content) {
  const abs = join(repo, rel);
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(abs, content, { mode: 0o600 });
}

function track(repo, ...rels) {
  git(repo, 'add', '-f', '--', ...rels);
}

function commit(repo) {
  git(repo, 'commit', '-q', '--no-gpg-sign', '-m', 'synthetic fixture');
}

function scan(dir) {
  const run = spawnSync(process.execPath, [SCANNER, dir], { env: GIT_ENV, encoding: 'utf8', timeout: 60_000 });
  return { code: run.status, stdout: run.stdout, stderr: run.stderr, lines: run.stdout.split('\n').filter(Boolean) };
}

function findingsOf(result) {
  return result.lines
    .filter((line) => line.startsWith('no-secrets: rule='))
    .map((line) => {
      const match = /^no-secrets: rule=(\S+) file=(\S+) source=(\S+)(?: line=(\d+))?$/.exec(line);
      assert.ok(match, `malformed finding line: ${line}`);
      return { rule: match[1], file: match[2], source: match[3], line: match[4] === undefined ? undefined : Number(match[4]) };
    });
}

function expectFinding(result, rule, file, source) {
  const hit = findingsOf(result).some((f) => f.rule === rule && f.file === file && (source === undefined || f.source === source));
  assert.ok(hit, `expected ${rule} on ${file}${source ? ` (${source})` : ''}; scanner output:\n${result.stdout}`);
}

function expectNoFinding(result, file, rule) {
  const hits = findingsOf(result).filter((f) => f.file === file && (rule === undefined || f.rule === rule));
  assert.deepEqual(hits, [], `unexpected finding on ${file}; scanner output:\n${result.stdout}`);
}

function expectNoContent(result, samples) {
  for (const sample of samples) {
    assert.ok(sample.length >= 8, 'content probes must be specific');
    assert.ok(!result.stdout.includes(sample) && !result.stderr.includes(sample), 'scanner output must never contain matched content');
  }
}

// --- structural sample builders ---------------------------------------------

function der(tag, body) {
  const length = body.length;
  let head;
  if (length < 0x80) head = Buffer.from([tag, length]);
  else if (length < 0x100) head = Buffer.from([tag, 0x81, length]);
  else head = Buffer.from([tag, 0x82, length >> 8, length & 0xff]);
  return Buffer.concat([head, body]);
}

/** A structurally valid PFX: version 3, a pkcs7-data authSafe and SHA-1 macData. */
function pfxBytes() {
  const pkcs7Data = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
  const authSafe = der(0x30, Buffer.concat([pkcs7Data, der(0xa0, der(0x04, randomBytes(320)))]));
  const sha1Algorithm = der(0x30, Buffer.from([0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00]));
  const macData = der(
    0x30,
    Buffer.concat([der(0x30, Buffer.concat([sha1Algorithm, der(0x04, randomBytes(20))])), der(0x04, randomBytes(8)), der(0x02, Buffer.from([0x08, 0x00]))]),
  );
  return der(0x30, Buffer.concat([der(0x02, Buffer.from([0x03])), authSafe, macData]));
}

/** A 1x1 greyscale PNG with valid chunk CRCs. */
function pngBytes() {
  const chunk = (type, data) => {
    const typeBytes = Buffer.from(type, 'latin1');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])));
    return Buffer.concat([length, typeBytes, data, crc]);
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(1, 0);
  header.writeUInt32BE(1, 4);
  header[8] = 8; // bit depth; colour type, compression, filter and interlace stay 0
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(Buffer.from([0x00, 0xff]))),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function svgText() {
  return '<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="40" height="10"><path d="M0 5 L40 5"/></svg>\n';
}

/** The same PFX in BER indefinite-length form (SEQUENCE 0x30 0x80 ... 0x00 0x00). */
function pfxBerBytes() {
  const ber = (tag, ...parts) => Buffer.concat([Buffer.from([tag, 0x80]), ...parts, Buffer.from([0x00, 0x00])]);
  const pkcs7Data = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]);
  const authSafe = ber(0x30, pkcs7Data, ber(0xa0, der(0x04, randomBytes(320))));
  const sha1Algorithm = der(0x30, Buffer.from([0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00]));
  const macData = der(0x30, Buffer.concat([der(0x30, Buffer.concat([sha1Algorithm, der(0x04, randomBytes(20))])), der(0x04, randomBytes(8))]));
  return ber(0x30, der(0x02, Buffer.from([0x03])), authSafe, macData);
}

function randomValue() {
  return randomBytes(18).toString('base64url');
}

/** A random base32 (RFC 4648) string, the shape of a TOTP shared secret. */
function randomBase32(length) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  return [...randomBytes(length)].map((byte) => alphabet[byte % 32]).join('');
}

function wrap64(text) {
  return text.match(/.{1,64}/g).join('\n');
}

function utf16be(text) {
  return Buffer.from(text, 'utf16le').swap16();
}

/** A 512-byte header block shaped like an uncompressed tar member header (name, NUL padding). */
function tarHeader(name) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 'latin1');
  header.write('0000644\0', 100, 'latin1');
  return header;
}

function pemParts(pem) {
  const lines = pem.trim().split('\n');
  return { lines, header: lines[0], body: lines.slice(1, -1).join(''), footer: lines.at(-1) };
}

// --- cases ---------------------------------------------------------------------

test('[NS-01] private-key PEM blocks are reported, public keys are not', () => {
  const repo = newRepo();
  const ed = generateKeyPairSync('ed25519');
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pkcs8 = ed.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pkcs1 = rsa.privateKey.export({ type: 'pkcs1', format: 'pem' });
  const sec1 = ec.privateKey.export({ type: 'sec1', format: 'pem' });
  const encrypted = ed.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: randomBytes(16).toString('hex') });
  const indented = pkcs8
    .trimEnd()
    .split('\n')
    .map((line) => `    ${line}`)
    .join('\n');
  put(repo, 'deploy/a.pem', pkcs8);
  put(repo, 'deploy/b.txt', `preamble\n${pkcs1}`);
  put(repo, 'src/c.ts', `export const material = \`\n${sec1}\`;\n`);
  put(repo, 'conf/d.pem', encrypted);
  put(repo, 'conf/e.json', JSON.stringify({ kind: 'service', key_pem: pkcs8 }));
  put(repo, 'conf/f.yaml', `tls:\n  key: |\n${indented}\n`);
  put(repo, 'conf/public.pem', ed.publicKey.export({ type: 'spki', format: 'pem' }));
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of ['deploy/a.pem', 'deploy/b.txt', 'src/c.ts', 'conf/d.pem', 'conf/e.json', 'conf/f.yaml']) {
    expectFinding(result, 'private-key-pem', file, 'index');
  }
  expectNoFinding(result, 'conf/public.pem');
  expectNoContent(result, [pkcs8.split('\n')[1], pkcs1.split('\n')[1], sec1.split('\n')[1]]);
});

test('[NS-02] PKCS#12/PFX content is reported by structure, extension and base64 embedding', () => {
  const repo = newRepo();
  const pfx = pfxBytes();
  const base64 = pfx.toString('base64');
  put(repo, 'store/bundle.bin', pfx);
  put(repo, 'store/client.p12', randomBytes(64));
  put(repo, 'store/LEGACY.PFX', randomBytes(64));
  put(repo, 'conf/truststore.yaml', `bundle: |\n${wrap64(base64)
    .split('\n')
    .map((line) => `  ${line}`)
    .join('\n')}\n`);
  put(repo, 'store/spki.der', generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }));
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  expectFinding(result, 'pkcs12-content', 'store/bundle.bin', 'index');
  expectFinding(result, 'pkcs12-content', 'store/client.p12', 'path');
  expectFinding(result, 'pkcs12-content', 'store/LEGACY.PFX', 'path');
  expectFinding(result, 'pkcs12-content', 'conf/truststore.yaml', 'index');
  expectNoFinding(result, 'store/spki.der');
  expectNoContent(result, [base64.slice(0, 40)]);
});

test('[NS-03] SQLite database, WAL and journal headers are reported', () => {
  const repo = newRepo();
  mkdirSync(join(repo, 'state'), { recursive: true });
  const db = new DatabaseSync(join(repo, 'state', 'cache.dat'));
  db.exec('CREATE TABLE item (id INTEGER PRIMARY KEY, label TEXT)');
  db.prepare('INSERT INTO item (label) VALUES (?)').run('synthetic');
  db.close();
  put(repo, 'state/wal.bin', Buffer.concat([Buffer.from([0x37, 0x7f, 0x06, 0x82]), randomBytes(60)]));
  put(repo, 'state/journal.bin', Buffer.concat([Buffer.from([0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]), randomBytes(56)]));
  put(repo, 'docs/storage.md', 'Database files begin with the header "SQLite format 3" and are never committed.\n');
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  expectFinding(result, 'sqlite-database', 'state/cache.dat', 'index');
  expectFinding(result, 'sqlite-database', 'state/wal.bin', 'index');
  expectFinding(result, 'sqlite-database', 'state/journal.bin', 'index');
  expectNoFinding(result, 'docs/storage.md');
});

test('[NS-04] raster and SVG images under fixtures/ are reported', () => {
  const repo = newRepo();
  const png = pngBytes();
  put(repo, 'fixtures/synthetic/mark.bin', png);
  put(repo, 'fixtures/synthetic/photo.jpg', Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), randomBytes(60)]));
  put(repo, 'fixtures/anim.dat', Buffer.concat([Buffer.from('GIF89a', 'latin1'), randomBytes(40)]));
  const webp = Buffer.concat([Buffer.from('RIFF', 'latin1'), Buffer.from([0x24, 0, 0, 0]), Buffer.from('WEBPVP8 ', 'latin1'), randomBytes(28)]);
  put(repo, 'fixtures/synthetic/img.raw', webp);
  put(repo, 'fixtures/synthetic/stroke.svg', svgText());
  put(repo, 'fixtures/synthetic/drawing.xml', svgText());
  put(repo, 'tests/oracle/fixtures/tiny.bin', png);
  put(repo, 'docs/diagram.png', png);
  put(repo, 'fixtures/synthetic/document.pdf', '%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n');
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of [
    'fixtures/synthetic/mark.bin',
    'fixtures/synthetic/photo.jpg',
    'fixtures/anim.dat',
    'fixtures/synthetic/img.raw',
    'fixtures/synthetic/stroke.svg',
    'fixtures/synthetic/drawing.xml',
    'tests/oracle/fixtures/tiny.bin',
  ]) {
    expectFinding(result, 'fixture-image', file);
  }
  expectNoFinding(result, 'docs/diagram.png');
  expectNoFinding(result, 'fixtures/synthetic/document.pdf');
});

test('[NS-05] .env files are reported wherever they are tracked', () => {
  const repo = newRepo();
  put(repo, '.env', 'MODE=development\n');
  put(repo, 'services/api/.env.production', 'MODE=production\n');
  put(repo, '.envrc', 'export MODE=development\n');
  put(repo, 'docs/env.md', 'Environment variables are documented here.\n');
  put(repo, 'src/environment.ts', 'export const mode = "development";\n');
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  expectFinding(result, 'env-file', '.env', 'path');
  expectFinding(result, 'env-file', 'services/api/.env.production', 'path');
  expectFinding(result, 'env-file', '.envrc', 'path');
  expectNoFinding(result, 'docs/env.md');
  expectNoFinding(result, 'src/environment.ts');
});

test('[NS-06] known secret names assigned literal values are reported, references are not', () => {
  const repo = newRepo();
  const values = Array.from({ length: 6 }, randomValue);
  put(repo, 'deploy/values.yaml', `mail:\n  smtp_password: ${values[0]}\n`);
  put(repo, 'conf/client.json', `{"endpoint": "https://api.example.test", "apiKey": "${values[1]}"}\n`);
  put(repo, 'src/settings.mjs', `export const clientSecret = '${values[2]}';\n`);
  put(repo, 'conf/hooks.toml', `[hooks]\nwebhook_secret = "${values[3]}"\n`);
  put(repo, 'scripts/env.sh', `export GITHUB_TOKEN=${values[4]}\n`);
  put(repo, 'conf/app.ini', `[db]\nDB_PASSWORD = ${values[5]}\n`);
  put(
    repo,
    'deploy/references.yaml',
    [
      'smtp_password: ${SMTP_PASSWORD}',
      'smtp_password_file: /run/credentials/smtp',
      'api_key: <redacted>',
      'client_secret: changeme-in-deployment',
      'webhook_secret: OPENSIG_WEBHOOK_SECRET',
      'password_min_length: 12345678',
      '',
    ].join('\n'),
  );
  put(
    repo,
    'src/references.mjs',
    [
      'const apiKey = process.env.API_KEY;',
      "const password = readFileSync(passwordPath, 'utf8');",
      "if (password === 'abcdefghij') throw new Error('rejected');",
      'const passwordMinLength = 12;',
      "const tokenCount = '123456789';",
      'const header = `Bearer ${accessToken}`;',
      '',
    ].join('\n'),
  );
  put(repo, 'docs/setup.md', 'Set SMTP_PASSWORD=value-from-the-vault before starting the service.\n');
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  expectFinding(result, 'secret-assignment', 'deploy/values.yaml', 'index');
  expectFinding(result, 'secret-assignment', 'conf/client.json', 'index');
  expectFinding(result, 'secret-assignment', 'src/settings.mjs', 'index');
  expectFinding(result, 'secret-assignment', 'conf/hooks.toml', 'index');
  expectFinding(result, 'secret-assignment', 'scripts/env.sh', 'index');
  expectFinding(result, 'secret-assignment', 'conf/app.ini', 'index');
  assert.equal(findingsOf(result).find((f) => f.file === 'deploy/values.yaml').line, 2, 'the line number is reported');
  expectNoFinding(result, 'deploy/references.yaml');
  expectNoFinding(result, 'src/references.mjs');
  expectNoFinding(result, 'docs/setup.md');
  expectNoContent(result, values);
});

test('[NS-07] findings exit non-zero naming file and rule only; a clean repository exits 0', () => {
  const repo = newRepo();
  const pem = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pfx = pfxBytes();
  const value = randomValue();
  put(repo, 'deploy/key.pem', pem);
  put(repo, 'store/bundle.bin', pfx);
  mkdirSync(join(repo, 'state'), { recursive: true });
  const db = new DatabaseSync(join(repo, 'state', 'local.db'));
  db.exec('CREATE TABLE t (v TEXT)');
  db.close();
  put(repo, 'fixtures/synthetic/mark.svg', svgText());
  put(repo, '.env.local', `MODE=${randomValue()}\n`);
  put(repo, 'deploy/values.yaml', `api_token: ${value}\n`);
  track(repo, '.');
  commit(repo);
  const result = scan(repo);
  assert.equal(result.code, 1);
  const lineShape =
    /^no-secrets: (?:rule=(?:private-key-pem|pkcs12-content|sqlite-database|fixture-image|env-file|secret-assignment) file=\S+ source=(?:index|worktree|path)(?: line=\d+)?|FAIL findings=\d+ files=\d+ scanned=\d+)$/;
  for (const line of result.lines) assert.match(line, lineShape);
  assert.match(result.lines.at(-1), /^no-secrets: FAIL findings=\d+ files=6 scanned=6$/);
  assert.deepEqual([...new Set(findingsOf(result).map((f) => f.rule))].sort(), [...RULE_NAMES].sort());
  expectNoContent(result, [pem.split('\n')[1], pfx.toString('base64').slice(0, 40), value]);

  const clean = newRepo();
  put(clean, 'README.md', '# Synthetic repository\n');
  put(clean, 'src/index.ts', 'export const answer = 42;\n');
  track(clean, '.');
  commit(clean);
  const cleanResult = scan(clean);
  assert.equal(cleanResult.code, 0);
  assert.deepEqual(cleanResult.lines, ['no-secrets: PASS findings=0 scanned=2']);
});

test('[NS-01] PEM keys split across string pieces, joined arrays or one line are reported', () => {
  const repo = newRepo();
  const pkcs8 = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs1', format: 'pem' });
  const ed = pemParts(pkcs8);
  const rs = pemParts(rsa);
  const chunks16 = ed.body.match(/.{1,16}/g);
  const publicPem = pemParts(generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }));
  // Line-by-line concatenation with escaped newlines (JavaScript, Java, C#).
  put(repo, 'src/concat.ts', `export const material =\n  ${rs.lines.map((line) => JSON.stringify(`${line}\n`)).join(' +\n  ')};\n`);
  // An array of lines joined at run time.
  put(repo, 'src/joined.mjs', `const parts = ${JSON.stringify(ed.lines)};\nexport const material = parts.join('\\n');\n`);
  // Flattened onto one line, separated by spaces.
  put(repo, 'conf/one-line.conf', `key = ${ed.lines.join(' ')}\n`);
  // Python implicit concatenation of 16-character pieces.
  put(repo, 'app/key.py', `KEY = (\n    "${ed.header}\\n"\n${chunks16.map((chunk) => `    "${chunk}"\n`).join('')}    "\\n${ed.footer}"\n)\n`);
  // 16-character pieces joined with + on one line.
  put(repo, 'src/pieces.js', `module.exports = ${[ed.header, ...chunks16, ed.footer].map((piece) => `'${piece}'`).join(' + ')};\n`);
  // A YAML list with one quoted line per item.
  put(repo, 'conf/list.yaml', `key_lines:\n${rs.lines.map((line) => `  - "${line}"\n`).join('')}`);
  // Not keys: a public key flattened onto one line, and prose that names the header.
  put(repo, 'conf/public-one-line.conf', `key = ${publicPem.lines.join(' ')}\n`);
  put(repo, 'docs/keys.md', `Files that contain a ${ed.header} line are rejected, and the scanner reports only the file and the rule name.\n`);
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of ['src/concat.ts', 'src/joined.mjs', 'conf/one-line.conf', 'app/key.py', 'src/pieces.js', 'conf/list.yaml']) {
    expectFinding(result, 'private-key-pem', file, 'index');
  }
  expectNoFinding(result, 'conf/public-one-line.conf');
  expectNoFinding(result, 'docs/keys.md');
  expectNoContent(result, [ed.body.slice(0, 32), rs.body.slice(0, 32), ...chunks16.slice(0, 2)]);
});

test('[NS-01] UTF-16 PEM, PEM after a binary prefix and base64-encoded PEM are reported', () => {
  const repo = newRepo();
  const pem = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const b64 = (text) => Buffer.from(text, 'latin1').toString('base64');
  put(repo, 'keys/utf16le-bom.txt', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(pem, 'utf16le')]));
  put(repo, 'keys/utf16be.txt', utf16be(pem));
  put(repo, 'bundle/archive.tar', Buffer.concat([tarHeader('key.pem'), Buffer.from(pem, 'latin1'), Buffer.alloc(1024)]));
  // UTF-16 text at an odd offset inside binary content.
  put(repo, 'bundle/blob.bin', Buffer.concat([Buffer.alloc(333, 0x00), Buffer.from(pem, 'utf16le'), Buffer.alloc(64)]));
  // Kubernetes Secret value (base64 of the whole PEM file).
  put(repo, 'deploy/secret.yaml', `apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata:\n  tls.key: ${b64(pem)}\n`);
  // Base64 wrapped at 76 columns in a block scalar.
  put(repo, 'deploy/wrapped.yaml', `key: |\n${b64(pem)
    .match(/.{1,76}/g)
    .map((line) => `  ${line}`)
    .join('\n')}\n`);
  // The PEM after a one-byte and a two-byte preamble (the other base64 alignments), in JSON strings.
  put(repo, 'deploy/shift-1.json', `${JSON.stringify({ blob: b64(`\n${pem}`) })}\n`);
  put(repo, 'deploy/shift-2.json', `${JSON.stringify({ blob: b64(`#\n${pem}`) })}\n`);
  // Base64 of base64.
  put(repo, 'deploy/nested.txt', `${b64(b64(pem))}\n`);
  // Not keys: a public key in the same encodings.
  put(repo, 'deploy/public.yaml', `data:\n  tls.crt: ${b64(publicPem)}\n`);
  put(repo, 'keys/public-utf16.txt', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(publicPem, 'utf16le')]));
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of [
    'keys/utf16le-bom.txt',
    'keys/utf16be.txt',
    'bundle/archive.tar',
    'bundle/blob.bin',
    'deploy/secret.yaml',
    'deploy/wrapped.yaml',
    'deploy/shift-1.json',
    'deploy/shift-2.json',
    'deploy/nested.txt',
  ]) {
    expectFinding(result, 'private-key-pem', file, 'index');
  }
  expectNoFinding(result, 'deploy/public.yaml');
  expectNoFinding(result, 'keys/public-utf16.txt');
  expectNoContent(result, [pem.split('\n')[1], b64(pem).slice(0, 40)]);
});

test('[NS-02] BER indefinite-length PKCS#12 is reported raw, base64-encoded and in UTF-16', () => {
  const repo = newRepo();
  const pfx = pfxBerBytes();
  const base64 = pfx.toString('base64');
  put(repo, 'store/indefinite.bin', pfx);
  put(repo, 'conf/bundle.yaml', `bundle: ${base64}\n`);
  put(repo, 'conf/wrapped.yaml', `bundle: |\n${wrap64(base64)
    .split('\n')
    .map((line) => `  ${line}`)
    .join('\n')}\n`);
  put(repo, 'conf/utf16.txt', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`bundle=${base64}\n`, 'utf16le')]));
  put(repo, 'bundle/archive.tar', Buffer.concat([tarHeader('bundle.b64'), Buffer.from(`${base64}\n`, 'latin1'), Buffer.alloc(512)]));
  put(repo, 'conf/spki.txt', `${generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}\n`);
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of ['store/indefinite.bin', 'conf/bundle.yaml', 'conf/wrapped.yaml', 'conf/utf16.txt', 'bundle/archive.tar']) {
    expectFinding(result, 'pkcs12-content', file, 'index');
  }
  expectNoFinding(result, 'conf/spki.txt');
  expectNoContent(result, [base64.slice(0, 40)]);
});

test('[NS-04] images under fixture directories in any spelling are reported', () => {
  const repo = newRepo();
  const png = pngBytes();
  put(repo, 'src/__fixtures__/mark.png', png);
  put(repo, 'tests/Fixtures/stroke.svg', svgText());
  put(repo, 'tests/pdf-fixtures/page.bin', png);
  put(repo, 'tests/fixture/drawing.xml', svgText());
  put(repo, 'tests/Fixtures/utf16.xml', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(svgText(), 'utf16le')]));
  put(repo, 'docs/fixturesque/diagram.png', png);
  put(repo, 'src/fixture.svg', svgText());
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of ['src/__fixtures__/mark.png', 'tests/Fixtures/stroke.svg', 'tests/pdf-fixtures/page.bin', 'tests/fixture/drawing.xml', 'tests/Fixtures/utf16.xml']) {
    expectFinding(result, 'fixture-image', file);
  }
  expectNoFinding(result, 'docs/fixturesque/diagram.png');
  expectNoFinding(result, 'src/fixture.svg');
});

test('[NS-05] .env-local, prod.env and other .env spellings are reported', () => {
  const repo = newRepo();
  for (const file of ['.env-local', 'deploy/prod.env', 'services/.env_staging', 'config/.prod.env', 'config/.ENV']) put(repo, file, 'MODE=synthetic\n');
  put(repo, 'src/dotenv.ts', 'export const loader = "dotenv";\n');
  put(repo, 'docs/environment.md', 'Environment files are never committed.\n');
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of ['.env-local', 'deploy/prod.env', 'services/.env_staging', 'config/.prod.env', 'config/.ENV']) expectFinding(result, 'env-file', file, 'path');
  expectNoFinding(result, 'src/dotenv.ts');
  expectNoFinding(result, 'docs/environment.md');
});

test('[NS-06] typed declarations, Go :=, flags, URL credentials and upper-case secrets are reported', () => {
  const repo = newRepo();
  const v = Array.from({ length: 13 }, randomValue);
  const totp = [randomBase32(32), randomBase32(16)];
  const samples = {
    'src/typed.ts': `\nconst signingKey: string = '${v[0]}';\n`,
    'src/service.ts': `export class Service {\n  private readonly apiKey: string = "${v[1]}";\n}\n`,
    'src/union.ts': `export const webhookSecret: string | undefined = '${v[2]}';\n`,
    'app/settings.py': `api_key: str = "${v[3]}"\n`,
    'app/final.py': `CLIENT_SECRET: Final[str] = '${v[4]}'\n`,
    'src/main.rs': `const API_KEY: &str = "${v[5]}";\n`,
    'cmd/main.go': `func main() {\n\tapiKey := "${v[6]}"\n\t_ = apiKey\n}\n`,
    'cmd/vars.go': `var dbPassword string = "${v[7]}"\n`,
    'scripts/run.sh': `tool --password=${v[8]} --verbose\n`,
    'src/spawn.mjs': `spawn('db-tool', ['--db-password=${v[9]}']);\n`,
    'docs/run.md': `Run java -Dapp.password=${v[10]} -jar app.jar locally.\n`,
    'conf/db.yaml': `url: postgres://svc:${v[11]}@db.example.test:5432/app\n`,
    'src/client.ts': `const endpoint = "https://deploy:${v[12]}@registry.example.test/v2";\n`,
    'conf/totp.yaml': `totp_secret: ${totp[0]}\n`,
    'src/totp.ts': `export const mfaSecret = '${totp[1]}';\n`,
  };
  for (const [file, content] of Object.entries(samples)) put(repo, file, content);
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of Object.keys(samples)) expectFinding(result, 'secret-assignment', file, 'index');
  assert.equal(findingsOf(result).find((f) => f.file === 'src/typed.ts').line, 2, 'the line number is reported');
  expectNoContent(result, [...v, ...totp]);
});

test('[NS-06] command substitution, ternary branches, type-only annotations and placeholder URLs are not reported', () => {
  const repo = newRepo();
  const v = randomValue();
  const bt = String.fromCharCode(0x60); // shell command substitution quote, kept out of this file's own scan
  put(repo, 'scripts/gen.sh', `export X_SECRET=$(openssl rand -hex 32)\nexport Y_SECRET=${bt}openssl rand -hex 32${bt}\nZ_PASSWORD=$HOME/.config/synthetic\n`);
  put(repo, 'src/choose.ts', `const chosen = ready ? password : '${v}';\n`);
  put(repo, 'src/types.ts', 'export function connect(password: string): void {}\nexport interface Options { apiKey?: string; clientSecret: string | undefined }\n');
  put(repo, 'app/types.py', 'def connect(password: str) -> None: ...\napi_key: Optional[str] = None\n');
  put(
    repo,
    'conf/urls.yaml',
    [
      'docs: https://user:password@db.example.test/',
      'sample: https://user:pass@api.example.test/v1',
      'templated: postgres://svc:${DB_PASSWORD}@db.example.test/app',
      'variable: redis://cache:$REDIS_PASSWORD@cache.example.test:6379',
      'port: https://registry.example.test:8443/v2',
      'reference: webhook_secret is OPENSIG_WEBHOOK_SECRET',
      'upper: api_password: PASSWORD',
      '',
    ].join('\n'),
  );
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 0, result.stdout);
  assert.deepEqual(findingsOf(result), []);
});

test('[NS-08] a path deleted from both the index and the working tree has no findings; a remaining copy is still scanned', () => {
  const repo = newRepo();
  put(repo, '.env', `MODE=${randomValue()}\n`);
  put(repo, 'store/client.p12', randomBytes(64));
  put(repo, 'fixtures/synthetic/mark.png', pngBytes());
  put(repo, 'conf/keep.p12', randomBytes(64));
  put(repo, 'services/.env.local', 'MODE=synthetic\n');
  put(repo, 'README.md', '# Synthetic repository\n');
  track(repo, '.');
  commit(repo);
  git(repo, 'rm', '-q', '--', '.env', 'store/client.p12', 'fixtures/synthetic/mark.png'); // staged deletions, gone from disk
  git(repo, 'rm', '-q', '--cached', '--', 'conf/keep.p12'); // staged removal, copy kept on disk
  rmSync(join(repo, 'services', '.env.local')); // deleted on disk only, still in the index
  const result = scan(repo);
  assert.equal(result.code, 1, result.stdout);
  for (const file of ['.env', 'store/client.p12', 'fixtures/synthetic/mark.png']) expectNoFinding(result, file);
  expectFinding(result, 'pkcs12-content', 'conf/keep.p12', 'path');
  expectFinding(result, 'env-file', 'services/.env.local', 'path');
  assert.match(result.lines.at(-1), /^no-secrets: FAIL findings=\d+ files=2 scanned=3$/);

  const onlyDeleted = newRepo();
  put(onlyDeleted, '.env', 'MODE=synthetic\n');
  put(onlyDeleted, 'README.md', '# Synthetic repository\n');
  track(onlyDeleted, '.');
  commit(onlyDeleted);
  git(onlyDeleted, 'rm', '-q', '--', '.env');
  const clean = scan(onlyDeleted);
  assert.equal(clean.code, 0, clean.stdout);
  assert.deepEqual(clean.lines, ['no-secrets: PASS findings=0 scanned=1']);
});

test('[NS-09] quoted literals spelt like variable names are reported; unquoted references and placeholders are not', () => {
  const repo = newRepo();
  const upper = (length) => [...randomBytes(length)].map((byte) => 'ABCDEFGHJKLMNPQRSTUVWXYZ'[byte % 24]).join('');
  const digits = (length) => [...randomBytes(length)].map((byte) => String(byte % 10)).join('');
  const values = [`${upper(4)}_${digits(10)}${upper(3)}`, `${upper(6)}_${upper(5)}_${upper(4)}`, `${upper(5)}_${digits(4)}`, `${upper(4)}_${upper(4)}`];
  const samples = {
    'conf/client.json': `{"password":"${values[0]}"}\n`,
    'src/settings.ts': `export const apiKey = '${values[1]}';\n`,
    'deploy/values.yaml': `api_token: "${values[2]}"\n`,
    'app/settings.py': `CLIENT_SECRET = "${values[3]}"\n`,
  };
  for (const [file, content] of Object.entries(samples)) put(repo, file, content);
  put(
    repo,
    'deploy/references.yaml',
    ['api_token: OPENSIG_API_TOKEN', 'client_secret: process.env.OPENSIG_CLIENT_SECRET', 'webhook_secret: import.meta.env.OPENSIG_WEBHOOK_SECRET', 'api_key: "${OPENSIG_API_KEY}"', ''].join('\n'),
  );
  put(repo, 'scripts/env.sh', 'export API_KEY=$OPENSIG_API_KEY\nexport DB_PASSWORD="$OPENSIG_DB_PASSWORD"\n');
  put(repo, 'conf/names.json', '{"password": "PASSWORD", "token_count": "SIXTEEN_TOKENS"}\n');
  track(repo, '.');
  const result = scan(repo);
  assert.equal(result.code, 1);
  for (const file of Object.keys(samples)) expectFinding(result, 'secret-assignment', file, 'index');
  expectNoFinding(result, 'deploy/references.yaml');
  expectNoFinding(result, 'scripts/env.sh');
  expectNoFinding(result, 'conf/names.json');
  expectNoContent(result, values);
});

test('staged and working-tree content of tracked files is scanned; untracked files are not', () => {
  const repo = newRepo();
  put(repo, 'conf/app.yaml', 'mode: development\n');
  put(repo, 'conf/staged.yaml', 'mode: development\n');
  track(repo, '.');
  commit(repo);
  put(repo, 'conf/app.yaml', `mode: development\napi_key: ${randomValue()}\n`); // modified, not staged
  put(repo, 'conf/staged.yaml', `access_token: ${randomValue()}\n`);
  track(repo, 'conf/staged.yaml');
  put(repo, 'conf/staged.yaml', 'mode: development\n'); // secret only in the index now
  put(repo, 'conf/new.yaml', `refresh_token: ${randomValue()}\n`);
  track(repo, 'conf/new.yaml'); // staged, never committed
  put(repo, 'notes/scratch.yaml', `api_key: ${randomValue()}\n`); // untracked
  const result = scan(repo);
  assert.equal(result.code, 1);
  expectFinding(result, 'secret-assignment', 'conf/app.yaml', 'worktree');
  expectFinding(result, 'secret-assignment', 'conf/staged.yaml', 'index');
  expectFinding(result, 'secret-assignment', 'conf/new.yaml', 'index');
  expectNoFinding(result, 'notes/scratch.yaml');
});

test('usage and repository errors exit 2', () => {
  const notRepo = mkdtempSync(join(tmpdir(), 'opensig-no-secrets-plain-'));
  scratch.push(notRepo);
  const outside = scan(notRepo);
  assert.equal(outside.code, 2);
  assert.deepEqual(outside.lines, ['no-secrets: ERROR repository']);
  const flagged = spawnSync(process.execPath, [SCANNER, '--allow'], { env: GIT_ENV, encoding: 'utf8' });
  assert.equal(flagged.status, 2);
});

test('the code-leg repository passes its own gate', () => {
  const result = scan(REPO_ROOT);
  assert.equal(result.code, 0, `repository findings:\n${result.stdout}${result.stderr}`);
  assert.match(result.lines.at(-1), /^no-secrets: PASS findings=0 scanned=\d+$/);
});
