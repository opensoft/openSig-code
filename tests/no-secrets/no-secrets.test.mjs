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

function randomValue() {
  return randomBytes(18).toString('base64url');
}

function wrap64(text) {
  return text.match(/.{1,64}/g).join('\n');
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
