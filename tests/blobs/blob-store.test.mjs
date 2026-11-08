// SPDX-License-Identifier: Apache-2.0
//
// Immutable, tenant-namespaced, content-addressed blob store (T028).
//   BL-01 tenant-namespaced content-addressed keys and durable publication
//   BL-02 reads verify the digest
//   BL-03 no overwrite
//   BL-04 no cross-tenant deduplication
// plus streaming writes, crash safety, input validation and the write order
// (temp file, fsync, no-replace publish, directory fsync).

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { openDatabase, StorageConstraintError, StorageUsageError } from '../../src/storage/db/index.ts';
import {
  BlobDigestMismatchError,
  BlobIntegrityError,
  BlobNotFoundError,
  BlobTooLargeError,
  blobRef,
  nodeFsOps,
  openBlobStore,
  parseBlobRef,
} from '../../src/storage/blobs/index.ts';
import { createTenant, envelopeRow, ts } from '../storage/support/fixtures.mjs';
import { sha256, syntheticBytes } from './support/synthetic.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = join(HERE, 'support', 'blob-worker.mjs');
const EMPTY_DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const scratchDirs = [];
after(() => {
  for (const dir of scratchDirs) rmSync(dir, { recursive: true, force: true });
});

function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'opensig-blobs-'));
  scratchDirs.push(dir);
  return dir;
}

function tenantId(label) {
  return `${label}-${randomBytes(12).toString('base64url')}`;
}

function newStore(options = {}) {
  const root = scratch();
  return { root, store: openBlobStore({ root, ...options }) };
}

function blobPath(root, tenant, digest) {
  return join(root, 'tenants', tenant, 'sha256', digest);
}

function tmpEntries(root, tenant) {
  return readdirSync(join(root, 'tenants', tenant, 'tmp'));
}

/** Change one byte of a published (read-only) blob in place. */
function flipByte(path, position) {
  chmodSync(path, 0o600);
  const original = readFileSync(path);
  const fd = openSync(path, 'r+');
  try {
    writeSync(fd, Buffer.from([original[position] ^ 0xff]), 0, 1, position);
  } finally {
    closeSync(fd);
  }
  chmodSync(path, 0o400);
}

function runWorker(args, { onStdout } = {}) {
  const child = spawn(process.execPath, [WORKER, ...args], { cwd: resolve(HERE, '..', '..'), stdio: ['ignore', 'pipe', 'pipe'] });
  const done = new Promise((settle, fail) => {
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      onStdout?.(stdout, child);
    });
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('error', fail);
    child.on('close', (code, signal) => settle({ code, signal, stdout, stderr }));
  });
  return { child, done };
}

test('[BL-01] a blob is stored at tenants/<tenant>/sha256/<digest> as a read-only file, and its ref satisfies the T003 schema', () => {
  const { root, store } = newStore();
  const tenant = tenantId('tenant');
  const bytes = syntheticBytes('bl-01', 5000);
  const result = store.put(tenant, bytes);
  const digest = sha256(bytes);
  assert.deepEqual(result, { ref: `tenants/${tenant}/sha256/${digest}`, tenantId: tenant, digest, size: 5000, created: true });
  assert.equal(blobRef(tenant, digest), result.ref);
  assert.deepEqual(parseBlobRef(result.ref), { tenantId: tenant, digest });

  const path = join(root, result.ref);
  assert.deepEqual(readFileSync(path), bytes);
  assert.equal(statSync(path).mode & 0o777, 0o400, 'published blobs are read-only');
  assert.equal(statSync(path).nlink, 1, 'the temp name is gone');
  for (const dir of [join(root, 'tenants'), join(root, 'tenants', tenant), join(root, 'tenants', tenant, 'sha256')]) {
    assert.equal(statSync(dir).mode & 0o777, 0o700, `${dir} is private`);
  }
  assert.deepEqual(tmpEntries(root, tenant), []);
  assert.deepEqual(store.read(tenant, digest), bytes);
  assert.deepEqual(store.readRef(tenant, result.ref), bytes);
  assert.deepEqual(store.list(tenant), [digest]);
  assert.equal(store.check(tenant, digest), 'ok');

  const empty = store.put(tenant, new Uint8Array(0));
  assert.equal(empty.digest, EMPTY_DIGEST);
  assert.equal(store.read(tenant, EMPTY_DIGEST).length, 0);

  // The ref is accepted by the T003 document_revisions.blob_ref check, and a
  // ref naming another tenant is not.
  const db = openDatabase({ path: join(scratch(), 'opensig.db') });
  try {
    db.migrate();
    createTenant(db, tenant);
    const envelope = `env-${randomBytes(12).toString('base64url')}`;
    const revision = (id, ref) => ({
      id,
      envelope_id: envelope,
      content_digest: digest,
      blob_ref: ref,
      bytes: 5000,
      pages: 1,
      page_geometry_json: '[]',
      parse_report_json: '{}',
      created_at: ts(2),
    });
    const s = db.forTenant(tenant);
    db.transaction(() => {
      s.insert('envelopes', envelopeRow(envelope));
      s.insert('document_revisions', revision(`rev-${randomBytes(12).toString('base64url')}`, result.ref));
    });
    assert.throws(
      () => db.transaction(() => s.insert('document_revisions', revision(`rev-${randomBytes(12).toString('base64url')}`, blobRef(tenantId('other'), digest)))),
      (error) => error instanceof StorageConstraintError && error.constraint === 'check',
    );
  } finally {
    db.close();
  }
});

test('[BL-02] reads hash the whole content and refuse modified, truncated, extended, linked or non-file entries', () => {
  const { root, store } = newStore();
  const tenant = tenantId('tenant');
  const put = (seed) => store.put(tenant, syntheticBytes(seed, 4096));

  const flipped = put('flip');
  flipByte(blobPath(root, tenant, flipped.digest), 100);
  assert.throws(() => store.read(tenant, flipped.digest), (error) => error instanceof BlobIntegrityError && /does not match its digest/.test(error.message));
  assert.equal(store.check(tenant, flipped.digest), 'corrupt');

  const truncated = put('truncate');
  chmodSync(blobPath(root, tenant, truncated.digest), 0o600);
  truncateSync(blobPath(root, tenant, truncated.digest), 1000);
  assert.equal(store.check(tenant, truncated.digest), 'corrupt');

  const extended = put('extend');
  chmodSync(blobPath(root, tenant, extended.digest), 0o600);
  writeFileSync(blobPath(root, tenant, extended.digest), Buffer.concat([syntheticBytes('extend', 4096), Buffer.from([0])]));
  assert.equal(store.check(tenant, extended.digest), 'corrupt');

  // A link is never followed, even to a file with the right bytes.
  const linked = put('link');
  const copy = join(scratch(), 'copy');
  writeFileSync(copy, syntheticBytes('link', 4096));
  unlinkSync(blobPath(root, tenant, linked.digest));
  symlinkSync(copy, blobPath(root, tenant, linked.digest));
  assert.throws(() => store.read(tenant, linked.digest), (error) => error instanceof BlobIntegrityError && /symbolic link/.test(error.message));

  const directory = sha256(Buffer.from('directory-at-blob-path'));
  mkdirSync(blobPath(root, tenant, directory));
  assert.equal(store.check(tenant, directory), 'corrupt');

  const missing = sha256(Buffer.from('never-stored'));
  assert.throws(() => store.read(tenant, missing), BlobNotFoundError);
  assert.equal(store.check(tenant, missing), 'missing');
  assert.equal(store.check(tenantId('unknown'), missing), 'missing');
  assert.deepEqual(store.list(tenantId('unknown')), []);

  // A file above the reader's size limit is refused without being trusted.
  const big = put('large');
  const small = openBlobStore({ root, maxBytes: 1024 });
  assert.throws(() => small.read(tenant, big.digest), (error) => error instanceof BlobIntegrityError && /size limit/.test(error.message));
  assert.equal(store.check(tenant, big.digest), 'ok');
});

test('[BL-03] an existing blob is never overwritten: repeats are no-ops and a corrupt blob is reported, not replaced', async () => {
  const { root, store } = newStore();
  const tenant = tenantId('tenant');
  const bytes = syntheticBytes('bl-03', 8192);
  const first = store.put(tenant, bytes);
  const path = blobPath(root, tenant, first.digest);
  const before = statSync(path);

  const again = store.put(tenant, bytes);
  const streamed = await store.putStream(tenant, [bytes.subarray(0, 100), bytes.subarray(100)]);
  for (const result of [again, streamed]) {
    assert.equal(result.created, false);
    assert.equal(result.ref, first.ref);
  }
  const afterRepeat = statSync(path);
  assert.equal(afterRepeat.ino, before.ino, 'same file');
  assert.equal(afterRepeat.mtimeMs, before.mtimeMs, 'not rewritten');
  assert.equal(afterRepeat.nlink, 1);
  assert.deepEqual(tmpEntries(root, tenant), []);

  flipByte(path, 0);
  const tampered = readFileSync(path);
  assert.throws(() => store.put(tenant, bytes), (error) => error instanceof BlobIntegrityError && /never overwritten/.test(error.message));
  await assert.rejects(store.putStream(tenant, [bytes]), BlobIntegrityError);
  assert.deepEqual(readFileSync(path), tampered, 'the corrupt blob is kept as evidence');
  assert.equal(statSync(path).ino, before.ino);
  assert.deepEqual(tmpEntries(root, tenant), []);

  // Removal is explicit (retention), and only then can the content return.
  assert.equal(store.dispose(tenant, first.digest), true);
  assert.equal(store.dispose(tenant, first.digest), false);
  assert.deepEqual(store.list(tenant), []);
  assert.equal(store.put(tenant, bytes).created, true);
  assert.deepEqual(store.read(tenant, first.digest), bytes);

  // Concurrent writers in separate processes: exactly one publishes.
  const race = tenantId('race');
  const startAt = String(Date.now() + 400);
  const runs = await Promise.all(
    Array.from({ length: 6 }, () => runWorker(['put', root, race, 'race', '65536', startAt]).done),
  );
  for (const run of runs) assert.equal(run.code, 0, run.stderr.slice(0, 400));
  const results = runs.map((run) => JSON.parse(run.stdout));
  const raceDigest = sha256(syntheticBytes('race', 65536));
  assert.ok(results.every((result) => result.digest === raceDigest));
  assert.equal(results.filter((result) => result.created).length, 1, 'exactly one writer created the blob');
  assert.deepEqual(store.list(race), [raceDigest]);
  assert.equal(store.check(race, raceDigest), 'ok');
  assert.deepEqual(tmpEntries(root, race), []);
});

test('[BL-04] equal bytes in two tenants are two separate blobs, reachable only through their own tenant', () => {
  const { root, store } = newStore();
  const tenantA = tenantId('tenant-a');
  const tenantB = tenantId('tenant-b');
  const bytes = syntheticBytes('shared-content', 3000);
  const a = store.put(tenantA, bytes);
  const b = store.put(tenantB, bytes);
  assert.equal(a.digest, b.digest);
  assert.equal(b.created, true, 'not deduplicated against tenant A');
  assert.notEqual(a.ref, b.ref);
  const statA = statSync(blobPath(root, tenantA, a.digest));
  const statB = statSync(blobPath(root, tenantB, b.digest));
  assert.notEqual(statA.ino, statB.ino, 'distinct files');
  assert.equal(statA.nlink, 1);
  assert.equal(statB.nlink, 1, 'no shared hard link');

  const tenantC = tenantId('tenant-c');
  assert.throws(() => store.read(tenantC, a.digest), BlobNotFoundError);
  assert.throws(() => store.readRef(tenantB, a.ref), (error) => error instanceof StorageUsageError && /another tenant/.test(error.message));
  assert.throws(() => store.readRef(tenantC, a.ref), StorageUsageError);

  flipByte(blobPath(root, tenantB, b.digest), 10);
  assert.equal(store.check(tenantB, b.digest), 'corrupt');
  assert.deepEqual(store.read(tenantA, a.digest), bytes, "tenant B's corruption does not reach tenant A");
  assert.equal(store.dispose(tenantA, a.digest), true);
  assert.equal(store.check(tenantB, b.digest), 'corrupt', "disposing tenant A's blob leaves tenant B's");
  assert.deepEqual(store.list(tenantA), []);
  assert.deepEqual(store.list(tenantB), [b.digest]);
});

test('[BL-05] streaming writes hash as they write, honor the size limit and expected digest, and publish nothing on failure', async () => {
  const { root, store } = newStore({ maxBytes: 10_000 });
  const tenant = tenantId('tenant');
  const parts = [syntheticBytes('s1', 3000), syntheticBytes('s2', 3000), syntheticBytes('s3', 1000)];
  const whole = Buffer.concat(parts);
  async function* chunks(list, failAfter) {
    for (const [index, part] of list.entries()) {
      if (index === failAfter) throw new Error('synthetic source failure');
      yield part;
    }
  }

  const streamed = await store.putStream(tenant, chunks(parts), { expectedDigest: sha256(whole) });
  assert.equal(streamed.digest, sha256(whole));
  assert.equal(streamed.size, 7000);
  assert.deepEqual(store.read(tenant, streamed.digest), whole);

  const before = store.list(tenant);
  await assert.rejects(store.putStream(tenant, chunks([...parts, syntheticBytes('s4', 4000)])), BlobTooLargeError);
  await assert.rejects(store.putStream(tenant, chunks(parts, 2)), /synthetic source failure/);
  await assert.rejects(store.putStream(tenant, [syntheticBytes('x', 10)], { expectedDigest: sha256(whole) }), BlobDigestMismatchError);
  await assert.rejects(store.putStream(tenant, ['text chunk']), StorageUsageError);
  assert.throws(() => store.put(tenant, syntheticBytes('big', 10_001)), BlobTooLargeError);
  assert.throws(() => store.put(tenant, syntheticBytes('y', 10), { expectedDigest: sha256(whole) }), BlobDigestMismatchError);
  assert.throws(() => store.put(tenant, 'not bytes'), StorageUsageError);
  assert.deepEqual(store.list(tenant), before, 'no failed write published anything');
  assert.deepEqual(tmpEntries(root, tenant), [], 'no failed write left a temp file');
  assert.equal(store.put(tenant, syntheticBytes('exact-limit', 10_000)).size, 10_000);
});

test('[BL-06] a writer killed mid-write leaves no visible blob, and leftover partial files are swept', async () => {
  const { root, store } = newStore();
  const tenant = tenantId('tenant');
  const { done } = runWorker(['slow', root, tenant], {
    onStdout: (stdout, child) => {
      if (stdout.includes('writing')) child.kill('SIGKILL');
    },
  });
  const run = await done;
  assert.equal(run.signal, 'SIGKILL', run.stderr.slice(0, 400));
  assert.deepEqual(store.list(tenant), [], 'nothing was published');
  assert.deepEqual(readdirSync(join(root, 'tenants', tenant, 'sha256')), []);
  const partials = tmpEntries(root, tenant);
  assert.equal(partials.length, 1);
  assert.match(partials[0], /^[0-9a-f]{32}\.partial$/);
  assert.ok(statSync(join(root, 'tenants', tenant, 'tmp', partials[0])).size >= 3 * 4096, 'data had reached the temp file');

  assert.equal(store.sweepPartials(tenant), 1);
  assert.deepEqual(tmpEntries(root, tenant), []);
  assert.equal(store.sweepPartials(tenantId('unknown')), 0);
  assert.equal(store.put(tenant, syntheticBytes('after-crash', 100)).created, true);
});

test('[BL-07] roots, tenant ids, digests and refs are validated, and links in the namespace are refused', () => {
  const base = scratch();
  const usage = (fn, label) => assert.throws(fn, StorageUsageError, label);
  usage(() => openBlobStore({ root: 'relative/blobs' }), 'relative root');
  usage(() => openBlobStore({ root: join(base, 'missing') }), 'missing root');
  writeFileSync(join(base, 'a-file'), 'x');
  usage(() => openBlobStore({ root: join(base, 'a-file') }), 'file root');
  mkdirSync(join(base, 'real'));
  symlinkSync(join(base, 'real'), join(base, 'link'));
  usage(() => openBlobStore({ root: join(base, 'link') }), 'linked root');
  for (const maxBytes of [0, -1, 1.5, 1024 ** 3 + 1]) usage(() => openBlobStore({ root: base, maxBytes }), `maxBytes ${maxBytes}`);

  const { root, store } = newStore();
  const tenant = tenantId('tenant');
  const digest = store.put(tenant, syntheticBytes('valid', 10)).digest;
  for (const bad of ['short', '', 'x'.repeat(65), '../escape-tenant-id', 'tenant/with/slash-xx', null, 7]) {
    usage(() => store.put(bad, syntheticBytes('v', 1)), `put tenant ${String(bad)}`);
    usage(() => store.read(bad, digest), `read tenant ${String(bad)}`);
    usage(() => store.list(bad), `list tenant ${String(bad)}`);
  }
  for (const bad of [digest.toUpperCase(), digest.slice(1), `${digest}0`, '../../etc', '', null]) {
    usage(() => store.read(tenant, bad), `digest ${String(bad)}`);
    usage(() => store.dispose(tenant, bad), `dispose digest ${String(bad)}`);
  }
  for (const ref of [`tenants/${tenant}/sha256/${digest}/`, `tenants/${tenant}/sha1/${digest}`, `/tenants/${tenant}/sha256/${digest}`, `tenants/short/sha256/${digest}`, `tenants/${tenant}/sha256/${digest.toUpperCase()}`, 42]) {
    usage(() => parseBlobRef(ref), `ref ${String(ref)}`);
  }

  // A tenant directory replaced by a link to another tenant's namespace is refused.
  const other = tenantId('other');
  store.put(other, syntheticBytes('valid', 10));
  const victim = tenantId('victim');
  symlinkSync(join(root, 'tenants', other), join(root, 'tenants', victim));
  assert.throws(() => store.read(victim, digest), BlobIntegrityError);
  assert.throws(() => store.put(victim, syntheticBytes('valid', 10)), BlobIntegrityError);
  assert.throws(() => store.list(victim), BlobIntegrityError);
});

test('[BL-08] a write runs temp file, fsync, read-only, publish without replacement, directory fsync; a failed step publishes nothing', () => {
  const root = scratch();
  const tenant = tenantId('tenant');
  const log = [];
  const paths = new Map();
  const failures = new Set();
  const label = (path) => (path.endsWith('.partial') ? 'temp' : path.endsWith('/sha256') ? 'blob-dir' : path.includes('/sha256/') ? 'blob' : 'other');
  const recording = {
    ...nodeFsOps,
    open(path, flags, mode) {
      const fd = nodeFsOps.open(path, flags, mode);
      paths.set(fd, label(path));
      log.push(`open:${label(path)}`);
      return fd;
    },
    writeAll(fd, data) {
      log.push(`write:${paths.get(fd)}`);
      nodeFsOps.writeAll(fd, data);
    },
    fsync(fd) {
      log.push(`fsync:${paths.get(fd)}`);
      if (failures.has(`fsync:${paths.get(fd)}`)) throw Object.assign(new Error('synthetic EIO'), { code: 'EIO' });
      nodeFsOps.fsync(fd);
    },
    fchmod(fd, mode) {
      log.push(`fchmod:${paths.get(fd)}:${mode.toString(8)}`);
      nodeFsOps.fchmod(fd, mode);
    },
    close(fd) {
      log.push(`close:${paths.get(fd)}`);
      paths.delete(fd);
      nodeFsOps.close(fd);
    },
    link(existing, target) {
      log.push(`link:${label(existing)}->${label(target)}`);
      if (failures.has('link')) throw Object.assign(new Error('synthetic EIO'), { code: 'EIO' });
      nodeFsOps.link(existing, target);
    },
    unlink(path) {
      log.push(`unlink:${label(path)}`);
      nodeFsOps.unlink(path);
    },
  };
  const store = openBlobStore({ root, fsOps: recording });
  store.put(tenant, syntheticBytes('warm-up', 10)); // creates the tenant directories
  log.length = 0;

  const result = store.put(tenant, syntheticBytes('ordered', 2048));
  assert.equal(result.created, true);
  assert.deepEqual(log, [
    'open:temp',
    'write:temp',
    'fsync:temp',
    'fchmod:temp:400',
    'close:temp',
    'link:temp->blob',
    'open:blob-dir',
    'fsync:blob-dir',
    'close:blob-dir',
    'unlink:temp',
  ]);

  for (const failure of ['fsync:temp', 'link']) {
    failures.clear();
    failures.add(failure);
    const bytes = syntheticBytes(`fail-${failure}`, 512);
    assert.throws(() => store.put(tenant, bytes), /synthetic EIO/, failure);
    assert.equal(store.check(tenant, sha256(bytes)), 'missing', `${failure}: nothing published`);
    assert.deepEqual(tmpEntries(root, tenant), [], `${failure}: temp file removed`);
  }
});
