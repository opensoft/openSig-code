// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-12 (extended) and SEC-16 (extended) for the US2 composition (A-010 row
// ARTIFACT-ROUTES, request #46; T038 requests #39 Part F and #44): the composed server
// (src/server/main.ts startServer) with T038's finalization runner and the seal and
// trust-anchor settings that src/server/finalization.ts checks at startup.
// - SEC-12, settings: each refusal comes before anything is composed (no blob store directory,
//   no `listening` line), is a ServerConfigError naming the setting and the rule, and never
//   names the path. Controls: no seal settings start a server with no runner
//   (`finalization_not_configured`); a valid pair starts one, at 0600 and at 0400; a key file
//   whose custody is valid but whose bytes are no key still starts, because the main process
//   never reads the key (request #39 Q6: T037's worker child does, at each attempt); a valid
//   anchors file is counted on the `listening` line, with or without the seal pair.
//   A set anchors file holds at least one certificate (request #81 (10)).
// - SEC-12, the fault-flag case (request #86 (4)): T015's hook arms from the process's own
//   command line, so the startup checks refuse any argument equal to FAULT_HOOK_FLAG or starting
//   with `FAULT_HOOK_FLAG=`, well-formed or not, naming the flag and the rule, never the value.
//   The check: node src/server/main.ts, with the seal pair set, started with a well-formed flag
//   (a known phase and an absolute path), with the bare flag and with a malformed value, each
//   writes the refusal line and no `listening` line, composes nothing and exits 1. T015's own
//   parser is used only for premises: it accepts the well-formed flag and throws on the other
//   two. In-process, startServer with the flag in more spellings (with and without the seal
//   pair) calls no listener's listen(), starts no runner and composes nothing, so a refusal
//   moved after the bind fails here even before a `listening` line; a look-alike argument
//   still starts. The flag goes onto process.argv only for the duration of each in-process
//   start and is restored at once.
// - SEC-12, runner: the composition starts its runner exactly once, at its default interval.
//   The runner is built from exactly the values startup validated (request #81 (10)): the key
//   file's path, the certificate's DER and the anchors' PEM items, read once, with no path to
//   re-read them from; a runner given no anchors fails here (the preparation's M21). Its onError
//   is wired to `finalization_run_failed`, a warning with the error's name only (row RUN-ERRORS).
//   Over the composed database its reclaim moves an expired lease at the attempt limit to
//   `failed` with one envelope.finalization_failed; the retry route then answers through T038's
//   handler (403 for a sender, 202 for the tenant_admin, replayed byte for byte, 409 for the key
//   reused with another body) and audits the operator once.
// - SEC-16, runner (requests #80 (3), #81 (11)): once both listeners have closed, shutdown calls
//   the runner's stop() and awaits it before the ceremony drain, the sweeper's stop and the
//   database's close. The real stop() runs; the spy only holds the settlement the composition
//   awaits until the test releases it, so a composition that does not await it fails (M9), as
//   one that never calls it does (M8).
// Keys and certificates are synthetic, generated in memory at run time (support.mjs); a private
// key is written only as a 0600 file in its own mkdtemp directory, removed by cleanup(). The
// runner case keeps the runner's timer off (its start is recorded, not called through), so no
// scheduled run races the steps it drives; T038's own tests cover the scheduling. The only timers
// are hang guards.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, symlinkSync } from 'node:fs';
import { Server as NetServer } from 'node:net';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { ArtifactApi } from '../../src/api/artifacts/index.ts';
import { FinalizationRetryApi } from '../../src/api/envelopes/retry.ts';
import { RecipientCeremony } from '../../src/api/recipients/ceremony.ts';
import { FAULT_HOOK_FLAG, parseFaultHookFlag } from '../../src/domain/finalization/fault-hook.ts';
import { ExpirySweeper } from '../../src/jobs/expiry.ts';
import { FinalizationRunner } from '../../src/jobs/finalize.ts';
import { createParseServiceForTests } from '../../src/pdf/service.ts';
import { SEAL_CERT_FILE_LIMIT } from '../../src/server/finalization.ts';
import { startServer } from '../../src/server/main.ts';
import { Database } from '../../src/storage/db/index.ts';
import { insertFinalizationReservation } from '../../src/storage/repositories/approvals.ts';
import { compareAndSetEnvelope } from '../../src/storage/repositories/envelopes.ts';
import { grantLease, LEASE_EXPIRED_ERROR_CODE } from '../../src/storage/repositories/jobs.ts';
import { splitPemCertificates } from '../../src/verifier/index.ts';
import { rsaKeyPair } from '../integrity/product/helpers/cert-build.mjs';
import { call, guarded, rows, testSide, turn } from './composed-support.mjs';
import { ALPHA, anchorsFile, authFile, bearer, certificateFor, cleanup, composedEnv, REPO, sealFiles, sealKeyPair, tempDir } from './support.mjs';

after(cleanup);

// T033's own plan for an empty launcher set: no probe runs, so each start is fast.
const unprobedPlan = createParseServiceForTests({ launchers: [] }).plan;
const start = (env, lines = []) => guarded(startServer(env, { logSink: (line) => lines.push(line), parsePlan: unprobedPlan }), 'startServer');
const records = (lines) => lines.map((line) => JSON.parse(line));
const newKey = () => `ik-${randomBytes(18).toString('base64url')}`;

/** A PEM block labelled CERTIFICATE whose body is not a certificate (built at run time). */
const notACertificate = () => `-----BEGIN CERTIFICATE-----\n${randomBytes(48).toString('base64')}\n-----END CERTIFICATE-----\n`;

/**
 * node src/server/main.ts with `args` and `env`: a start the caller expects to be refused. A child
 * that writes a `listening` line anyway is sent SIGTERM at once (it closes and exits 0), and one
 * still running when the hang guard fires is killed, so a failing case leaves no server behind.
 */
async function refusedEntrypoint(args, env, label) {
  const child = spawn(process.execPath, [join(REPO, 'src', 'server', 'main.ts'), ...args], {
    cwd: REPO,
    env: { PATH: process.env.PATH ?? '', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const output = { stdout: '', stderr: '' };
  let stopping = false;
  child.stdout.setEncoding('utf8').on('data', (chunk) => {
    output.stdout += chunk;
    if (!stopping && output.stdout.includes('"event":"listening"')) {
      stopping = true;
      child.kill('SIGTERM');
    }
  });
  child.stderr.setEncoding('utf8').on('data', (chunk) => (output.stderr += chunk));
  const exited = new Promise((resolveExit) => child.on('close', (exitCode) => resolveExit(exitCode)));
  try {
    const code = await guarded(exited, `${label}: entrypoint exit`, 60_000);
    return { code, ...output };
  } finally {
    // Still running here means a failing case: this fixture's own child gets SIGTERM, a bounded
    // grace, then SIGKILL, each awaited through its own exit, so no server outlives the case.
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      if (!(await within(exited, 5_000))) {
        child.kill('SIGKILL');
        await within(exited, 5_000);
      }
    }
  }
}

/** Whether `promise` settles within `ms`; the timer is cleared either way, so it holds nothing open. */
async function within(promise, ms) {
  let timer;
  try {
    return await Promise.race([promise.then(() => true), new Promise((resolveWait) => (timer = setTimeout(resolveWait, ms, false)))]);
  } finally {
    clearTimeout(timer);
  }
}

test('[SEC-12] startup checks the seal and trust-anchor settings before composing anything: each refusal names the setting and the rule, never the path; valid settings start, with or without a runner', async () => {
  const valid = sealFiles();
  const certificatePem = certificateFor(sealKeyPair()).pem;
  const fifo = (label) => {
    const path = join(tempDir(`${label}-fifo`), label);
    assert.equal(spawnSync('mkfifo', ['-m', '600', path]).status, 0, `premise: a FIFO was created for ${label}`);
    return path;
  };
  const link = (target, label) => {
    const path = join(tempDir(`${label}-link`), label);
    symlinkSync(target, path);
    return path;
  };
  const directory = (label) => {
    const path = join(tempDir(`${label}-dir`), label);
    mkdirSync(path, { mode: 0o700 });
    return path;
  };
  const missing = (label) => join(tempDir(`${label}-missing`), 'absent');
  const anchor = certificateFor(rsaKeyPair(2048), { commonName: 'T031 Development Anchor (anchor.example.test)', serial: 0x3103 }).pem;
  const key = { OPENSIG_SEAL_CERT_FILE: valid.OPENSIG_SEAL_CERT_FILE };
  const cert = { OPENSIG_SEAL_KEY_FILE: valid.OPENSIG_SEAL_KEY_FILE };
  const certText = (text) => ({ ...cert, OPENSIG_SEAL_CERT_FILE: sealFiles({ certificate: text }).OPENSIG_SEAL_CERT_FILE });
  const keyFileOf = (options) => ({ ...key, OPENSIG_SEAL_KEY_FILE: sealFiles(options).OPENSIG_SEAL_KEY_FILE });

  const cases = {
    'only the key': [{ OPENSIG_SEAL_KEY_FILE: valid.OPENSIG_SEAL_KEY_FILE }, /^OPENSIG_SEAL_CERT_FILE refused: the setting is required when OPENSIG_SEAL_KEY_FILE is set/],
    'only the certificate': [{ OPENSIG_SEAL_CERT_FILE: valid.OPENSIG_SEAL_CERT_FILE }, /^OPENSIG_SEAL_KEY_FILE refused: the setting is required when OPENSIG_SEAL_CERT_FILE is set/],
    'a relative key path': [{ ...key, OPENSIG_SEAL_KEY_FILE: 'relative/seal.key' }, /^OPENSIG_SEAL_KEY_FILE must be an absolute path$/],
    'a relative certificate path': [{ ...cert, OPENSIG_SEAL_CERT_FILE: 'relative/seal-cert.pem' }, /^OPENSIG_SEAL_CERT_FILE must be an absolute path$/],
    'a relative anchors path': [{ OPENSIG_TRUST_ANCHORS_FILE: 'relative/anchors.pem' }, /^OPENSIG_TRUST_ANCHORS_FILE must be an absolute path$/],
    'a missing key file': [{ ...key, OPENSIG_SEAL_KEY_FILE: missing('key') }, /^OPENSIG_SEAL_KEY_FILE refused: the file does not exist/],
    'a symbolic link to a valid key': [{ ...key, OPENSIG_SEAL_KEY_FILE: link(valid.OPENSIG_SEAL_KEY_FILE, 'key') }, /^OPENSIG_SEAL_KEY_FILE refused: the path must not be a symbolic link$/],
    'a key directory': [{ ...key, OPENSIG_SEAL_KEY_FILE: directory('key') }, /^OPENSIG_SEAL_KEY_FILE refused: the path must name a regular file$/],
    'a key FIFO (never opened, so startup cannot block on it)': [{ ...key, OPENSIG_SEAL_KEY_FILE: fifo('key') }, /^OPENSIG_SEAL_KEY_FILE refused: the path must name a regular file$/],
    'a group-readable key (0640)': [keyFileOf({ keyMode: 0o640 }), /^OPENSIG_SEAL_KEY_FILE refused: the file is group- or other-accessible/],
    'an other-readable key (0604)': [keyFileOf({ keyMode: 0o604 }), /^OPENSIG_SEAL_KEY_FILE refused: the file is group- or other-accessible/],
    'a group-writable key (0620)': [keyFileOf({ keyMode: 0o620 }), /^OPENSIG_SEAL_KEY_FILE refused: the file is group- or other-accessible/],
    'an empty key file': [keyFileOf({ keyBytes: Buffer.alloc(0) }), /^OPENSIG_SEAL_KEY_FILE refused: the file must hold 1 to 16384 bytes$/],
    'a key file over 16 KiB': [keyFileOf({ keyBytes: Buffer.alloc(16 * 1024 + 1, 0x41) }), /^OPENSIG_SEAL_KEY_FILE refused: the file must hold 1 to 16384 bytes$/],
    'a missing certificate file': [{ ...cert, OPENSIG_SEAL_CERT_FILE: missing('cert') }, /^OPENSIG_SEAL_CERT_FILE refused: the file does not exist/],
    'a symbolic link to a valid certificate': [{ ...cert, OPENSIG_SEAL_CERT_FILE: link(valid.OPENSIG_SEAL_CERT_FILE, 'cert') }, /^OPENSIG_SEAL_CERT_FILE refused: the path must not be a symbolic link$/],
    'a certificate FIFO': [{ ...cert, OPENSIG_SEAL_CERT_FILE: fifo('cert') }, /^OPENSIG_SEAL_CERT_FILE refused: the path must name a regular file$/],
    'an empty certificate file': [certText(''), new RegExp(`^OPENSIG_SEAL_CERT_FILE refused: the file must hold 1 to ${SEAL_CERT_FILE_LIMIT} bytes$`)],
    'a certificate file over its limit': [certText('A'.repeat(SEAL_CERT_FILE_LIMIT + 1)), new RegExp(`^OPENSIG_SEAL_CERT_FILE refused: the file must hold 1 to ${SEAL_CERT_FILE_LIMIT} bytes$`)],
    'certificate DER (not PEM text)': [certText(certificateFor(sealKeyPair()).der), /^OPENSIG_SEAL_CERT_FILE refused: the file is not UTF-8 text$/],
    'two certificates': [certText(`${certificatePem}${certificatePem}`), /^OPENSIG_SEAL_CERT_FILE refused: the file must hold exactly one PEM certificate and nothing else$/],
    'a certificate and its private key': [certText(`${certificatePem}${sealKeyPair().privateKey.export({ type: 'pkcs8', format: 'pem' })}`), /^OPENSIG_SEAL_CERT_FILE refused: the file must hold exactly one PEM certificate and nothing else$/],
    'stray text beside the certificate': [certText(`${certificatePem}synthetic stray text\n`), /^OPENSIG_SEAL_CERT_FILE refused: the file must hold exactly one PEM certificate and nothing else$/],
    'a CERTIFICATE block that is not a certificate': [certText(notACertificate()), /^OPENSIG_SEAL_CERT_FILE refused: the certificate cannot be parsed$/],
    'an RSA-2048 certificate': [certText(certificateFor(rsaKeyPair(2048)).pem), /^OPENSIG_SEAL_CERT_FILE refused: the certificate is not usable for the seal \([a-z-]+\)$/],
    'an EC certificate': [certText(certificateFor(generateKeyPairSync('ec', { namedCurve: 'P-256' })).pem), /^OPENSIG_SEAL_CERT_FILE refused: the certificate is not usable for the seal \([a-z-]+\)$/],
    'a missing anchors file': [{ OPENSIG_TRUST_ANCHORS_FILE: missing('anchors') }, /^OPENSIG_TRUST_ANCHORS_FILE refused: the file does not exist/],
    'a symbolic link to a valid anchors file': [{ OPENSIG_TRUST_ANCHORS_FILE: link(anchorsFile(anchor), 'anchors') }, /^OPENSIG_TRUST_ANCHORS_FILE refused: the path must not be a symbolic link$/],
    'an anchors directory': [{ OPENSIG_TRUST_ANCHORS_FILE: directory('anchors') }, /^OPENSIG_TRUST_ANCHORS_FILE refused: the path must name a regular file$/],
    'an empty anchors file': [{ OPENSIG_TRUST_ANCHORS_FILE: anchorsFile('') }, /^OPENSIG_TRUST_ANCHORS_FILE refused: the file must hold 1 to 1048576 bytes$/],
    // Request #81 (10): a set anchors file holds at least one certificate.
    'an anchors file with no certificate (white space only)': [{ OPENSIG_TRUST_ANCHORS_FILE: anchorsFile('\n\n') }, /^OPENSIG_TRUST_ANCHORS_FILE refused: anchors-invalid/],
    'stray text in the anchors file': [{ OPENSIG_TRUST_ANCHORS_FILE: anchorsFile(`${anchor}synthetic stray text\n`) }, /^OPENSIG_TRUST_ANCHORS_FILE refused: anchors-invalid/],
    'a private key in the anchors file': [{ OPENSIG_TRUST_ANCHORS_FILE: anchorsFile(`${anchor}${rsaKeyPair(2048).privateKey.export({ type: 'pkcs8', format: 'pem' })}`) }, /^OPENSIG_TRUST_ANCHORS_FILE refused: anchors-invalid/],
    'an anchor block that is not a certificate (refused here, not at every verification)': [{ OPENSIG_TRUST_ANCHORS_FILE: anchorsFile(`${anchor}${notACertificate()}`) }, /^OPENSIG_TRUST_ANCHORS_FILE refused: anchors-invalid/],
    'more than 32 anchors': [{ OPENSIG_TRUST_ANCHORS_FILE: anchorsFile(anchor.repeat(33)) }, /^OPENSIG_TRUST_ANCHORS_FILE refused: anchors-invalid/],
    'an invalid anchors file beside a valid seal pair': [{ ...valid, OPENSIG_TRUST_ANCHORS_FILE: anchorsFile(notACertificate()) }, /^OPENSIG_TRUST_ANCHORS_FILE refused: anchors-invalid/],
  };
  for (const [label, [overrides, pattern]] of Object.entries(cases)) {
    const env = composedEnv(overrides);
    const lines = [];
    let error = null;
    try {
      const running = await start(env, lines);
      await running.close();
    } catch (caught) {
      error = caught;
    }
    assert.ok(error !== null, `${label}: the server must refuse to start`);
    assert.equal(error.name, 'ServerConfigError', `${label}: ${error.name}`);
    assert.match(error.message, pattern, label);
    for (const path of Object.values(overrides)) assert.equal(error.message.includes(path), false, `${label}: the refusal never names a path`);
    assert.equal(existsSync(join(env.OPENSIG_DATA_DIR, 'blobs')), false, `${label}: refused before anything was composed`);
    assert.deepEqual(lines.filter((line) => line.includes('"event":"listening"')), [], `${label}: nothing listens`);
  }

  // KEY-02 (T013): PEM private-key text visible in this process's environment refuses a seal pair at startup.
  const canary = 'OPENSIG_T031_KEY02_CANARY';
  process.env[canary] = rsaKeyPair(2048).privateKey.export({ type: 'pkcs8', format: 'pem' });
  let starting = null;
  try {
    const env = composedEnv(valid);
    starting = start(env);
    await assert.rejects(starting, (error) => error.name === 'ServerConfigError' && /^OPENSIG_SEAL_KEY_FILE refused: private-key material is present in the process environment/.test(error.message), 'KEY-02: refused while key text is in the environment');
    assert.equal(existsSync(join(env.OPENSIG_DATA_DIR, 'blobs')), false, 'KEY-02: refused before anything was composed');
  } finally {
    delete process.env[canary];
    // A start that was not refused is closed (listeners, runner, sweeper), so a failing case lets the file end.
    const started = starting === null ? null : await starting.catch(() => null);
    if (started !== null) await guarded(started.close(), 'KEY-02: close the server a non-refusing start returned');
  }

  // Controls.
  const controls = [
    ['no seal settings', {}, 'not-configured', 0],
    ['a valid pair, key 0600', valid, 'running', 0],
    ['a valid pair, key 0400', { ...valid, OPENSIG_SEAL_KEY_FILE: sealFiles({ keyMode: 0o400 }).OPENSIG_SEAL_KEY_FILE }, 'running', 0],
    // The main process checks the key file's custody only; its bytes are read in T037's worker child at each attempt.
    ['a custody-valid key file whose bytes are no key', { ...valid, OPENSIG_SEAL_KEY_FILE: sealFiles({ keyBytes: randomBytes(64) }).OPENSIG_SEAL_KEY_FILE }, 'running', 0],
    ['a valid pair and two anchors', { ...valid, OPENSIG_TRUST_ANCHORS_FILE: anchorsFile(`${anchor}${certificatePem}`) }, 'running', 2],
    ['one anchor and no seal settings', { OPENSIG_TRUST_ANCHORS_FILE: anchorsFile(anchor) }, 'not-configured', 1],
  ];
  for (const [label, overrides, finalization, anchors] of controls) {
    const env = composedEnv(overrides);
    const lines = [];
    const running = await start(env, lines);
    try {
      const listening = records(lines).find((record) => record.event === 'listening');
      assert.deepEqual([listening?.finalization, listening?.trust_anchors], [finalization, anchors], `${label}: the listening line says ${listening?.finalization} with ${listening?.trust_anchors} anchor(s)`);
      assert.equal(running.composition.trustAnchors, anchors, `${label}: ${running.composition.trustAnchors} anchor(s) composed`);
      const notConfigured = records(lines).filter((record) => record.event === 'finalization_not_configured');
      assert.equal(notConfigured.length, finalization === 'running' ? 0 : 1, `${label}: ${notConfigured.length} finalization_not_configured line(s)`);
      assert.equal(running.composition.finalization instanceof FinalizationRunner, finalization === 'running', `${label}: a runner is composed exactly when the seal pair is set`);
      assert.ok(running.composition.artifacts instanceof ArtifactApi && running.composition.finalizationRetry instanceof FinalizationRetryApi, `${label}: the artifact and retry APIs are composed either way`);
    } finally {
      await running.close();
    }
  }

  // node src/server/main.ts with half a seal pair exits 1 with the refusal and never listens.
  const output = await refusedEntrypoint([], composedEnv({ OPENSIG_SEAL_KEY_FILE: valid.OPENSIG_SEAL_KEY_FILE }), 'half a seal pair');
  assert.equal(output.code, 1, `the entrypoint exits ${output.code}`);
  assert.match(output.stderr, /^opensig: OPENSIG_SEAL_CERT_FILE refused: the setting is required when OPENSIG_SEAL_KEY_FILE is set/m);
  assert.doesNotMatch(output.stdout, /"event":"listening"/);
});

test('[SEC-12] the composition starts T038\'s runner once at its default interval, built from exactly the validated values with its onError wired; over the composed database it reclaims an expired lease at the attempt limit, and the retry route answers through T038\'s handler and audits the operator', async () => {
  const started = [];
  const originalStart = FinalizationRunner.prototype.start;
  FinalizationRunner.prototype.start = function recordedStart(...args) {
    // Recorded, not called through: no scheduled run races the steps below.
    started.push({ runner: this, args });
  };
  // The seal certificate and two anchors, built here so the test knows the values startup must hand the runner.
  const certificate = certificateFor(sealKeyPair(), { serial: 0x3104 });
  const anchorsText = [0x3105, 0x3106].map((serial) => certificateFor(rsaKeyPair(2048), { commonName: 'T031 Development Anchor (anchor.example.test)', serial }).pem).join('');
  const env = composedEnv({ OPENSIG_OPERATOR_AUTH_FILE: authFile(), ...sealFiles({ certificate: certificate.pem }), OPENSIG_TRUST_ANCHORS_FILE: anchorsFile(anchorsText) });
  const lines = [];
  let running;
  try {
    running = await start(env, lines);
  } finally {
    FinalizationRunner.prototype.start = originalStart;
  }
  const side = testSide(env);
  const job = (id) => rows(env.OPENSIG_DATABASE, 'SELECT status, attempt_count, max_attempts, last_error_code FROM signing_jobs WHERE envelope_id = ?', id)[0];
  const audit = (id, type) => rows(env.OPENSIG_DATABASE, 'SELECT actor_kind, metadata_json FROM audit_events WHERE envelope_id = ? AND type = ? ORDER BY seq', id, type);
  const outbox = (id, type) => rows(env.OPENSIG_DATABASE, 'SELECT type FROM outbox_events WHERE envelope_id = ? AND type = ?', id, type);
  try {
    assert.equal(started.length, 1, `the runner is started ${started.length} time(s)`);
    assert.equal(started[0].runner, running.composition.finalization, 'the composition\'s own runner');
    assert.deepEqual(started[0].args, [], 'at its default interval');

    // Request #81 (10): the runner is built from exactly the values startup validated, read once.
    const options = running.composition.finalizationOptions;
    assert.ok(options !== null && Object.isFrozen(options), 'premise: the composition keeps the runner\'s frozen options');
    const expectedAnchors = splitPemCertificates(anchorsText);
    assert.equal(expectedAnchors.length, 2, 'premise: the anchors file holds two certificates');
    assert.deepEqual([...options.anchors], expectedAnchors, `the runner gets the ${expectedAnchors.length} validated anchors (it got ${options.anchors.length})`);
    assert.equal(options.seal.keyFile, env.OPENSIG_SEAL_KEY_FILE, 'the runner opens the validated key file for each attempt');
    assert.ok(Buffer.from(options.seal.certificateDer).equals(Buffer.from(certificate.der)), `the runner gets the validated certificate's DER (${options.seal.certificateDer.length} bytes, expected ${certificate.der.length})`);
    assert.equal(options.seal.developmentCertificate, true, 'a development seal');
    assert.deepEqual(Object.keys(options.seal).sort(), ['certificateDer', 'developmentCertificate', 'keyFile'], 'no certificate or anchors path reaches the runner, so nothing is re-read');
    const { composition } = running;
    assert.ok(options.db === composition.db && options.audit === composition.audit && options.blobs === composition.blobs, 'the runner shares the composition\'s database, audit writer and blob store');

    // Row RUN-ERRORS: the runner's onError is the bounded finalization_run_failed warning, with the error's name only.
    assert.equal(typeof options.onError, 'function', 'the runner\'s onError is wired');
    const before = records(lines).filter((record) => record.event === 'finalization_run_failed').length;
    options.onError(new RangeError('synthetic run failure detail-canary-3107'));
    const reported = records(lines).filter((record) => record.event === 'finalization_run_failed');
    assert.equal(reported.length, before + 1, `${reported.length - before} finalization_run_failed line(s) for one run error`);
    const line = reported.at(-1);
    assert.deepEqual([line.level, line.error_name], ['warn', 'RangeError'], `the line is ${line.level} with error_name ${line.error_name}`);
    assert.equal(JSON.stringify(line).includes('detail-canary-3107'), false, 'the line carries the error\'s name only, never its message');

    // A crashed attempt, set up on the test side: a finalizing envelope whose one allowed attempt
    // holds a lease that expired a minute ago.
    const { envelope: sent } = await side.sentEnvelope();
    const store = side.db.forTenant(ALPHA.id);
    const past = new Date(Date.now() - 60_000);
    const reserved = sent.version + 1;
    side.db.transaction(() => {
      assert.ok(compareAndSetEnvelope(store, sent.id, sent.version, { state: 'finalizing', approvalsComplete: true, updatedAt: new Date().toISOString() }), 'premise: the envelope moved to finalizing');
      insertFinalizationReservation(store, { envelopeId: sent.id, reservedVersion: reserved, maxAttempts: 1, now: past.toISOString() });
    });
    const grant = side.db.transaction(() => grantLease(store, sent.id, { owner: 'test-side-crashed-attempt', now: past, leaseMs: 1_000 }));
    assert.ok(grant !== null, 'premise: the crashed attempt held the lease');
    assert.deepEqual({ ...job(sent.id) }, { status: 'running', attempt_count: 1, max_attempts: 1, last_error_code: null }, 'premise: one attempt of one, running');

    // The composed runner, over the composed database: the reclaim moves the job to failed once.
    const report = await guarded(running.composition.finalization.runOnce(), 'one composed run');
    assert.deepEqual([report.reclaimed, report.attempts.length], [1, 0], `the run reclaimed ${report.reclaimed} lease(s) and made ${report.attempts.length} attempt(s)`);
    assert.deepEqual([job(sent.id).status, job(sent.id).last_error_code], ['failed', LEASE_EXPIRED_ERROR_CODE], `the job is ${job(sent.id).status} (${job(sent.id).last_error_code})`);
    assert.equal(outbox(sent.id, 'envelope.finalization_failed').length, 1, 'one envelope.finalization_failed in the outbox');
    assert.equal(audit(sent.id, 'envelope.finalization_failed').length, 1, 'one envelope.finalization_failed audit event');
    const again = await guarded(running.composition.finalization.runOnce(), 'a second composed run');
    assert.equal(again.reclaimed, 0, `a second run reclaims ${again.reclaimed}: the failure is announced once`);

    // The retry route, through T038's handler on the composed server.
    const path = `/v1/envelopes/${sent.id}/finalization/retry`;
    const key = newKey();
    const bySender = await call(running.port, { method: 'POST', path, headers: { authorization: `Bearer ${bearer('sender')}`, 'idempotency-key': newKey() }, body: { expected_version: reserved } });
    assert.deepEqual([bySender.status, bySender.json?.code], [403, 'forbidden'], `a sender's retry: ${bySender.status} ${bySender.json?.code}`);
    assert.equal(audit(sent.id, 'envelope.finalization_retried').length, 0, 'a refused retry is not audited');
    const retried = await call(running.port, { method: 'POST', path, headers: { authorization: `Bearer ${bearer('admin')}`, 'idempotency-key': key }, body: { expected_version: reserved } });
    assert.deepEqual([retried.status, retried.json?.id, retried.json?.state], [202, sent.id, 'finalizing'], `the tenant_admin's retry: ${retried.status} ${retried.json?.state}`);
    assert.deepEqual({ ...job(sent.id) }, { status: 'retryable', attempt_count: 1, max_attempts: 2, last_error_code: LEASE_EXPIRED_ERROR_CODE }, 'from failed at the limit, max_attempts rose by exactly one');
    const events = audit(sent.id, 'envelope.finalization_retried');
    assert.equal(events.length, 1, `${events.length} envelope.finalization_retried event(s)`);
    assert.equal(events[0].actor_kind, 'human-operator', `the retry is audited with the operator as actor (${events[0].actor_kind})`);
    assert.deepEqual(JSON.parse(events[0].metadata_json), { envelope_version: reserved, attempt_count: 1, max_attempts: 2 });
    const replay = await call(running.port, { method: 'POST', path, headers: { authorization: `Bearer ${bearer('admin')}`, 'idempotency-key': key }, body: { expected_version: reserved } });
    assert.deepEqual([replay.status, replay.bytes.equals(retried.bytes)], [202, true], `the replay answers ${replay.status} with the same ${replay.bytes.length} bytes`);
    assert.equal(audit(sent.id, 'envelope.finalization_retried').length, 1, 'the replay writes no second audit event');
    const conflict = await call(running.port, { method: 'POST', path, headers: { authorization: `Bearer ${bearer('admin')}`, 'idempotency-key': key }, body: { expected_version: reserved + 1 } });
    assert.deepEqual([conflict.status, conflict.json?.code], [409, 'idempotency_conflict'], `the key reused with another body: ${conflict.status} ${conflict.json?.code}`);
  } finally {
    side.close();
    await running.close();
  }
});

test('[SEC-16] once both listeners have closed, shutdown awaits the finalization runner\'s stop() before the ceremony drain, the sweeper\'s stop and the database\'s close', async () => {
  const socketPath = join(tempDir('relay'), 'opensig.sock');
  const env = composedEnv({ OPENSIG_RELAY_SOCKET: socketPath, ...sealFiles() });
  const order = [];
  // The server's own `closed` line, as its log sink receives it.
  const sink = (line) => {
    if (line.includes('"event":"closed"')) order.push('closed');
  };
  const running = await guarded(startServer(env, { logSink: sink, parsePlan: unprobedPlan }), 'startServer');
  const original = {
    stop: FinalizationRunner.prototype.stop,
    drain: RecipientCeremony.prototype.drain,
    sweeperStop: ExpirySweeper.prototype.stop,
    close: Database.prototype.close,
  };
  // The real stop() runs at once; only the settlement the composition awaits is held until the test releases it.
  let releaseStop;
  const stopReleased = new Promise((resolveRelease) => {
    releaseStop = resolveRelease;
  });
  let stopCalls = 0;
  let markStopCalled;
  const stopCalled = new Promise((resolveCalled) => {
    markStopCalled = resolveCalled;
  });
  FinalizationRunner.prototype.stop = function spiedStop(...args) {
    if (this !== running.composition.finalization) return original.stop.apply(this, args);
    stopCalls += 1;
    markStopCalled();
    order.push(`runner stop called (listening: ${running.listeners.map((listener) => listener.listening).join(',')})`);
    const stopped = original.stop.apply(this, args);
    return Promise.all([stopped, stopReleased]).then(() => {
      order.push('runner stop settled');
    });
  };
  RecipientCeremony.prototype.drain = function spiedDrain(...args) {
    if (this === running.composition.ceremony) order.push('drain called');
    return original.drain.apply(this, args);
  };
  ExpirySweeper.prototype.stop = function spiedSweeperStop(...args) {
    if (this === running.composition.sweeper) order.push('sweeper stopped');
    return original.sweeperStop.apply(this, args);
  };
  Database.prototype.close = function spiedClose(...args) {
    if (this === running.composition.db) order.push('database closed');
    return original.close.apply(this, args);
  };
  let closing = null;
  try {
    assert.ok(running.composition.finalization instanceof FinalizationRunner, 'premise: the seal pair composed a runner');
    assert.deepEqual(running.listeners.map((listener) => listener.listening), [true, true], 'premise: both listeners are listening');
    let settled = false;
    closing = running.close();
    closing.then(() => {
      settled = true;
    });
    // Barrier: stop() was called, or close() settled without calling it (a head that never stops the runner).
    await guarded(Promise.race([stopCalled, closing]), 'the runner\'s stop() was called or close() settled');
    // A few macrotask turns: a composition that did not await stop() would reach the drain, the sweeper and the database now.
    await turn();
    await turn();
    await turn();
    assert.deepEqual([...order], ['runner stop called (listening: false,false)'], `while stop() is unsettled nothing after it runs (${order.join(' > ')})`);
    assert.equal(settled, false, 'close() waits for the runner\'s stop()');
    releaseStop();
    await guarded(closing, 'close() settles');
    assert.equal(stopCalls, 1, `the runner's stop() was called ${stopCalls} time(s)`);
    assert.deepEqual(
      order,
      ['runner stop called (listening: false,false)', 'runner stop settled', 'drain called', 'sweeper stopped', 'database closed', 'closed'],
      `the shutdown order: ${order.join(' > ')}`,
    );
  } finally {
    releaseStop();
    FinalizationRunner.prototype.stop = original.stop;
    RecipientCeremony.prototype.drain = original.drain;
    ExpirySweeper.prototype.stop = original.sweeperStop;
    Database.prototype.close = original.close;
    if (closing !== null) await guarded(closing, 'final close');
    await running.close();
  }
});

test('[SEC-12] fault-flag case: the startup checks refuse any command-line argument equal to T015\'s fault-hook flag or starting with it and `=`, well-formed or not; the entrypoint started with a well-formed flag, the bare flag and a malformed value each writes the refusal line and no listening line and exits 1, and in-process nothing is composed, bound or started (request #86 (4))', async () => {
  const seal = sealFiles();
  // An absolute release path that is never created: the refusal comes before anything could open it.
  const release = join(tempDir('fault-release'), 'release.fifo');
  // The refusal names the flag and the rule, never the argument's value (request #86 (4)).
  const refusal = `${FAULT_HOOK_FLAG} refused: no command-line argument may equal ${FAULT_HOOK_FLAG} or start with ${FAULT_HOOK_FLAG}=, well-formed or not; the flag arms the test fault hook`;
  const valueOf = (arg) => arg.slice(FAULT_HOOK_FLAG.length + 1);
  const wellFormed = `${FAULT_HOOK_FLAG}=compose:${release}`;
  const malformed = `${FAULT_HOOK_FLAG}=seal:relative/release.fifo`;
  const lookAlike = `${FAULT_HOOK_FLAG}s=compose:${release}`;
  // Premises from T015's own parser (used for nothing else): what is well-formed and what is not.
  assert.deepEqual(parseFaultHookFlag([wellFormed]), { phase: 'compose', releasePath: release }, 'premise: T015 accepts the well-formed flag (a known phase and an absolute path)');
  assert.throws(() => parseFaultHookFlag([FAULT_HOOK_FLAG]), TypeError, 'premise: T015 throws on the bare flag');
  assert.throws(() => parseFaultHookFlag([malformed]), TypeError, 'premise: T015 throws on the malformed value');
  assert.equal(parseFaultHookFlag([lookAlike]), null, 'premise: T015 ignores the look-alike');

  // The check: node src/server/main.ts, with the seal pair set, started three ways.
  const entrypoint = async (label, arg) => {
    const env = composedEnv(seal);
    const output = await refusedEntrypoint([arg], env, label);
    const written = `${output.stdout}${output.stderr}`;
    assert.equal(output.code, 1, `${label}: the entrypoint exits ${output.code}`);
    assert.ok(output.stderr.split('\n').includes(`opensig: ${refusal}`), `${label}: the refusal line is written (stderr: ${JSON.stringify(output.stderr.slice(0, 600))})`);
    assert.doesNotMatch(written, /"event":"listening"/, `${label}: no listening line`);
    if (valueOf(arg) !== '') assert.equal(written.includes(valueOf(arg)), false, `${label}: the refusal never names the value`);
    assert.equal(written.includes(release), false, `${label}: the release path is never written`);
    assert.equal(existsSync(join(env.OPENSIG_DATA_DIR, 'blobs')), false, `${label}: refused before anything was composed`);
  };
  await entrypoint('a well-formed flag', wellFormed);
  await entrypoint('the bare flag', FAULT_HOOK_FLAG);
  await entrypoint('a malformed value', malformed);

  // In-process: spies that only record while a start with the flag is in progress.
  const spellings = {
    'a well-formed flag': [[wellFormed], seal],
    'a well-formed flag with no seal settings (refused whether or not a runner would be composed)': [[wellFormed], {}],
    'the bare flag': [[FAULT_HOOK_FLAG], seal],
    'an empty value': [[`${FAULT_HOOK_FLAG}=`], seal],
    'an unknown phase': [[`${FAULT_HOOK_FLAG}=nowhere:${release}`], seal],
    'a relative release path': [[malformed], seal],
    'the flag given twice': [[wellFormed, wellFormed], seal],
  };
  let watching = false;
  const listened = [];
  const started = [];
  const original = { listen: NetServer.prototype.listen, start: FinalizationRunner.prototype.start };
  NetServer.prototype.listen = function recordedListen(...args) {
    if (watching) listened.push('listen');
    return original.listen.apply(this, args);
  };
  FinalizationRunner.prototype.start = function recordedStart(...args) {
    if (watching) started.push('start');
    return original.start.apply(this, args);
  };
  const originalArgv = process.argv;
  /** startServer with `args` on process.argv for the duration of the start only. */
  const startWith = async (env, args, lines) => {
    process.argv = [...originalArgv, ...args];
    watching = true;
    try {
      return await start(env, lines);
    } finally {
      watching = false;
      process.argv = originalArgv;
    }
  };
  try {
    for (const [label, [args, overrides]] of Object.entries(spellings)) {
      listened.length = 0;
      started.length = 0;
      const env = composedEnv(overrides);
      const lines = [];
      let error = null;
      try {
        const running = await startWith(env, args, lines);
        await running.close();
      } catch (caught) {
        error = caught;
      }
      assert.ok(error !== null, `${label}: the server must refuse to start`);
      assert.equal(error.name, 'ServerConfigError', `${label}: ${error.name}`);
      assert.equal(error.message, refusal, label);
      for (const arg of args) if (valueOf(arg) !== '') assert.equal(error.message.includes(valueOf(arg)), false, `${label}: the refusal never names the value`);
      assert.equal(existsSync(join(env.OPENSIG_DATA_DIR, 'blobs')), false, `${label}: refused before anything was composed`);
      assert.deepEqual([listened.length, started.length], [0, 0], `${label}: ${listened.length} listen() call(s) and ${started.length} runner start(s) before the refusal`);
      assert.deepEqual(lines.filter((line) => line.includes('"event":"listening"')), [], `${label}: nothing listens`);
    }
    assert.equal(process.argv, originalArgv, 'premise: process.argv is restored after every start');

    // Control: an argument that neither equals the flag nor starts with it and `=` is not refused.
    listened.length = 0;
    started.length = 0;
    const running = await startWith(composedEnv(seal), [lookAlike], []);
    try {
      assert.ok(running.composition.finalization instanceof FinalizationRunner, 'the look-alike starts a server with its runner');
      assert.deepEqual([listened.length >= 1, started.length], [true, 1], `the look-alike start: ${listened.length} listen() call(s), ${started.length} runner start(s)`);
    } finally {
      await running.close();
    }
  } finally {
    NetServer.prototype.listen = original.listen;
    FinalizationRunner.prototype.start = original.start;
    process.argv = originalArgv;
  }
});
