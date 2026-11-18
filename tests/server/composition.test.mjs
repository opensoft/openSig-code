// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-12 (A-010 row WIRE-US1; § Rulings, T008 deviations D1; request #16; request
// #26 (3)): the US1 composition of the real entrypoint (src/server/main.ts startServer).
// - Startup refuses OPENSIG_CHALLENGE_KEY_FILE unless it names a regular file, not a link,
//   that holds 32 to 4096 bytes and has no group or other permission bit; the refusal comes
//   before anything is composed and names the setting and the rule, never the path or a byte.
// - The composed server serves every route of the T008, T034 and T010 maps through its real
//   handler: each answer is one only that handler gives (never the 501 of a missing handler,
//   never the 500 of a missing composition), is a status the contract declares for the
//   operation, and its request log line names the operation. Routes still without a handler
//   keep the uniform 501.
// - Both listeners (TCP, and the Hermes relay's Unix socket) serve one registry with one
//   composition: the same ceremony, EnvelopeApi and ApprovalApi objects, and T034's one
//   process-wide per-tenant upload cap, which uploads through either listener fill together.
// - An operator-path expiry on the composed server (an upload to an overdue draft; rows
//   EXPIRED-EVT and UPLOAD-OVERDUE, composed by the T034 follow-up) writes exactly one
//   envelope.expired and admits nothing to the parse service.
// - The composition starts T010's expiry sweeper once, at its default interval, over the
//   composed database and the ceremony's listener (row SWEEP-SCHED).
// - The key-file mode rule is "no group or other permission bit": 0600 and 0400 both start
//   (A-010 request #30 (4)).
// - Startup settles T033's sandbox plan before either listener exists, and the `listening` line
//   carries it: its mode and launcher. That line is info when the plan is sandboxed and is itself
//   a warning when it is not, and the server still starts (request #32). The non-sandboxed plan is
//   T033's own plan for an empty launcher set (createParseServiceForTests), injected through
//   startServer's parsePlan seam: no host change is needed.
// Waits are barriers on observable state; the only timers are hang guards.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, statSync, symlinkSync } from 'node:fs';
import { connect } from 'node:net';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, test } from 'node:test';

import { ROLE_MATRIX } from '../../src/api/auth/index.ts';
import { EnvelopeApi } from '../../src/api/envelopes/api.ts';
import { UPLOADS_PER_TENANT, uploadCapacity, uploadsInFlight } from '../../src/api/envelopes/uploads.ts';
import { ApprovalApi } from '../../src/api/recipients/approval.ts';
import { RecipientCeremony } from '../../src/api/recipients/ceremony.ts';
import { ROUTES } from '../../src/api/routes.ts';
import { ExpirySweeper } from '../../src/jobs/expiry.ts';
import { createParseServiceForTests, parseAdmissions, parseServicePlan } from '../../src/pdf/service.ts';
import { startServer } from '../../src/server/main.ts';
import { loadVendoredContract } from '../contract/envelopes/lib/contract.mjs';
import { call, codeOf, cookieOf, COOKIE, FIELDS, guarded, mails, ORIGIN, rows, testSide } from './composed-support.mjs';
import { ALPHA, authFile, bearer, cleanup, composedEnv, ENVELOPE_ID, keyFile, REPO, seedConsent, tempDir } from './support.mjs';

after(cleanup);

const DAY = 24 * 60 * 60 * 1000;
const newKey = () => `ik-${randomBytes(18).toString('base64url')}`;

/** Status codes the vendored contract declares for each operationId. */
const DECLARED = (() => {
  const declared = {};
  for (const item of Object.values(loadVendoredContract().doc.paths)) {
    for (const operation of Object.values(item)) {
      if (operation && typeof operation === 'object' && typeof operation.operationId === 'string') declared[operation.operationId] = new Set(Object.keys(operation.responses ?? {}));
    }
  }
  return declared;
})();

/** The request log lines as operation:status. */
const handled = (lines) =>
  lines
    .map((line) => JSON.parse(line))
    .filter((record) => record.event === 'request')
    .map((record) => `${record.operation}:${record.status}`);

/** Start the composed server, refusing the test (not hanging it) if startup never settles. */
const start = (env, lines = []) => guarded(startServer(env, { logSink: (line) => lines.push(line) }), 'startServer');

test('[SEC-12] startup refuses the challenge key file unless it is a regular file with no group or other permission bit (0600 or 0400) of 32 to 4096 bytes, before composing anything', async () => {
  const valid = keyFile();
  const linkDir = tempDir('key-link');
  const link = join(linkDir, 'challenge-hmac.key');
  symlinkSync(valid, link);
  const directory = join(tempDir('key-dir'), 'challenge-hmac.key');
  mkdirSync(directory, { mode: 0o700 });
  const fifo = join(tempDir('key-fifo'), 'challenge-hmac.key');
  assert.equal(spawnSync('mkfifo', ['-m', '600', fifo]).status, 0, 'premise: a FIFO was created for the non-regular-file case');
  const cases = {
    // The owner-only rule in words, never "0600" (request #34 note 3).
    'no setting': [undefined, /^OPENSIG_CHALLENGE_KEY_FILE refused: the setting is required \(an owner-only file, with no group or other permission bit, holding the recipient challenge-HMAC key\)$/],
    'a relative path': ['relative/challenge-hmac.key', /OPENSIG_CHALLENGE_KEY_FILE must be an absolute path/],
    'a missing file': [join(tempDir('key-missing'), 'absent.key'), /OPENSIG_CHALLENGE_KEY_FILE refused: the file does not exist/],
    'a symbolic link to a valid key': [link, /OPENSIG_CHALLENGE_KEY_FILE refused: the path must not be a symbolic link/],
    'a directory': [directory, /OPENSIG_CHALLENGE_KEY_FILE refused: the path must name a regular file/],
    'a FIFO (never opened, so startup cannot block on it)': [fifo, /OPENSIG_CHALLENGE_KEY_FILE refused: the path must name a regular file/],
    'group-readable (0640)': [keyFile({ mode: 0o640 }), /OPENSIG_CHALLENGE_KEY_FILE refused: .*group- or other-accessible/],
    'other-readable (0604)': [keyFile({ mode: 0o604 }), /OPENSIG_CHALLENGE_KEY_FILE refused: .*group- or other-accessible/],
    'group-writable (0620)': [keyFile({ mode: 0o620 }), /OPENSIG_CHALLENGE_KEY_FILE refused: .*group- or other-accessible/],
    '31 bytes': [keyFile({ bytes: randomBytes(31) }), /OPENSIG_CHALLENGE_KEY_FILE refused: .*32 to 4096 bytes/],
    'empty': [keyFile({ bytes: Buffer.alloc(0) }), /OPENSIG_CHALLENGE_KEY_FILE refused: .*32 to 4096 bytes/],
    '4097 bytes': [keyFile({ bytes: randomBytes(4097) }), /OPENSIG_CHALLENGE_KEY_FILE refused: .*32 to 4096 bytes/],
  };
  // The mode rule is no group or other bit (request #30 (4)): 0400 is accepted below, 0640, 0604 and 0620 are refused here.
  for (const [label, [path, pattern]] of Object.entries(cases)) {
    const env = composedEnv({ OPENSIG_CHALLENGE_KEY_FILE: path });
    const lines = [];
    let error = null;
    try {
      const running = await start(env, lines);
      await running.close();
    } catch (caught) {
      error = caught;
    }
    assert.ok(error !== null, `${label}: the server must refuse to start`);
    assert.equal(error.name, 'ServerConfigError', label);
    assert.match(error.message, pattern, label);
    if (path !== undefined) assert.equal(error.message.includes(path), false, `${label}: the refusal never names the path`);
    assert.equal(existsSync(join(env.OPENSIG_DATA_DIR, 'blobs')), false, `${label}: refused before anything was composed`);
    assert.deepEqual(lines.filter((line) => line.includes('"event":"listening"')), [], `${label}: nothing listens`);
  }

  // Controls: a valid key of 32 bytes starts, composed, at 0600 and at 0400 (owner read-only), and so does one of 4096 bytes.
  for (const [label, path] of [
    ['0600, 32 bytes', valid],
    ['0400, 32 bytes', keyFile({ mode: 0o400 })],
    ['0600, 4096 bytes', keyFile({ bytes: randomBytes(4096) })],
  ]) {
    const env = composedEnv({ OPENSIG_CHALLENGE_KEY_FILE: path });
    const running = await start(env);
    try {
      assert.ok(running.composition.ceremony instanceof RecipientCeremony, `${label}: the ceremony is composed with the key`);
      assert.equal(existsSync(join(env.OPENSIG_DATA_DIR, 'blobs')), true, `${label}: the blob store directory was created`);
      assert.equal(statSync(join(env.OPENSIG_DATA_DIR, 'blobs')).mode & 0o777, 0o700, `${label}: the blob store directory is 0700`);
    } finally {
      await running.close();
    }
  }

  // node src/server/main.ts without the key exits 1 with the refusal and never listens.
  const child = spawn(process.execPath, [join(REPO, 'src', 'server', 'main.ts')], {
    cwd: REPO,
    env: { PATH: process.env.PATH ?? '', ...composedEnv({ OPENSIG_CHALLENGE_KEY_FILE: undefined }) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk));
  const code = await guarded(new Promise((resolveExit) => child.on('exit', (exitCode) => resolveExit(exitCode))), 'refused entrypoint exit');
  assert.equal(code, 1);
  assert.match(stderr, /^opensig: OPENSIG_CHALLENGE_KEY_FILE refused: the setting is required/m);
  assert.doesNotMatch(stdout, /"event":"listening"/);
});

test('[SEC-12] the composed server serves every wired route through its real handler; routes without one keep 501', async () => {
  const env = composedEnv({ OPENSIG_OPERATOR_AUTH_FILE: authFile(), OPENSIG_ALLOWED_ORIGINS: ORIGIN, OPENSIG_PUBLIC_ORIGIN: ORIGIN });
  seedConsent(env.OPENSIG_DATABASE);
  const lines = [];
  const running = await start(env, lines);
  const side = testSide(env);
  const exercised = new Map();
  /** One request to `operationId`; asserts it reached the real handler and returns the response. */
  const through = async (operationId, options) => {
    const route = ROUTES.find((entry) => entry.operationId === operationId);
    const before = handled(lines).length;
    const response = await call(running.port, { method: route.method, ...options });
    assert.notEqual(response.status, 501, `${operationId}: never the 501 of a missing handler`);
    assert.ok(response.status < 500, `${operationId}: never a 5xx (got ${response.status} ${response.json?.code ?? ''})`);
    assert.ok(DECLARED[operationId]?.has(String(response.status)), `${operationId}: ${response.status} is a response the contract declares`);
    assert.deepEqual(handled(lines).slice(before), [`${operationId}:${response.status}`], `${operationId}: handled and logged as the operation`);
    exercised.set(operationId, response.status);
    return response;
  };
  const sender = () => ({ authorization: `Bearer ${bearer('sender')}` });
  try {
    // The settled parse plan (request #32): the same memoized plan every upload's parsePdf() uses.
    const plan = await parseServicePlan();
    const records = lines.map((line) => JSON.parse(line));
    const listening = records.find((record) => record.event === 'listening');
    assert.deepEqual([listening.parse_mode, listening.parse_launcher], [plan.mode, plan.probe.launcher], 'the listening line carries the settled parse plan');
    assert.equal(listening.level, plan.mode === 'sandboxed' ? 'info' : 'warn', 'the listening line is info exactly when the settled plan is sandboxed');
    // T034, operator routes, as the sender.
    const created = await through('createEnvelope', { path: '/v1/envelopes', headers: { ...sender(), 'idempotency-key': newKey() }, body: { source: { app: 'manual', record: 'synthetic-record-0001', version: 'v1' }, recipients: [{ email: 'signer.one@example.test', role: 'approver', ordinal: 1 }] } });
    assert.equal(created.status, 201);
    const id = created.json.id;
    const read = await through('readEnvelope', { path: `/v1/envelopes/${id}`, headers: sender() });
    assert.deepEqual([read.status, read.json.id, read.json.state], [200, id, 'draft']);
    // A wrong If-Match is refused by the handler's own pre-parse check: no body is parsed.
    const admitted = parseAdmissions().next_ticket;
    const upload = await through('uploadDocument', { path: `/v1/envelopes/${id}/document`, headers: { ...sender(), 'idempotency-key': newKey(), 'if-match': '"9"', 'content-type': 'application/pdf' }, body: Buffer.from('%PDF-1.7\n%%EOF\n', 'latin1') });
    assert.deepEqual([upload.status, upload.json.code], [409, 'version_conflict']);
    assert.equal(parseAdmissions().next_ticket, admitted, 'nothing reached the parse service');
    await through('prepareEnvelope', { path: `/v1/envelopes/${id}/prepare`, headers: { ...sender(), 'idempotency-key': newKey() }, body: { expected_version: 1, fields: FIELDS } });
    await through('readRecipientPreview', { path: `/v1/envelopes/${id}/preview`, headers: sender() });
    await through('confirmSend', { path: `/v1/envelopes/${id}/send-confirmations`, headers: { ...sender(), 'idempotency-key': newKey() }, body: { expected_version: 1, document_digest: '0'.repeat(64), manifest_digest: '0'.repeat(64), recipients_digest: '0'.repeat(64) } });
    await through('sendEnvelope', { path: `/v1/envelopes/${id}/send`, headers: { ...sender(), 'idempotency-key': newKey() }, body: { expected_version: 1 } });
    await through('resendInvitation', { path: `/v1/envelopes/${id}/recipients/${created.json.recipients[0].id}/resend-invitation`, headers: { ...sender(), 'idempotency-key': newKey() }, body: { expected_version: 1 } });
    const voided = await through('voidEnvelope', { path: `/v1/envelopes/${id}/void`, headers: { ...sender(), 'idempotency-key': newKey() }, body: { expected_version: 1, reason_code: 'sender-cancelled' } });
    assert.deepEqual([voided.status, voided.json.state], [200, 'voided']);
    const reissued = await through('reissueEnvelope', { path: `/v1/envelopes/${id}/reissue`, headers: { ...sender(), 'idempotency-key': newKey() }, body: { expected_version: voided.json.version } });
    assert.equal(reissued.status, 201);

    // T008 and T010, recipient routes, for an invitation issued on the test side.
    const { token, pdf } = await side.sentEnvelope();
    const challenge = await through('requestChallenge', { path: '/v1/recipient-session/challenges', headers: { origin: ORIGIN }, body: { invitation: token } });
    assert.deepEqual([challenge.status, challenge.json], [202, { status: 'accepted' }]);
    await guarded(running.composition.ceremony.drain(), 'the composed ceremony settles its post-response work');
    const codeMail = mails(env.OPENSIG_SPOOL_DIR, 'recipient_challenge').pop();
    assert.ok(codeMail, 'the composed notifier mailed the code to the server spool');
    const session = await through('createRecipientSession', { path: '/v1/recipient-session', headers: { origin: ORIGIN }, body: { invitation: token, code: codeOf(codeMail) } });
    assert.equal(session.status, 201);
    const cookie = { cookie: `${COOKIE}=${cookieOf(session)}` };
    const state = await through('readRecipientSession', { path: '/v1/recipient-session', headers: cookie });
    assert.equal(state.status, 200);
    const documentResponse = await through('readRecipientDocument', { path: '/v1/recipient-session/document', headers: cookie });
    assert.ok(documentResponse.bytes.equals(pdf), 'the exact frozen document bytes from the composed blob store');
    await through('readRecipientManifest', { path: '/v1/recipient-session/manifest', headers: cookie });
    const mutation = { ...cookie, origin: ORIGIN, 'x-csrf-token': state.json.csrf_token };
    // T010's handlers (T008's guard-only entries would answer 501 once the guard passed).
    const approval = await through('approveAsHuman', { path: '/v1/recipient-session/approval', headers: mutation, body: {} });
    assert.deepEqual([approval.status, approval.json.code], [400, 'invalid_request'], 'T010 checks the body after the session and the receipt');
    const decline = await through('declineAsRecipient', { path: '/v1/recipient-session/decline', headers: mutation, body: {} });
    assert.deepEqual([decline.status, decline.json.code], [400, 'invalid_request']);
    const ended = await through('endRecipientSession', { path: '/v1/recipient-session', headers: mutation });
    assert.equal(ended.status, 204);

    // Every wired route was exercised, and nothing else counted as wired.
    assert.deepEqual([...exercised.keys()].sort(), ROUTES.filter((route) => route.handler !== null).map((route) => route.operationId).sort(), 'every route with a composed handler was served through it');

    // Routes still without a handler keep the uniform 501 on the composed server.
    const retry = await call(running.port, { method: 'POST', path: `/v1/envelopes/${id}/finalization/retry`, headers: { authorization: `Bearer ${bearer('admin')}` }, body: {} });
    assert.deepEqual([retry.status, retry.json.code], [501, 'internal']);
    assert.ok(ROLE_MATRIX.retryFinalization.roles.includes('tenant_admin'), 'premise: the admin is authorized, so the 501 is the missing handler');
  } finally {
    side.close();
    await running.close();
  }
});

/** A held upload on a raw connection (TCP port or Unix socket): headers and one chunk, then nothing more. */
function heldUpload(target, { envelopeId, key, ifMatch, who = 'sender' }) {
  const socket = connect(target);
  socket.on('error', () => {});
  const received = [];
  socket.on('data', (chunk) => received.push(chunk));
  socket.write(
    `PUT /v1/envelopes/${envelopeId}/document HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${bearer(who)}\r\nIdempotency-Key: ${key}\r\nIf-Match: "${ifMatch}"\r\n` +
      'Content-Type: application/pdf\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n%PDF-1.7\r\n',
  );
  return { socket, text: () => Buffer.concat(received).toString('latin1') };
}

/** Barrier: poll `check` with a bounded sleep until it holds, failing with `label` at the guard. */
async function until(check, label, ms = 5_000) {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > ms) assert.fail(`${label} (hang guard ${ms} ms)`);
    await sleep(5);
  }
}

test('[SEC-12] the listening line is info when the settled parse plan is sandboxed and is itself a warning when it is not; the server still starts', async () => {
  const cases = [
    // This host's production plan (the default reader, parseServicePlan()).
    ['the production plan', undefined],
    // T033's own plan for an empty launcher set: no launcher can be probed, so it is not sandboxed.
    ['an empty launcher set', createParseServiceForTests({ launchers: [] }).plan],
  ];
  const production = await parseServicePlan();
  assert.equal(production.mode, 'sandboxed', 'premise: this host runs uploads sandboxed (this case needs the T033 sandbox launcher)');
  for (const [label, parsePlan] of cases) {
    const plan = parsePlan === undefined ? production : await parsePlan();
    const sandboxed = parsePlan === undefined;
    if (!sandboxed) assert.deepEqual([plan.mode, plan.probe.launcher, plan.network_sandbox], ['refused', null, 'unavailable'], `premise: ${label} gives T033's refused plan`);
    const env = composedEnv({ OPENSIG_OPERATOR_AUTH_FILE: authFile() });
    const lines = [];
    const running = await guarded(startServer(env, { logSink: (line) => lines.push(line), ...(sandboxed ? {} : { parsePlan }) }), 'startServer');
    try {
      const records = lines.map((line) => JSON.parse(line));
      const listening = records.filter((record) => record.event === 'listening');
      assert.equal(listening.length, 1, `${label}: one listening line`);
      assert.deepEqual([listening[0].parse_mode, listening[0].parse_launcher, listening[0].network_sandbox], [plan.mode, plan.probe.launcher, plan.network_sandbox], `${label}: the listening line carries the settled plan`);
      assert.equal(listening[0].level, sandboxed ? 'info' : 'warn', sandboxed ? `${label}: a sandboxed plan's listening line stays info` : `${label}: a plan that is not sandboxed makes the listening line itself a warning`);
      assert.equal(records.some((record) => record.event === 'parse_service_not_sandboxed'), false, `${label}: no separate warning line; the listening line is the warning`);
      // The server still starts: an operator read reaches its real handler.
      const read = await call(running.port, { path: `/v1/envelopes/${ENVELOPE_ID}`, headers: { authorization: `Bearer ${bearer('sender')}` } });
      assert.deepEqual([read.status, read.json?.code], [404, 'not_found'], `${label}: the server serves (the handler's 404 for an absent envelope)`);
      assert.deepEqual(handled(lines).slice(-1), ['readEnvelope:404'], `${label}: the 404 is the handler's`);
    } finally {
      await running.close();
    }
  }
});

test('[SEC-12] both listeners share one composition and T034\'s one process-wide per-tenant upload cap', async () => {
  const socketPath = join(tempDir('relay'), 'opensig.sock');
  const env = composedEnv({ OPENSIG_OPERATOR_AUTH_FILE: authFile(), OPENSIG_RELAY_SOCKET: socketPath });
  const lines = [];
  const running = await start(env, lines);
  const side = testSide(env);
  const held = [];
  try {
    // One composition: the same registry and the same service objects in both listeners' apps.
    const { composition } = running;
    assert.deepEqual(running.listeners.map((listener) => listener.name), ['tcp', 'relay']);
    assert.ok(composition.ceremony instanceof RecipientCeremony && composition.envelopes instanceof EnvelopeApi && composition.approvals instanceof ApprovalApi);
    for (const listener of running.listeners) {
      assert.equal(listener.routes, ROUTES, `${listener.name}: serves the registry itself`);
      assert.ok(Object.isFrozen(listener.routes), `${listener.name}: the registry it exposes is read-only`);
      assert.equal(listener.services.ceremony, composition.ceremony, `${listener.name}: the composition's ceremony`);
      assert.equal(listener.services.envelopes, composition.envelopes, `${listener.name}: the composition's EnvelopeApi`);
      assert.equal(listener.services.approvals, composition.approvals, `${listener.name}: the composition's ApprovalApi`);
    }
    // The composition states the cap, and the listening line logs it.
    assert.deepEqual({ ...composition.uploadCap }, { scope: 'process', perTenant: UPLOADS_PER_TENANT });
    const listening = lines.map((line) => JSON.parse(line)).find((record) => record.event === 'listening');
    assert.deepEqual([listening.upload_cap_scope, listening.upload_cap_per_tenant], ['process', UPLOADS_PER_TENANT]);

    // One cap: hold the tenant's every slot with uploads through BOTH listeners. Each held upload
    // has a key already recorded on the test side, so it is resolved without the parse service
    // and holds its slot while its body trickles.
    assert.equal(uploadsInFlight(), 0, 'premise: no upload in flight');
    const created = await call(running.port, { method: 'POST', path: '/v1/envelopes', headers: { authorization: `Bearer ${bearer('sender')}`, 'idempotency-key': newKey() }, body: { source: { app: 'manual', record: 'synthetic-record-0001', version: 'v1' }, recipients: [{ email: 'signer.one@example.test', role: 'approver', ordinal: 1 }] } });
    assert.equal(created.status, 201);
    const sender = created.json.created_by;
    let envelope = created.json;
    const keys = [];
    for (let index = 0; index < UPLOADS_PER_TENANT; index += 1) {
      const key = newKey();
      envelope = side.recordDocument(envelope, { actor: sender, key }).envelope;
      keys.push(key);
    }
    const targets = [{ host: '127.0.0.1', port: running.port }, { path: socketPath }];
    keys.forEach((key, index) => held.push(heldUpload(targets[index % targets.length], { envelopeId: envelope.id, key, ifMatch: 1 })));
    await until(() => uploadCapacity(ALPHA.id).held === UPLOADS_PER_TENANT, `the ${UPLOADS_PER_TENANT} held uploads took their slots (held ${uploadCapacity(ALPHA.id).held})`);
    // A further upload of the tenant is refused at once through either listener.
    for (const [label, options] of [
      ['relay', { socketPath, who: 'service' }],
      ['tcp', { who: 'sender' }],
    ]) {
      const refused = await call(running.port, {
        method: 'PUT',
        path: `/v1/envelopes/${envelope.id}/document`,
        socketPath: options.socketPath,
        headers: { authorization: `Bearer ${bearer(options.who)}`, 'idempotency-key': newKey(), 'if-match': `"${envelope.version}"`, 'content-type': 'application/pdf' },
        body: Buffer.from('%PDF-1.7\n%%EOF\n', 'latin1'),
      });
      assert.equal(refused.status, 429, `${label}: the tenant is at its one cap, filled through both listeners`);
      assert.deepEqual(refused.json.details, [{ field: 'tenant', code: 'upload-capacity' }], `${label}: refused by the upload cap`);
    }
    for (const upload of held) assert.equal(upload.text(), '', 'the held uploads are still pending');
  } finally {
    for (const upload of held) upload.socket.destroy();
    await until(() => uploadsInFlight() === 0, 'aborted uploads released their slots');
    side.close();
    await running.close();
  }
});

test('[SEC-12] an operator-path expiry on the composed server writes exactly one envelope.expired and parses nothing', async () => {
  const env = composedEnv({ OPENSIG_OPERATOR_AUTH_FILE: authFile() });
  const running = await start(env);
  // A draft created two days ago (the test side's clock), due one hour after its creation.
  const past = Date.now() - 2 * DAY;
  const side = testSide(env, { clock: () => new Date(past) });
  try {
    const overdue = side.draft({ expires_at: new Date(past + 60 * 60 * 1000).toISOString() });
    const admitted = parseAdmissions().next_ticket;
    const upload = await call(running.port, {
      method: 'PUT',
      path: `/v1/envelopes/${overdue.id}/document`,
      headers: { authorization: `Bearer ${bearer('sender')}`, 'idempotency-key': newKey(), 'if-match': `"${overdue.version}"`, 'content-type': 'application/pdf' },
      body: Buffer.from('%PDF-1.7\n%%EOF\n', 'latin1'),
    });
    assert.deepEqual([upload.status, upload.json.code], [409, 'state_conflict']);
    assert.equal(parseAdmissions().next_ticket, admitted, 'nothing was admitted to the parse service');
    assert.equal(rows(env.OPENSIG_DATABASE, 'SELECT state FROM envelopes WHERE id = ?', overdue.id)[0]?.state, 'expired');
    const events = rows(env.OPENSIG_DATABASE, 'SELECT type FROM outbox_events WHERE envelope_id = ?', overdue.id).map((row) => row.type);
    assert.deepEqual(events, ['envelope.expired'], 'exactly one envelope.expired, written by the composed EnvelopeApi');
    // A second operator request on the expired envelope commits no second expiry.
    const again = await call(running.port, { method: 'POST', path: `/v1/envelopes/${overdue.id}/void`, headers: { authorization: `Bearer ${bearer('sender')}`, 'idempotency-key': newKey() }, body: { expected_version: overdue.version + 1, reason_code: 'sender-cancelled' } });
    assert.equal(again.status, 409);
    assert.deepEqual(rows(env.OPENSIG_DATABASE, 'SELECT type FROM outbox_events WHERE envelope_id = ?', overdue.id).map((row) => row.type), ['envelope.expired']);
  } finally {
    side.close();
    await running.close();
  }
});

test('[SEC-12] the composition starts T010\'s expiry sweeper once, at its default interval, over the composed database and the ceremony\'s listener', async () => {
  const started = [];
  const originalStart = ExpirySweeper.prototype.start;
  ExpirySweeper.prototype.start = function spiedStart(...args) {
    started.push({ sweeper: this, args });
    return originalStart.apply(this, args);
  };
  const env = composedEnv({ OPENSIG_OPERATOR_AUTH_FILE: authFile() });
  let running;
  try {
    running = await start(env);
  } finally {
    ExpirySweeper.prototype.start = originalStart;
  }
  // An overdue draft, created two days ago on the test side and due one hour after its creation.
  const past = Date.now() - 2 * DAY;
  const side = testSide(env, { clock: () => new Date(past) });
  try {
    assert.equal(started.length, 1, 'the sweeper is started exactly once');
    assert.equal(started[0].sweeper, running.composition.sweeper, 'the composition\'s own sweeper');
    assert.ok(running.composition.sweeper instanceof ExpirySweeper);
    assert.deepEqual(started[0].args, [], 'at its default interval');
    const overdue = side.draft({ expires_at: new Date(past + 60 * 60 * 1000).toISOString() });
    // One run of the composed sweeper (the interval's next run would do the same) expires it on the
    // composed database, announced once through the composition's listener chain.
    const report = running.composition.sweeper.runOnce();
    assert.ok(report.expired >= 1, 'the run expired the overdue envelope');
    assert.equal(rows(env.OPENSIG_DATABASE, 'SELECT state FROM envelopes WHERE id = ?', overdue.id)[0]?.state, 'expired');
    assert.deepEqual(rows(env.OPENSIG_DATABASE, 'SELECT type FROM outbox_events WHERE envelope_id = ?', overdue.id).map((row) => row.type), ['envelope.expired']);
  } finally {
    side.close();
    await running.close();
  }
});
