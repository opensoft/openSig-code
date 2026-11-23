// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { buildFieldManifest, recipientsDigest } from '../../../src/domain/envelopes/manifest.ts';
import { createApiClient } from '../../../src/integrations/hermes/api-client.mjs';
import { callTool } from '../../../src/integrations/hermes/tools.mjs';
import contract from '../../../contracts/http-api.json' with { type: 'json' };
import { bearer, confirmRequest, createInput, createWorld, documentBytes, fieldsFor, SINGLE_PAGE, takeInvitation } from '../../api/envelopes/support.mjs';

const server = fileURLToPath(new URL('../../../src/integrations/hermes/mcp-server.mjs', import.meta.url));
const request = (id, method, params) => ({ jsonrpc: '2.0', id, method, params });
const initialize = request(1, 'initialize', {
  protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'contract-test', version: '1' },
});
const initialized = { jsonrpc: '2.0', method: 'notifications/initialized' };
const toolCall = (id, name, args) => request(id, 'tools/call', { name, arguments: args });
const ephemeral = () => randomBytes(24).toString('base64url');
const digest = (data) => createHash('sha256').update(data).digest('hex');
const pdf = documentBytes(SINGLE_PAGE);
const input = (n = 1) => ({ ...createInput(n), fields: fieldsFor(n), pdf: pdf.toString('base64') });

async function stdio(messages, config = {}) {
  const child = spawn(process.execPath, [server], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      OPENSIG_HERMES_API_URL: 'http://127.0.0.1:1',
      OPENSIG_HERMES_SERVICE_BEARER: ephemeral(),
      ...config,
    },
  });
  const closed = once(child, 'close');
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (data) => { stdout += data; });
  child.stderr.setEncoding('utf8').on('data', (data) => { stderr += data; });
  // Startup refusal can close stdin before the client is done writing.
  child.stdin.on('error', (error) => { if (error.code !== 'EPIPE') child.kill(); });
  child.stdin.end(messages.map((m) => typeof m === 'string' ? m : JSON.stringify(m)).join('\n') + '\n');
  const timer = setTimeout(() => child.kill(), 20_000);
  try {
    const [code, signal] = await closed;
    assert.equal(signal, null);
    return { code, stderr, stdout, responses: stdout.trim().split('\n').filter(Boolean).map(JSON.parse) };
  } finally {
    clearTimeout(timer);
  }
}

function readTool(message) {
  assert.equal(message.result?.isError, false);
  return JSON.parse(message.result.content[0].text);
}

function apiStub() {
  const args = input();
  const id = 'envelope-fixture-001';
  const document = { digest: digest(pdf), bytes: pdf.length, pages: [{ number: 1, width: 612, height: 792, rotate: 0 }] };
  const recipients = [{ ...args.recipients[0], id: 'recipient-fixture-001', status: 'pending' }];
  const fields = args.fields.map((field) => ({ ...field, recipient_id: recipients[0].id }));
  const manifest = buildFieldManifest(id, document.digest, fields);
  const draft = { id, version: 1, state: 'draft' };
  const uploaded = { ...draft, version: 2, document };
  const prepared = { ...uploaded, version: 3, state: 'prepared', manifest_digest: manifest.digest };
  const preview = {
    envelope_id: id, version: 3, state: 'prepared', created_by: { kind: 'service', ref: 'hermes' },
    source: args.source, document, manifest_digest: manifest.digest, recipients_digest: recipientsDigest(recipients),
    fields, recipients, requires_human_confirmation: true,
  };
  const queue = [draft, uploaded, prepared, preview];
  const requests = [];
  return {
    args, queue, requests,
    api: async (method, path, options) => {
      requests.push({ method, path, options });
      return queue.shift();
    },
  };
}

test('[HM-01] stdio negotiates MCP and advertises exactly the contract tools', async () => {
  const run = await stdio([initialize, initialized, request(2, 'tools/list'), request(3, 'ping')]);
  assert.equal(run.code, 0);
  assert.equal(run.stderr, '');
  assert.deepEqual(run.responses.map((row) => row.id), [1, 2, 3]);
  assert.equal(run.responses[0].result.protocolVersion, initialize.params.protocolVersion);
  assert.deepEqual(run.responses[0].result.capabilities, { tools: {} });
  const expected = Object.keys(contract['x-opensig-hermes-tools']).filter((name) => name !== 'never_exposed');
  assert.deepEqual(run.responses[1].result.tools.map((tool) => tool.name), expected);
  const send = run.responses[1].result.tools.find((tool) => tool.name === 'request_signatures');
  assert.deepEqual(send.inputSchema.required, ['envelope_id', 'expected_version', 'authorization_reference']);
});

test('[HM-02] prepares real synthetic PDF bytes and validates the real recipient preview', async (t) => {
  const world = await createWorld();
  t.after(() => world.close());
  const service = bearer('alpha', 'service');
  const config = { OPENSIG_HERMES_API_URL: 'http://127.0.0.1:' + world.port, OPENSIG_HERMES_SERVICE_BEARER: service };
  const args = input();
  const run = await stdio([initialize, initialized, toolCall(2, 'prepare_envelope', args)], config);
  const data = readTool(run.responses[1]);
  assert.equal(data.version, 3);
  assert.equal(data.document_digest, digest(pdf));
  assert.equal(data.manifest_digest, data.preview.manifest_digest);
  assert.equal(data.recipients_digest, recipientsDigest(args.recipients));
  assert.equal(data.preview.created_by.kind, 'service');
  assert.equal(data.preview.requires_human_confirmation, true);
  assert.equal(world.mails().length, 0);
  assert.ok(!run.stdout.includes(service));
});

test('[HM-02] preparation advances versions through the four mapped routes', async () => {
  const { args, api, requests } = apiStub();
  await callTool(api, 'prepare_envelope', args);
  assert.deepEqual(requests.map(({ method, path }) => [method, path]), [
    ['POST', '/v1/envelopes'], ['PUT', '/v1/envelopes/envelope-fixture-001/document'],
    ['POST', '/v1/envelopes/envelope-fixture-001/prepare'], ['GET', '/v1/envelopes/envelope-fixture-001/preview'],
  ]);
  assert.equal(requests[1].options.version, 1);
  assert.deepEqual(requests[1].options.body, pdf);
  assert.equal(requests[2].options.body.expected_version, 2);
});

test('[HM-03] preparation refuses independent document, manifest and recipients digest mismatches', async () => {
  for (const part of ['document', 'manifest_digest', 'recipients_digest']) {
    const { args, queue, api } = apiStub();
    if (part === 'document') queue[3].document = { ...queue[3].document, digest: '0'.repeat(64) };
    else queue[3][part] = '0'.repeat(64);
    await assert.rejects(callTool(api, 'prepare_envelope', args), /preview does not match/, part);
  }
});

test('[HM-03] a preview with a recomputed digest still cannot substitute different fields', async () => {
  const { args, queue, api } = apiStub();
  const preview = queue[3];
  preview.fields[0].key = 'substitute';
  preview.manifest_digest = buildFieldManifest(preview.envelope_id, preview.document.digest, preview.fields).digest;
  queue[2].manifest_digest = preview.manifest_digest;
  await assert.rejects(callTool(api, 'prepare_envelope', args), /preview does not match/);
});

test('[HM-04] send requires the human confirmation and discloses no mail capability', async (t) => {
  const world = await createWorld();
  t.after(() => world.close());
  const config = { OPENSIG_HERMES_API_URL: 'http://127.0.0.1:' + world.port, OPENSIG_HERMES_SERVICE_BEARER: bearer('alpha', 'service') };
  const ready = await stdio([initialize, initialized, toolCall(2, 'prepare_envelope', input())], config);
  const prepared = readTool(ready.responses[1]);
  const send = { envelope_id: prepared.envelope_id, expected_version: prepared.version };
  const denied = await stdio([
    initialize, initialized, toolCall(2, 'request_signatures', send),
    toolCall(3, 'request_signatures', { ...send, authorization_reference: ephemeral() }),
    toolCall(4, 'confirmSend', send),
  ], config);
  assert.deepEqual(denied.responses.slice(1).map((row) => row.result?.isError), [true, true, true]);
  assert.equal(world.mails().length, 0);
  const confirmed = await confirmRequest(world, { envelope: { id: prepared.envelope_id } });
  assert.equal(confirmed.status, 201);
  const reference = confirmed.json.authorization_reference;
  const sent = await stdio([
    initialize, initialized,
    toolCall(2, 'get_status', { envelope_id: prepared.envelope_id }),
    toolCall(3, 'request_signatures', { ...send, authorization_reference: reference }),
    toolCall(4, 'get_status', { envelope_id: prepared.envelope_id }),
  ], config);
  assert.equal(readTool(sent.responses[1]).state, 'prepared');
  assert.deepEqual(Object.keys(readTool(sent.responses[2])), ['id', 'version', 'state', 'approvals_complete']);
  assert.equal(readTool(sent.responses[2]).state, 'sent');
  assert.equal(readTool(sent.responses[3]).recipients[0].status, 'invited');
  assert.equal(world.mails().length, 1);
  const invitation = takeInvitation(world);
  assert.ok(!sent.stdout.includes(reference) && !sent.stdout.includes(invitation));
});

test('[HM-05] status and nested summaries whitelist fields and discard unexpected capabilities', async () => {
  const id = 'envelope-fixture-001';
  const marker = ephemeral();
  const state = {
    id, version: 3, state: 'prepared', approvals_complete: false, anchor_status: 'disabled',
    recipients: [{ id: 'recipient-fixture-001', ordinal: 1, status: 'pending', invitation: marker }],
    finalization: { job_status: 'pending', cookie: marker, last_error_code: { token: marker } },
    artifact: { artifact_digest: '1'.repeat(64), url: marker },
    send_confirmation: { required: true, authorization_reference: marker },
  };
  const data = await callTool(async () => state, 'get_status', { envelope_id: id });
  assert.equal(data.state, 'prepared');
  assert.equal(data.artifact.artifact_digest, '1'.repeat(64));
  assert.ok(!JSON.stringify(data).includes(marker));
});

test('[HM-06] completed retrieval returns the exact ZIP bytes and the separate verification report', async () => {
  const buffer = Buffer.from('504b0506000000000000000000000000000000000000', 'hex');
  const marker = ephemeral();
  const hits = [];
  const api = async (method, path, options) => {
    hits.push({ method, path, options });
    if (path.endsWith('/package')) return buffer;
    return {
      schema: 'opensig.verification/1', artifact_digest: '1'.repeat(64), integrity: 'valid',
      verifier: { name: 'synthetic', version: '1', capability: marker },
      checks: [{ id: 'integrity', result: 'pass', capability: marker }],
      capability: marker,
    };
  };
  const data = await callTool(api, 'retrieve_completed_package', { envelope_id: 'envelope-fixture-001' });
  assert.equal(data.package_base64, buffer.toString('base64'));
  assert.equal(data.package_digest, digest(buffer));
  assert.equal(data.verification.integrity, 'valid');
  assert.ok(!JSON.stringify(data).includes(marker));
  assert.deepEqual(hits, [
    { method: 'GET', path: '/v1/envelopes/envelope-fixture-001/package', options: { zip: true } },
    { method: 'GET', path: '/v1/envelopes/envelope-fixture-001/verification', options: undefined },
  ]);
});

test('[HM-06] stdio maps API refusals to a generic tool error without forwarding bodies or redirects', async (t) => {
  const marker = ephemeral();
  let hits = 0;
  const upstream = createServer((_req, res) => {
    hits += 1;
    res.writeHead(302, { location: '/redirected?value=' + marker, 'content-type': 'application/json' });
    res.end(JSON.stringify({ capability: marker }));
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  t.after(() => new Promise((resolve) => upstream.close(resolve)));
  const run = await stdio([
    initialize, initialized, toolCall(2, 'retrieve_completed_package', { envelope_id: 'envelope-fixture-001' }),
  ], { OPENSIG_HERMES_API_URL: 'http://127.0.0.1:' + upstream.address().port });
  assert.equal(run.responses[1].result.isError, true);
  assert.equal(hits, 1);
  assert.ok(!run.stdout.includes(marker) && !run.stderr.includes(marker));
});

test('[HM-01] invalid requests and unadvertised methods cannot forward arbitrary operations', async () => {
  const run = await stdio(['{', request(10, 'tools/list'), initialize, initialized,
    request(2, 'resources/list'), toolCall(3, 'requestChallenge', {}),
    toolCall(4, 'get_status', { envelope_id: '../send-confirmations' }),
  ]);
  assert.deepEqual(run.responses.slice(0, 2).map((row) => row.error.code), [-32700, -32000]);
  assert.equal(run.responses[3].error.code, -32601);
  assert.deepEqual(run.responses.slice(4).map((row) => row.result.isError), [true, true]);
});

test('[HM-05] the adapter refuses a non-local endpoint before opening a service connection', () => {
  assert.throws(() => createApiClient({ baseUrl: 'https://sign.example.test', credential: ephemeral() }), /loopback/);
});


test('[HM-06] the stdio relay retrieves a package and report over a Unix socket', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'osig-hm-'));
  const socketPath = join(dir, 'api.sock');
  const id = 'envelope-fixture-001';
  const credential = ephemeral();
  const zip = Buffer.from('504b0506000000000000000000000000000000000000', 'hex');
  const seen = [];
  const upstream = createServer((req, res) => {
    const authorized = req.headers.authorization === 'Bearer ' + credential;
    seen.push({ method: req.method, path: req.url, authorized });
    if (req.url.endsWith('/package')) {
      res.writeHead(200, { 'content-type': 'application/zip' }).end(zip);
    } else {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' }).end(JSON.stringify({
        schema: 'opensig.verification/1', artifact_digest: '1'.repeat(64), integrity: 'valid',
        verifier: { name: 'synthetic', version: '1' }, checks: [],
      }));
    }
  });
  t.after(async () => {
    if (upstream.listening) await new Promise((resolve) => upstream.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });
  upstream.listen(socketPath);
  await once(upstream, 'listening');
  const run = await stdio([initialize, initialized, toolCall(2, 'retrieve_completed_package', { envelope_id: id })], {
    OPENSIG_HERMES_API_URL: '', OPENSIG_HERMES_API_SOCKET: socketPath, OPENSIG_HERMES_SERVICE_BEARER: credential,
  });
  const retrieved = readTool(run.responses[1]);
  assert.equal(retrieved.package_digest, digest(zip));
  assert.equal(retrieved.verification.artifact_digest, '1'.repeat(64));
  assert.deepEqual(seen, [
    { method: 'GET', path: '/v1/envelopes/' + id + '/package', authorized: true },
    { method: 'GET', path: '/v1/envelopes/' + id + '/verification', authorized: true },
  ]);
  assert.ok(!run.stdout.includes(credential) && !run.stderr.includes(credential));
});
