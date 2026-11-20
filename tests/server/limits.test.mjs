// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-03: streaming body limits. JSON bodies are at most 256 KiB and PDF bodies
// at most 10 MiB; a declared length over the limit is refused before any byte is read, and
// a streamed body is refused at the first chunk past the limit, before the client has sent
// it in full.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { JSON_BODY_LIMIT, PDF_BODY_LIMIT } from '../../src/server/config.ts';
import { bearer, cleanup, ENVELOPE_ID, send, serveApp, streamUpload } from './support.mjs';

const KIB = 1024;
const MIB = 1024 * KIB;
let served;

before(async () => {
  served = await serveApp({
    handlers: {
      createEnvelope: async (ctx) => {
        const body = await ctx.json();
        return { status: 201, json: { received: JSON.stringify(body).length } };
      },
      uploadDocument: async (ctx) => {
        let bytes = 0;
        for await (const chunk of ctx.pdf()) bytes += chunk.length;
        return { status: 200, json: { bytes } };
      },
    },
  });
});

after(async () => {
  await served.close();
  cleanup();
});

const auth = () => ({ authorization: `Bearer ${bearer('sender')}` });

/** bytes_read of the request log line with this correlation ID. */
function bytesRead(correlationId) {
  const line = served.lines.map((l) => JSON.parse(l)).find((record) => record.event === 'request' && record.correlation_id === correlationId);
  assert.ok(line, 'the request was logged');
  return line.bytes_read;
}

test('[SEC-03] a JSON body over 256 KiB is refused with 413 before it is read in full', async () => {
  assert.equal(JSON_BODY_LIMIT, 256 * KIB);
  const path = '/v1/envelopes';
  const headers = { ...auth(), 'content-type': 'application/json' };

  const declared = await streamUpload(served.port, { method: 'POST', path, headers: { ...headers, 'content-length': String(JSON_BODY_LIMIT + 1) }, total: JSON_BODY_LIMIT + 1 });
  assert.equal(declared.status, 413);
  assert.equal(declared.json.code, 'payload_too_large');
  assert.equal(bytesRead(declared.json.correlation_id), 0, 'a declared over-limit length is refused before reading');
  assert.equal(declared.headers.connection, 'close');

  const streamed = await streamUpload(served.port, { method: 'POST', path, headers, total: 64 * MIB });
  assert.equal(streamed.status, 413);
  assert.ok(streamed.written < 64 * MIB, `client wrote ${streamed.written} of ${64 * MIB} bytes`);
  const read = bytesRead(streamed.json.correlation_id);
  assert.ok(read > JSON_BODY_LIMIT && read <= JSON_BODY_LIMIT + 128 * KIB, `server read ${read} bytes`);

  // At the limit: accepted. One byte over: refused.
  const atLimit = `{"pad":"${'a'.repeat(JSON_BODY_LIMIT - 10)}"}`;
  assert.equal(Buffer.byteLength(atLimit), JSON_BODY_LIMIT);
  const accepted = await send(served.port, { method: 'POST', path, headers, body: atLimit });
  assert.equal(accepted.status, 201, accepted.text);
  const over = `{"pad":"${'a'.repeat(JSON_BODY_LIMIT - 9)}"}`;
  assert.equal((await send(served.port, { method: 'POST', path, headers, body: over })).status, 413);
});

test('[SEC-03] a PDF body over 10 MiB is refused with 413 before it is read in full', async () => {
  assert.equal(PDF_BODY_LIMIT, 10 * MIB);
  const path = `/v1/envelopes/${ENVELOPE_ID}/document`;
  const headers = { ...auth(), 'content-type': 'application/pdf', 'if-match': '"1"', 'idempotency-key': 'idem_synthetic_000000000001' };

  const declared = await streamUpload(served.port, { path, headers: { ...headers, 'content-length': String(PDF_BODY_LIMIT + 1) }, total: PDF_BODY_LIMIT + 1 });
  assert.equal(declared.status, 413);
  assert.equal(bytesRead(declared.json.correlation_id), 0);

  const streamed = await streamUpload(served.port, { path, headers, total: 48 * MIB });
  assert.equal(streamed.status, 413);
  assert.equal(streamed.json.code, 'payload_too_large');
  assert.ok(streamed.written < 48 * MIB, `client wrote ${streamed.written} of ${48 * MIB} bytes`);
  const read = bytesRead(streamed.json.correlation_id);
  assert.ok(read > PDF_BODY_LIMIT && read <= PDF_BODY_LIMIT + 128 * KIB, `server read ${read} bytes`);

  const exact = await streamUpload(served.port, { path, headers, total: PDF_BODY_LIMIT });
  assert.equal(exact.status, 200);
  assert.equal(exact.json.bytes, PDF_BODY_LIMIT);
});

test('[SEC-03] bodies are checked for media type and syntax, and never read before authentication', async () => {
  const jsonPath = '/v1/envelopes';
  const pdfPath = `/v1/envelopes/${ENVELOPE_ID}/document`;
  assert.equal((await send(served.port, { method: 'POST', path: jsonPath, headers: { ...auth(), 'content-type': 'text/plain' }, body: '{}' })).status, 415);
  assert.equal((await send(served.port, { method: 'PUT', path: pdfPath, headers: { ...auth(), 'content-type': 'application/json' }, body: '{}' })).status, 415);
  const malformed = await send(served.port, { method: 'POST', path: jsonPath, headers: { ...auth(), 'content-type': 'application/json' }, body: '{"a":' });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.json.code, 'invalid_request');
  const badUtf8 = await send(served.port, { method: 'POST', path: jsonPath, headers: { ...auth(), 'content-type': 'application/json' }, body: Buffer.from([0x22, 0xc3, 0x28, 0x22]) });
  assert.equal(badUtf8.status, 400);
  assert.equal((await send(served.port, { method: 'POST', path: jsonPath, headers: { ...auth(), 'content-type': 'application/json; charset=utf-8' }, body: '{"a":1}' })).status, 201);

  const anonymous = await streamUpload(served.port, { path: pdfPath, headers: { 'content-type': 'application/pdf' }, total: 32 * MIB });
  assert.equal(anonymous.status, 401);
  assert.equal(bytesRead(anonymous.json.correlation_id), 0, 'an unauthenticated upload is refused before its body is read');
  assert.ok(anonymous.written < 32 * MIB);
});
