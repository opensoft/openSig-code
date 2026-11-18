// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-01 and SEC-02: security headers on every response, and frame-ancestors
// 'self' only on the recipient document response.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { startServer } from '../../src/server/main.ts';
import { bearer, cleanup, composedEnv, ENVELOPE_ID, send, serveApp } from './support.mjs';

after(cleanup);

function assertSecurityHeaders(response, framing, label) {
  const csp = response.headers['content-security-policy'];
  assert.ok(typeof csp === 'string', `${label}: CSP present`);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|unsafe-hashes|wasm-unsafe-eval|\*|https?:|data:|blob:/, `${label}: CSP has no inline, eval, wildcard or external source`);
  assert.match(csp, /(?:^|; )default-src 'none'(?:;|$)/, `${label}: default-src 'none'`);
  assert.match(csp, /(?:^|; )object-src 'none'(?:;|$)/);
  assert.match(csp, /(?:^|; )base-uri 'none'(?:;|$)/);
  assert.equal([...csp.matchAll(/frame-ancestors/g)].length, 1, `${label}: one frame-ancestors directive`);
  assert.match(csp, new RegExp(`(?:^|; )frame-ancestors '${framing}'(?:;|$)`), `${label}: frame-ancestors '${framing}'`);
  assert.equal(response.headers['referrer-policy'], 'no-referrer', `${label}: Referrer-Policy`);
  assert.equal(response.headers['x-content-type-options'], 'nosniff', `${label}: nosniff`);
  assert.equal(response.headers['x-frame-options'], framing === 'self' ? 'SAMEORIGIN' : 'DENY', `${label}: X-Frame-Options`);
  assert.equal(response.headers['cache-control'], 'no-store', `${label}: Cache-Control`);
  assert.equal(response.headers['cross-origin-opener-policy'], 'same-origin');
  assert.match(response.headers['x-correlation-id'], /^[A-Za-z0-9_-]{8,64}$/);
  for (const name of Object.keys(response.headers)) {
    assert.doesNotMatch(name, /^access-control-|^x-powered-by$|^server$/, `${label}: no ${name}`);
  }
}

test('[SEC-01] every response carries the security headers, and handlers cannot weaken them', async () => {
  const served = await serveApp({
    handlers: {
      readEnvelope: async () => ({
        status: 200,
        json: { ok: true },
        headers: {
          'Content-Security-Policy': "default-src * 'unsafe-inline' 'unsafe-eval'",
          'Access-Control-Allow-Origin': '*',
          'X-Frame-Options': 'ALLOWALL',
          'Referrer-Policy': 'unsafe-url',
          'Cache-Control': 'public, max-age=3600',
          'X-Correlation-Id': 'chosen-by-handler',
        },
      }),
    },
  });
  try {
    const auth = { authorization: `Bearer ${bearer('sender')}` };
    const cases = {
      '200 handler': { method: 'GET', path: `/v1/envelopes/${ENVELOPE_ID}`, headers: auth },
      'HEAD of a handler route': { method: 'HEAD', path: `/v1/envelopes/${ENVELOPE_ID}`, headers: auth },
      '401 no credential': { method: 'GET', path: `/v1/envelopes/${ENVELOPE_ID}` },
      '403 role': { method: 'POST', path: `/v1/envelopes/${ENVELOPE_ID}/send-confirmations`, headers: { authorization: `Bearer ${bearer('service')}`, 'content-type': 'application/json' }, body: '{}' },
      '403 origin': { method: 'POST', path: '/v1/recipient-session/challenges', headers: { 'content-type': 'application/json', origin: 'https://evil.example.test' }, body: '{}' },
      '404 unknown path': { method: 'GET', path: '/v1/unknown' },
      '413 declared length': { method: 'PUT', path: `/v1/envelopes/${ENVELOPE_ID}/document`, headers: { ...auth, 'content-type': 'application/pdf', 'content-length': String(10 * 1024 * 1024 + 1) } },
      '501 review shell without static assets': { method: 'GET', path: '/sign' },
    };
    const expected = { '200 handler': 200, 'HEAD of a handler route': 200, '401 no credential': 401, '403 role': 403, '403 origin': 403, '404 unknown path': 404, '413 declared length': 413, '501 review shell without static assets': 501 };
    for (const [label, options] of Object.entries(cases)) {
      const response = await send(served.port, options);
      assert.equal(response.status, expected[label], `${label}: status ${response.status} ${response.text}`);
      assertSecurityHeaders(response, 'none', label);
      if (label === 'HEAD of a handler route') assert.equal(response.bytes.length, 0, 'HEAD has no body');
    }
    const handled = await send(served.port, cases['200 handler']);
    assert.notEqual(handled.headers['x-correlation-id'], 'chosen-by-handler');
  } finally {
    await served.close();
  }
});

test('[SEC-01] the real entrypoint on its loopback default serves the same headers', async () => {
  const lines = [];
  const running = await startServer(composedEnv(), { logSink: (line) => lines.push(line) });
  try {
    for (const path of ['/sign', `/v1/envelopes/${ENVELOPE_ID}`, '/v1/recipient-session', '/missing']) {
      assertSecurityHeaders(await send(running.port, { path }), 'none', `entrypoint ${path}`);
    }
  } finally {
    await running.close();
  }
});

test('[SEC-02] only the recipient document response allows frame-ancestors self', async () => {
  const pdf = Buffer.from('%PDF-1.7\n% synthetic placeholder bytes for header checks\n%%EOF\n', 'latin1');
  let documentMode = 'pdf';
  const served = await serveApp({
    handlers: {
      readRecipientDocument: async () => {
        if (documentMode === 'pdf') return { status: 200, body: pdf, contentType: 'application/pdf', headers: { 'content-disposition': 'inline' } };
        if (documentMode === 'json') return { status: 200, json: { not: 'a document' } };
        return { status: 409, json: { code: 'state_conflict' } };
      },
      downloadFinalPdf: async () => ({ status: 200, body: pdf, contentType: 'application/pdf' }),
      readRecipientManifest: async () => ({ status: 200, body: pdf, contentType: 'application/pdf' }),
    },
  });
  try {
    const documentResponse = await send(served.port, { path: '/v1/recipient-session/document' });
    assert.equal(documentResponse.status, 200);
    assert.ok(documentResponse.bytes.equals(pdf), 'the exact bytes are served');
    assert.equal(documentResponse.headers['content-type'], 'application/pdf');
    assertSecurityHeaders(documentResponse, 'self', 'recipient document');

    documentMode = 'json';
    assertSecurityHeaders(await send(served.port, { path: '/v1/recipient-session/document' }), 'none', 'document route returning JSON');
    documentMode = 'error';
    assertSecurityHeaders(await send(served.port, { path: '/v1/recipient-session/document' }), 'none', 'document route returning an error status');
    assertSecurityHeaders(await send(served.port, { path: '/v1/recipient-session/document', headers: { authorization: `Bearer ${bearer()}` } }), 'none', 'document route refusing an operator bearer');
    assertSecurityHeaders(await send(served.port, { path: '/v1/recipient-session/manifest' }), 'none', 'another recipient route serving PDF bytes');
    assertSecurityHeaders(
      await send(served.port, { path: `/v1/envelopes/${ENVELOPE_ID}/final-pdf`, headers: { authorization: `Bearer ${bearer()}` } }),
      'none',
      'operator final PDF download',
    );
  } finally {
    await served.close();
  }
});
