// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-01 and SEC-02: security headers on every response, and frame-ancestors
// 'self' only on the recipient document response. SEC-01 (extended, A-010 row STATIC-CACHE,
// request #33): the one caching exception, shown in both directions with a stub static handler.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { startServer } from '../../src/server/main.ts';
import { bearer, cleanup, composedEnv, ENVELOPE_ID, send, serveApp } from './support.mjs';

after(cleanup);

/** The spec's Cache-Control for a content-addressed static asset (the T031 line, STATIC-CACHE). */
const IMMUTABLE = 'public, max-age=31536000, immutable';

/** Every security header other than Cache-Control, as sent. */
function otherSecurityHeaders(response) {
  const names = ['content-security-policy', 'referrer-policy', 'x-content-type-options', 'x-frame-options', 'cross-origin-opener-policy', 'cross-origin-resource-policy'];
  return Object.fromEntries(names.map((name) => [name, response.headers[name]]));
}

function assertSecurityHeaders(response, framing, label, cacheControl = 'no-store') {
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
  assert.equal(response.headers['cache-control'], cacheControl, `${label}: Cache-Control`);
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

test('[SEC-01] the one caching exception: only a 200 from the static handler for a path that matches no route, flagged immutable, is cacheable, with every other security header unchanged; every route response and every non-200 keeps no-store (A-010 STATIC-CACHE, request #33)', async () => {
  const asset = Buffer.from('/* synthetic content-addressed asset */\n', 'utf8');
  const shell = Buffer.from('<!doctype html><title>synthetic review shell</title>\n', 'utf8');
  // Headers a handler might try; the server's security headers win on every response.
  const weakening = {
    'Cache-Control': 'public, max-age=60',
    'X-Frame-Options': 'ALLOWALL',
    'Content-Security-Policy': 'default-src *',
    'Cross-Origin-Resource-Policy': 'cross-origin',
  };
  const asked = [];
  const staticHandler = async (ctx) => {
    asked.push(`${ctx.operationId ?? 'no route'} ${ctx.path}`);
    if (ctx.operationId === 'openReviewShell') return { status: 200, body: shell, contentType: 'text/html; charset=utf-8', cache: 'immutable', headers: weakening };
    switch (ctx.path) {
      case '/assets/app.flagged.js':
        return { status: 200, body: asset, contentType: 'text/javascript; charset=utf-8', cache: 'immutable', headers: weakening };
      case '/assets/app.unflagged.js':
        return { status: 200, body: asset, contentType: 'text/javascript; charset=utf-8' };
      case '/assets/app.no-store.js':
        return { status: 200, body: asset, contentType: 'text/javascript; charset=utf-8', cache: 'no-store' };
      case '/assets/app.missing.js':
        return { status: 404, json: { code: 'not_found' }, cache: 'immutable', headers: weakening };
      case '/assets/app.unchanged.js':
        return { status: 304, cache: 'immutable' };
      default:
        return null;
    }
  };
  const served = await serveApp({
    staticHandler,
    handlers: { readEnvelope: async () => ({ status: 200, json: { ok: true }, cache: 'immutable', headers: weakening }) },
  });
  try {
    const auth = { authorization: `Bearer ${bearer('sender')}` };
    // The no-store reference for the comparison of every other security header.
    const reference = await send(served.port, { path: '/assets/app.unflagged.js' });
    assert.equal(reference.status, 200, 'premise: the stub serves an unflagged asset');

    for (const method of ['GET', 'HEAD']) {
      const label = `${method} of a static asset 200 with the flag`;
      const response = await send(served.port, { method, path: '/assets/app.flagged.js' });
      assert.equal(response.status, 200, `${label}: status`);
      assertSecurityHeaders(response, 'none', label, IMMUTABLE);
      assert.deepEqual(otherSecurityHeaders(response), otherSecurityHeaders(reference), `${label}: every other security header is unchanged`);
      assert.equal(response.headers['content-type'], 'text/javascript; charset=utf-8', `${label}: the asset's own content type`);
      if (method === 'GET') assert.ok(response.bytes.equals(asset), `${label}: the asset's bytes`);
      else assert.equal(response.bytes.length, 0, `${label}: HEAD has no body`);
    }

    const noStore = {
      "the static handler's 404 with the flag": [{ path: '/assets/app.missing.js' }, 404],
      "the static handler's 304 with the flag": [{ path: '/assets/app.unchanged.js' }, 304],
      'a static 200 without the flag': [{ path: '/assets/app.unflagged.js' }, 200],
      'a static 200 flagged no-store': [{ path: '/assets/app.no-store.js' }, 200],
      'a path the static handler does not serve (the uniform 404)': [{ path: '/assets/app.absent.js' }, 404],
      'the review shell through openReviewShell, flagged': [{ path: '/sign' }, 200],
      "a route handler's 200 with the flag": [{ path: `/v1/envelopes/${ENVELOPE_ID}`, headers: auth }, 200],
      "HEAD of a route handler's 200 with the flag": [{ method: 'HEAD', path: `/v1/envelopes/${ENVELOPE_ID}`, headers: auth }, 200],
    };
    for (const [label, [options, status]] of Object.entries(noStore)) {
      const response = await send(served.port, options);
      assert.equal(response.status, status, `${label}: status ${response.status} ${response.text}`);
      assertSecurityHeaders(response, 'none', label);
    }
    // The shell's 200 came from the static handler, through its route: no-store is the route's rule.
    assert.ok(asked.includes('openReviewShell /sign'), `the static handler served the review shell through its route (asked: ${asked.join(', ')})`);
    assert.ok(asked.includes('no route /assets/app.flagged.js'), 'the flagged asset was served for a path that matches no route');
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
