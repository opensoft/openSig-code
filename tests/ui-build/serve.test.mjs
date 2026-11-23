// SPDX-License-Identifier: Apache-2.0
//
// T035 ui-build UB-03: a safe static route. The real application (T031's createApp) with the
// real route registry and the real createStaticHandler: GET and HEAD /sign serve the exact
// shell and /assets/<asset digest>/<path> the exact assets, with the strict security headers;
// nothing else is ever served, whatever the request-target; a missing, partial, tampered or
// linked build serves nothing. One case starts the composed server through the entrypoint's
// startServer (synthetic key file, migrated temporary database, the build in a temporary
// distDir), so the seam is proven by behaviour: no test reads main.ts (A-010 request #33 (4)),
// and no test writes the repository's dist/ (request #34, row DIST-DIR).
//
// Assets are immutable through T031's caching exception (row STATIC-CACHE, request #33);
// /sign, the 503 and every other non-200 keep no-store.

import assert from 'node:assert/strict';
import { cpSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { after, test } from 'node:test';

import { createParseServiceForTests } from '../../src/pdf/service.ts';
import { loadServerConfig } from '../../src/server/config.ts';
import { startServer } from '../../src/server/main.ts';
import { createStaticHandler, DEFAULT_DIST_DIR, RELOAD_INTERVAL_MS } from '../../src/server/static.ts';
import { assertBuilt, cleanup, composedEnvironment, copyTree, IMMUTABLE_CACHE_CONTROL, marker, rawRequest, REPO, runBuild, serveStatic, sha256, syntheticRoot, tempDir } from './support.mjs';

after(cleanup);

const SHELL = 'autograph/index.html';
const TYPES = { '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };

function assertStrictHeaders(response, cacheControl, label) {
  const csp = response.headers['content-security-policy'];
  assert.ok(typeof csp === 'string', `${label}: CSP present`);
  for (const directive of ["default-src 'none'", "script-src 'self'", "style-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"]) {
    assert.ok(csp.split(';').map((part) => part.trim()).includes(directive), `${label}: ${directive}`);
  }
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|'nonce-|'sha(?:256|384|512)-|\*|https?:|data:|blob:/, `${label}: no inline, eval or external source`);
  assert.equal(response.headers['x-content-type-options'], 'nosniff', `${label}: nosniff`);
  assert.equal(response.headers['referrer-policy'], 'no-referrer', `${label}: no-referrer`);
  assert.equal(response.headers['x-frame-options'], 'DENY', `${label}: X-Frame-Options`);
  assert.equal(response.headers['cross-origin-resource-policy'], 'same-origin', `${label}: CORP`);
  assert.equal(response.headers['cache-control'], cacheControl, `${label}: Cache-Control`);
  assert.equal(response.headers['set-cookie'], undefined, `${label}: no cookie`);
  for (const name of Object.keys(response.headers)) assert.doesNotMatch(name, /^access-control-/, `${label}: no CORS header`);
}

function buildSynthetic(outParent = tempDir('out')) {
  const root = syntheticRoot();
  const out = join(outParent, 'dist');
  const run = runBuild({ root, out });
  assertBuilt(run);
  return { root, out, manifest: run.manifest };
}

test('[UB-03] /sign serves the exact shell and each asset its exact bytes with the strict headers; assets are immutable, the shell is never cached', async () => {
  const { out, manifest } = buildSynthetic();
  const shellBytes = readFileSync(join(out, ...SHELL.split('/')));
  const served = await serveStatic({ distDir: out });
  try {
    for (const method of ['GET', 'HEAD']) {
      const response = await rawRequest(served.port, method, '/sign');
      assert.equal(response.status, 200, `${method} /sign`);
      assert.equal(response.headers['content-type'], 'text/html; charset=utf-8');
      assert.equal(response.headers['content-length'], String(shellBytes.length));
      if (method === 'GET') assert.ok(response.body.equals(shellBytes), 'the exact shell bytes');
      assertStrictHeaders(response, 'no-store', `${method} /sign`);
    }
    // A mail scanner's prefetch, or the invitation pushed into a query string: the same shell, and the query is never logged.
    const invitation = marker('invitation');
    const prefetch = await rawRequest(served.port, 'GET', `/sign?i=${invitation}`, { 'Sec-Purpose': 'prefetch' });
    assert.equal(prefetch.status, 200);
    assert.ok(prefetch.body.equals(shellBytes));
    assert.ok(!served.lines.join('\n').includes(invitation), 'the request log never carries the query');

    const assets = manifest.outputs.filter((output) => output.path !== SHELL);
    assert.equal(assets.length, 5);
    for (const output of assets) {
      assert.match(output.url, new RegExp(`^/assets/${manifest.asset_digest}/`));
      const bytes = readFileSync(join(out, ...output.path.split('/')));
      const extension = output.path.slice(output.path.lastIndexOf('.'));
      for (const method of ['GET', 'HEAD']) {
        const response = await rawRequest(served.port, method, output.url);
        assert.equal(response.status, 200, `${method} ${output.url}`);
        assert.equal(response.headers['content-type'], TYPES[extension], `${output.url}: content type`);
        assert.equal(response.headers['content-type'], output.content_type);
        assert.equal(response.headers['content-length'], String(bytes.length));
        if (method === 'GET') assert.ok(response.body.equals(bytes), `${output.url}: the exact bytes`);
        assertStrictHeaders(response, IMMUTABLE_CACHE_CONTROL, `${method} ${output.url}`);
      }
    }
  } finally {
    await served.close();
  }
});

test('[UB-03] traversal, encoded, malformed, stale and non-GET requests never reach a file: uniform 404, never a byte from outside the build', async () => {
  const project = tempDir('traversal');
  const { manifest, out } = buildSynthetic(project);
  const secret = marker('outside');
  writeFileSync(join(project, 'secret.txt'), `${secret}\n`);
  const mainBytes = readFileSync(join(out, 'autograph', 'main.js'));
  const digest = manifest.asset_digest;
  const served = await serveStatic({ distDir: out });
  const assertNothingServed = (response, label) => {
    assert.ok(!response.raw.includes(secret), `${label}: no byte from outside the build`);
    assert.ok(!response.body.includes(mainBytes), `${label}: no asset bytes`);
  };
  try {
    const targets = [
      `/assets/${digest}/../../secret.txt`,
      `/assets/${digest}/../build-provenance.json`,
      `/assets/${digest}/..%2f..%2fsecret.txt`,
      `/assets/${digest}/%2e%2e/%2e%2e/secret.txt`,
      `/assets/${digest}/%2E%2E%2F%2E%2E%2Fsecret.txt`,
      '/assets/%2e%2e/%2e%2e/secret.txt',
      `/assets/${digest}/main.js%00`,
      `/assets/${digest}/main.js%00.css`,
      `/assets/${digest}//main.js`,
      `/assets/${digest}/./main.js`,
      `/assets/${digest}/main.js/`,
      `/assets/${digest}/geometry`,
      `/assets/${digest}/`,
      `/assets/${digest}`,
      '/assets/',
      `/assets/${'0'.repeat(64)}/main.js`,
      `/assets/${digest.toUpperCase()}/main.js`,
      `/ASSETS/${digest}/main.js`,
      `/assets/${digest}/index.html`,
      `/assets/${digest}/main.ts`,
      `/assets/${digest}/build-provenance.json`,
      `/assets/${digest}/.hidden`,
      '/build-provenance.json',
      '/dist/build-provenance.json',
      '/autograph/main.js',
      '/autograph/index.html',
      '/index.html',
      '/src/autograph/main.ts',
      '/secret.txt',
      '/sign/',
      '/sign/../secret.txt',
      '/sign/..%2fsecret.txt',
      '/sign.html',
      '/SIGN',
      '/%73ign',
      '/favicon.ico',
      '/missing',
    ];
    for (const target of targets) {
      const response = await rawRequest(served.port, 'GET', target);
      assert.equal(response.status, 404, `GET ${target}`);
      assert.equal(JSON.parse(response.text).code, 'not_found', `GET ${target}: the uniform error body`);
      assertStrictHeaders(response, 'no-store', `GET ${target}`);
      assertNothingServed(response, `GET ${target}`);
    }
    // A request-target the HTTP parser itself may reject: Node's 400 or the uniform 404, never content.
    const backslash = await rawRequest(served.port, 'GET', `/assets/${digest}\\..\\..\\secret.txt`);
    assert.ok(backslash.status === 400 || backslash.status === 404, `backslash target: ${backslash.status}`);
    assertNothingServed(backslash, 'backslash target');
    // Only GET and HEAD ever reach the static handler.
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      for (const target of ['/sign', `/assets/${digest}/main.js`]) {
        const response = await rawRequest(served.port, method, target, { 'Content-Length': '0' });
        assert.equal(response.status, 404, `${method} ${target}`);
        assertNothingServed(response, `${method} ${target}`);
      }
    }
  } finally {
    await served.close();
  }
});

test('[UB-03] a missing, partial, tampered or linked build is never served: /sign is a no-store 503 and no asset is served', async (t) => {
  assert.equal(resolve(DEFAULT_DIST_DIR), join(REPO, 'dist'), "the default build is the repository's dist/");
  const config = loadServerConfig({ OPENSIG_PORT: '0' });
  assert.equal(typeof createStaticHandler({ config, distDir: join(tempDir('none'), 'dist') }), 'function', 'created without a build, and never throws');

  const { out: good, manifest } = buildSynthetic();
  const assetUrl = manifest.outputs.find((output) => output.path === 'autograph/main.js').url;
  const editManifest = (dir, change) => {
    const path = join(dir, 'build-provenance.json');
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    change(parsed);
    writeFileSync(path, `${JSON.stringify(parsed, null, 2)}\n`);
  };
  const damages = {
    'no output directory': (dir) => rmSync(dir, { recursive: true, force: true }),
    'no manifest': (dir) => rmSync(join(dir, 'build-provenance.json')),
    'a manifest that is not JSON': (dir) => writeFileSync(join(dir, 'build-provenance.json'), '{ not json'),
    'an output changed by one byte': (dir) => {
      const path = join(dir, 'autograph', 'review.css');
      const bytes = readFileSync(path);
      bytes[0] ^= 0x01;
      writeFileSync(path, bytes);
    },
    'an output missing': (dir) => rmSync(join(dir, 'autograph', 'types.js')),
    'an output replaced by a link to identical bytes': (dir) => {
      const copy = join(tempDir('link'), 'main.js');
      cpSync(join(dir, 'autograph', 'main.js'), copy);
      rmSync(join(dir, 'autograph', 'main.js'));
      symlinkSync(copy, join(dir, 'autograph', 'main.js'));
    },
    'the output directory replaced by a link to an identical copy': (dir) => {
      const copy = join(tempDir('linkdir'), 'autograph');
      copyTree(join(dir, 'autograph'), copy);
      rmSync(join(dir, 'autograph'), { recursive: true });
      symlinkSync(copy, join(dir, 'autograph'));
    },
    'a manifest path outside the build': (dir) => editManifest(dir, (parsed) => {
      parsed.outputs[0].path = 'autograph/../../secret.txt';
    }),
    'a second HTML output': (dir) => {
      const bytes = Buffer.from('<!doctype html>\n');
      writeFileSync(join(dir, 'autograph', 'other.html'), bytes);
      editManifest(dir, (parsed) => parsed.outputs.push({ path: 'autograph/other.html', sha256: sha256(bytes), bytes: bytes.length }));
    },
    'a build digest that does not match': (dir) => editManifest(dir, (parsed) => {
      parsed.build_digest = '0'.repeat(64);
    }),
  };
  const assertUnavailable = async (distDir, label) => {
    const served = await serveStatic({ distDir });
    try {
      const shell = await rawRequest(served.port, 'GET', '/sign');
      assert.equal(shell.status, 503, `${label}: /sign`);
      assert.equal(JSON.parse(shell.text).code, 'internal', `${label}: the uniform error body`);
      assertStrictHeaders(shell, 'no-store', `${label}: /sign`);
      assert.equal((await rawRequest(served.port, 'GET', assetUrl)).status, 404, `${label}: no asset`);
      assert.ok(served.lines.some((line) => line.includes('static_build_unavailable')), `${label}: logged`);
    } finally {
      await served.close();
    }
  };
  for (const [label, damage] of Object.entries(damages)) {
    const dir = join(tempDir('damaged'), 'dist');
    copyTree(good, dir);
    damage(dir);
    await assertUnavailable(dir, label);
  }
  const linked = join(tempDir('linked'), 'dist');
  symlinkSync(good, linked);
  await assertUnavailable(linked, 'the output root itself a link');

  // A file planted beside the outputs is never served, while the build itself is.
  const planted = join(tempDir('planted'), 'dist');
  copyTree(good, planted);
  writeFileSync(join(planted, 'autograph', 'planted.js'), 'export const planted = true;\n');
  const served = await serveStatic({ distDir: planted });
  try {
    assert.equal((await rawRequest(served.port, 'GET', '/sign')).status, 200);
    assert.equal((await rawRequest(served.port, 'GET', `/assets/${manifest.asset_digest}/planted.js`)).status, 404, 'only what the manifest lists');
  } finally {
    await served.close();
  }

  // No reload storm: a handler made before its build exists retries only after RELOAD_INTERVAL_MS.
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const later = join(tempDir('later'), 'dist');
  const handler = createStaticHandler({ config, distDir: later });
  const silent = { info() {}, warn() {}, error() {}, child() { return silent; } };
  const ctx = { operationId: 'openReviewShell', path: '/sign', request: { method: 'GET' }, logger: silent };
  await assert.rejects(handler(ctx), (error) => error.status === 503);
  copyTree(good, later);
  await assert.rejects(handler(ctx), (error) => error.status === 503, 'not reloaded before the interval');
  t.mock.timers.tick(RELOAD_INTERVAL_MS);
  const result = await handler(ctx);
  assert.equal(result.status, 200);
  assert.ok(Buffer.from(result.body).equals(readFileSync(join(later, 'autograph', 'index.html'))), 'served once the interval passed');
});

// T033's plan for an empty launcher set, as SEC-12's DIST-DIR case uses it: no sandbox probe
// runs at startup. Serving the shell and assets does not depend on the parse plan.
const unprobedPlan = createParseServiceForTests({ launchers: [] }).plan;

test('[UB-03] the entrypoint serves the build through static.ts: startServer, with a synthetic key file, a migrated temporary database and a temporary distDir, serves /sign (no-store) and an asset (immutable), and without a build /sign is a no-store 503', async () => {
  // Every build goes to a temporary directory, passed as StartOptions.distDir (row DIST-DIR):
  // never the repository's dist/. A head whose startServer ignored distDir would serve the
  // repository's dist/ (or nothing, a 503) instead of these exact bytes.
  const empty = join(tempDir('nobuild'), 'dist');
  const unbuilt = await startServer(composedEnvironment(), { logSink: () => {}, parsePlan: unprobedPlan, distDir: empty });
  try {
    const shell = await rawRequest(unbuilt.port, 'GET', '/sign');
    assert.equal(shell.status, 503, 'GET /sign through the entrypoint without a build');
    assert.equal(JSON.parse(shell.text).code, 'internal', 'the uniform error body');
    assertStrictHeaders(shell, 'no-store', 'entrypoint /sign without a build');
  } finally {
    await unbuilt.close();
  }

  const { out, manifest } = buildSynthetic();
  const shellBytes = readFileSync(join(out, 'autograph', 'index.html'));
  const main = manifest.outputs.find((output) => output.path === 'autograph/main.js');
  const mainBytes = readFileSync(join(out, ...main.path.split('/')));
  const lines = [];
  const running = await startServer(composedEnvironment(), { logSink: (line) => lines.push(line), parsePlan: unprobedPlan, distDir: out });
  try {
    const listening = lines.map((line) => JSON.parse(line)).find((record) => record.event === 'listening');
    assert.ok(listening !== undefined, 'the composed server is listening');
    assert.equal(listening.static_shell, true, 'the entrypoint loaded static.ts');
    const shell = await rawRequest(running.port, 'GET', '/sign');
    assert.equal(shell.status, 200, 'GET /sign through the entrypoint');
    assert.ok(shell.body.equals(shellBytes), 'the exact shell of the build in distDir');
    assertStrictHeaders(shell, 'no-store', 'entrypoint /sign');
    const asset = await rawRequest(running.port, 'GET', main.url);
    assert.equal(asset.status, 200, `GET ${main.url} through the entrypoint`);
    assert.ok(asset.body.equals(mainBytes), 'the exact asset bytes');
    assert.equal(asset.headers['content-type'], 'text/javascript; charset=utf-8');
    assertStrictHeaders(asset, IMMUTABLE_CACHE_CONTROL, `entrypoint ${main.url}`);
    const stale = await rawRequest(running.port, 'GET', `/assets/${'0'.repeat(64)}/main.js`);
    assert.equal(stale.status, 404, 'another digest is not served');
    assertStrictHeaders(stale, 'no-store', 'entrypoint stale asset');
  } finally {
    await running.close();
  }
});
