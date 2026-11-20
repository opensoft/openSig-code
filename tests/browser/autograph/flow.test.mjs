// SPDX-License-Identifier: Apache-2.0
//
// T009 review shell: the invitation, the challenge and the document review, driven in
// Chromium against the real server (world.mjs).
//   AG-01  the invitation is read from the fragment once and removed from the address and
//          the session history; opening the link sends nothing that changes state. The page
//          the link opens is the real build of src/autograph/ (A-010 request #36): built
//          twice into temporary directories with identical manifests, served as /sign with
//          no-store and its assets immutable, with the security headers.
//   AG-02  the challenge, then the code, and the real __Host-opensig_rs session cookie
//          accepted and sent back over plain http://127.0.0.1 by the locked Chromium (row
//          LOOPBACK-COOKIE, request #35); document review: the exact frozen bytes checked
//          against the digest, shown by the browser's own PDF viewer and downloadable, and the
//          original SVG page-outline schematic with the field boxes.
// Tokens and codes stay in memory; no assertion message carries one.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';

import { apiRequests, focused, launchBrowser, LOCKED_VERSION, lockedChromium, openPage, responseTo, SESSION_COOKIE, sessionCookie, signIn, step, verified } from './browser.mjs';
import { buildShell, CHALLENGE_PATH, DOCUMENT_PATH, SESSION_PATH, sha256, sloppyCode, startWorld, wrongCode } from './world.mjs';

let world;
let browser;

before(async () => {
  world = await startWorld();
  browser = await launchBrowser();
});

after(async () => {
  try {
    await browser?.close();
  } finally {
    await world?.close();
  }
});

/** A request URL as it goes on the wire: without its fragment. */
function wire(url) {
  const hash = url.indexOf('#');
  return hash === -1 ? url : url.slice(0, hash);
}

/** A number as the schematic writes it (dom.ts num): at most two decimals. */
function num(value) {
  return String(Math.round(value * 100) / 100);
}

const IMMUTABLE = 'public, max-age=31536000, immutable';

/** The security headers every response carries (T031), with the given Cache-Control. */
function assertSecurityHeaders(headers, cacheControl, label) {
  assert.equal(headers['cache-control'], cacheControl, `${label}: Cache-Control`);
  const csp = headers['content-security-policy'] ?? '';
  for (const directive of ["default-src 'none'", "script-src 'self'", "style-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"]) {
    assert.ok(csp.split(';').map((part) => part.trim()).includes(directive), `${label}: ${directive}`);
  }
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/, `${label}: no inline or eval allowance`);
  assert.equal(headers['x-content-type-options'], 'nosniff', `${label}: nosniff`);
  assert.equal(headers['referrer-policy'], 'no-referrer', `${label}: Referrer-Policy`);
  assert.equal(headers['x-frame-options'], 'DENY', `${label}: X-Frame-Options`);
}

test('[AG-01] the page the link opens is the real build of src/autograph/: two builds give identical manifests, and the server serves the shell as /sign (no-store) and its assets (immutable) with the security headers, byte for byte', async () => {
  // A second build of the real sources into another temporary directory (never the
  // repository's dist/): the same manifest, byte for byte, as the build the server serves.
  const manifestBytes = readFileSync(join(world.distDir, 'build-provenance.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const rebuildRoot = mkdtempSync(join(tmpdir(), 'opensig-autograph-rebuild-'));
  try {
    buildShell(join(rebuildRoot, 'dist'));
    assert.ok(readFileSync(join(rebuildRoot, 'dist', 'build-provenance.json')).equals(manifestBytes), 'two builds of the real sources give identical manifests');
  } finally {
    rmSync(rebuildRoot, { recursive: true, force: true });
  }
  const sources = manifest.inputs.filter((input) => input.path.startsWith('src/autograph/') && input.path.endsWith('.ts'));
  assert.ok(sources.length >= 10, `the build reads the real browser sources (${sources.length} scripts)`);

  const sent = await world.sentEnvelope();
  const { page, close } = await openPage(browser);
  const responses = [];
  page.on('response', (response) => responses.push(response));
  try {
    await page.goto(sent.url);
    await step(page, 'invitation');
    const shell = responses.find((response) => new URL(response.url()).pathname === '/sign');
    assert.ok(shell !== undefined, 'the browser loaded /sign');
    assert.equal(shell.status(), 200);
    assertSecurityHeaders(await shell.allHeaders(), 'no-store', '/sign');
    assert.ok((await shell.body()).equals(readFileSync(join(world.distDir, 'autograph', 'index.html'))), '/sign is the built shell');

    const outputs = new Map(manifest.outputs.map((output) => [output.url, output]));
    const assets = responses.filter((response) => new URL(response.url()).pathname.startsWith('/assets/'));
    const loaded = assets.map((response) => new URL(response.url()).pathname);
    for (const wanted of ['main.js', 'flow.js', 'review.css']) {
      assert.ok(loaded.includes(`/assets/${manifest.asset_digest}/${wanted}`), `the shell loaded ${wanted} from the build's immutable path`);
    }
    for (const response of assets) {
      const path = new URL(response.url()).pathname;
      const output = outputs.get(path);
      assert.ok(output !== undefined, `${path} is an output of this build`);
      assert.equal(response.status(), 200, `${path}: 200`);
      const headers = await response.allHeaders();
      assertSecurityHeaders(headers, IMMUTABLE, path);
      assert.equal(headers['content-type'], output.content_type, `${path}: content type`);
      assert.ok((await response.body()).equals(readFileSync(join(world.distDir, ...output.path.split('/')))), `${path}: the built bytes`);
    }
  } finally {
    await close();
  }
});

test('[AG-01] the invitation is read from the fragment once and scrubbed: not in the address, the history, storage, the DOM or any request URL; Back, Forward and reload cannot bring it back', async () => {
  const sent = await world.sentEnvelope();
  const { context, page, requests, close } = await openPage(browser);
  try {
    // A same-origin page first, so the invitation is a history entry of its own.
    await page.goto(`${world.origin}/not-a-page`);
    await page.goto(sent.url);
    await step(page, 'invitation');
    assert.equal(page.url(), `${world.origin}/sign`, 'the address bar holds the bare path');
    const where = await page.evaluate(() => ({ hash: location.hash, search: location.search, href: location.href }));
    assert.deepEqual(where, { hash: '', search: '', href: `${world.origin}/sign` });
    assert.equal((await page.content()).includes(sent.token), false, 'the token is not in the DOM');
    assert.equal(JSON.stringify(await context.storageState()).includes(sent.token), false, 'the token is not in cookies or storage');
    // Playwright reports a navigation's URL with its fragment, which never goes on the wire;
    // what the server can see is the URL without it, and the Referer.
    assert.equal(
      requests.some((request) => wire(request.url).includes(sent.token) || (request.headers.referer ?? '').includes(sent.token)),
      false,
      'no request URL or Referer carries the token',
    );
    assert.deepEqual(apiRequests(requests, world.origin), [], 'opening the link calls no API');

    await page.goBack();
    assert.equal(page.url(), `${world.origin}/not-a-page`);
    await page.goForward();
    assert.equal(page.url(), `${world.origin}/sign`, 'the history entry has no fragment');
    await page.reload();
    await step(page, 'no-invitation');
    assert.equal(page.url(), `${world.origin}/sign`);
    assert.match(await page.locator('#step-title').textContent(), /Open your invitation link/);
    assert.equal(
      requests.some((request) => wire(request.url).includes(sent.token)),
      false,
      'still no request URL carries the token',
    );
    assert.equal(
      requests.filter((request) => request.url.includes(sent.token)).length <= 1,
      true,
      'only the opening navigation itself had the fragment',
    );
  } finally {
    await close();
  }
});

test('[AG-01] opening and reloading the link change nothing (no API call, no code, no mail) until Email me a code; a token in the query string is never read', async () => {
  const sent = await world.sentEnvelope();
  const workBefore = world.composition.ceremony.challengeWorkStats();
  const { page, requests, close } = await openPage(browser);
  try {
    await page.goto(sent.url);
    await step(page, 'invitation');
    await page.locator('#request-code').waitFor();
    await world.composition.ceremony.drain();
    assert.deepEqual(apiRequests(requests, world.origin), [], 'no API request on open');
    assert.deepEqual(world.composition.ceremony.challengeWorkStats(), workBefore, 'no challenge work started');
    assert.deepEqual(world.takeMails('recipient_challenge', sent.recipients[0]), [], 'no code mailed');

    const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
    await page.getByRole('button', { name: 'Email me a code' }).click();
    assert.equal((await challenge).status(), 202);
    const posted = apiRequests(requests, world.origin);
    assert.equal(posted.length, 1, 'only the explicit action calls the API');
    assert.equal(posted[0].method, 'POST');
    assert.equal(posted[0].url, `${world.origin}${CHALLENGE_PATH}`);
    assert.equal(JSON.parse(posted[0].body).invitation === sent.token, true, 'the token goes in the request body, never a URL');
    assert.equal(typeof (await world.code(sent.recipients[0])), 'string');
  } finally {
    await close();
  }

  const scanner = await openPage(browser);
  try {
    const fake = randomBytes(32).toString('base64url');
    await scanner.page.goto(`${world.origin}/sign?i=${fake}`);
    await step(scanner.page, 'no-invitation');
    assert.equal(scanner.page.url(), `${world.origin}/sign`, 'the query string is dropped from the address');
    assert.equal((await scanner.page.content()).includes(fake), false);
    const calls = apiRequests(scanner.requests, world.origin);
    assert.deepEqual(
      calls.map((call) => `${call.method} ${call.url}`),
      [`GET ${world.origin}${SESSION_PATH}`],
      'without a fragment the shell only asks whether a session exists',
    );
  } finally {
    await scanner.close();
  }
});

test('[AG-02] challenge, then code: a wrong code is refused with an alert and no session; the right code typed loosely (case, spaces, dash, O and l) opens the session', async () => {
  const sent = await world.sentEnvelope();
  const { page, requests, close } = await openPage(browser);
  try {
    await page.goto(sent.url);
    await step(page, 'invitation');
    const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
    await page.getByRole('button', { name: 'Email me a code' }).click();
    assert.equal((await challenge).status(), 202);
    await step(page, 'code');
    assert.equal(await focused(page), 'h2#step-title[]', 'focus moves to the new step heading');
    assert.match(await page.locator('#status').textContent(), /If your link is valid, we emailed you a code/);
    const code = await world.code(sent.recipients[0]);

    const input = page.getByRole('textbox', { name: 'One-time code' });
    assert.equal(await input.getAttribute('autocomplete'), 'one-time-code');
    await input.fill(wrongCode(code));
    const refused = responseTo(page, world.origin, SESSION_PATH, 'POST');
    await page.getByRole('button', { name: 'Continue' }).click();
    assert.equal((await refused).status(), 401);
    await page.locator('#alert', { hasText: 'That code did not work' }).waitFor();
    await step(page, 'code');
    assert.equal(await focused(page), 'input#code[code]', 'focus returns to the code field');
    assert.equal(JSON.stringify(await page.context().cookies()).includes('__Host-opensig_rs'), false, 'no session cookie');

    await input.fill(sloppyCode(code));
    const created = responseTo(page, world.origin, SESSION_PATH, 'POST');
    await page.getByRole('button', { name: 'Continue' }).click();
    assert.equal((await created).status(), 201);
    const posts = apiRequests(requests, world.origin).filter((request) => request.method === 'POST' && request.url === `${world.origin}${SESSION_PATH}`);
    assert.equal(posts.length, 2);
    assert.equal(JSON.parse(posts[1].body).code === code, true, 'the code is sent in contract form');
    await step(page, 'review');
    assert.equal(await focused(page), 'h2#step-title[]');
    assert.equal(await page.locator('#alert').textContent(), '', 'the alert is cleared');
  } finally {
    await close();
  }
});

test('[AG-02] the locked Chromium accepts the real __Host-opensig_rs session cookie over plain http://127.0.0.1 with every production attribute and sends it back (row LOOPBACK-COOKIE: no bypass flag, no weakened attribute)', async (t) => {
  const locked = lockedChromium();
  t.diagnostic(`chromium revision ${locked.revision}, version ${browser.version()}, executable <browsers>/${locked.relativePath}, launched with no launch arguments`);
  assert.equal(browser.version(), LOCKED_VERSION);
  const sent = await world.sentEnvelope();
  const { context, page, requests, close } = await openPage(browser);
  try {
    await page.goto(sent.url);
    await step(page, 'invitation');
    assert.equal(await sessionCookie(context, world.origin), null, 'no session cookie before the code');
    const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
    await page.getByRole('button', { name: 'Email me a code' }).click();
    assert.equal((await challenge).status(), 202);
    const code = await world.code(sent.recipients[0]);
    await step(page, 'code');
    await page.getByRole('textbox', { name: 'One-time code' }).fill(code);
    const created = responseTo(page, world.origin, SESSION_PATH, 'POST');
    const fromCreated = world.lines.length;
    await page.getByRole('button', { name: 'Continue' }).click();
    const response = await created;
    assert.equal(response.status(), 201, 'the code opens a session');
    const setCookie = (await response.headerValue('set-cookie')) ?? '';
    assert.match(setCookie, /^__Host-opensig_rs=[^;\s]+; Path=\/; Secure; HttpOnly; SameSite=Strict$/, 'the server sets the production cookie, nothing weakened');

    const cookie = await sessionCookie(context, world.origin);
    t.diagnostic(`session cookie as the browser holds it (value omitted): ${JSON.stringify(cookie)}`);
    assert.ok(cookie !== null, 'the locked Chromium accepted the __Host- Secure cookie on http://127.0.0.1');
    assert.deepEqual(
      { name: cookie.name, domain: cookie.domain, path: cookie.path, secure: cookie.secure, httpOnly: cookie.httpOnly, sameSite: cookie.sameSite, expires: cookie.expires, hasValue: cookie.hasValue },
      { name: SESSION_COOKIE, domain: '127.0.0.1', path: '/', secure: true, httpOnly: true, sameSite: 'Strict', expires: -1, hasValue: true },
      'host-only (exact host, no Domain attribute), Secure, HttpOnly, SameSite=Strict, Path=/, a session cookie',
    );
    assert.doesNotMatch(setCookie, /;\s*Domain=/i, 'the server set no Domain attribute');

    // Sent back, proven at the SERVER (the jar alone is not proof): the review step's own
    // session-guarded reads, and a further same-origin read, are answered as an authenticated
    // session; the same read without credentials is the contract's 401 from the session guard.
    const handled = (from) =>
      world.lines
        .slice(from)
        .map((line) => JSON.parse(line))
        .filter((record) => record.event === 'request')
        .map((record) => `${record.method} ${record.path} ${record.operation} ${record.status}`);
    await step(page, 'review');
    await verified(page);
    const guarded = handled(fromCreated);
    assert.ok(guarded.includes(`GET ${DOCUMENT_PATH} readRecipientDocument 200`), `the browser's document read reached the session guard and was accepted (${guarded.join(', ')})`);
    const fromRead = world.lines.length;
    const read = responseTo(page, world.origin, SESSION_PATH, 'GET');
    const status = await page.evaluate((path) => fetch(path, { credentials: 'same-origin', cache: 'no-store' }).then((answer) => answer.status), SESSION_PATH);
    assert.equal(status, 200, 'the session read is authenticated by the cookie');
    const carried = (await (await read).request().allHeaders()).cookie ?? '';
    assert.match(carried, /(?:^|;\s*)__Host-opensig_rs=/, 'the browser sent the session cookie');
    const omitted = await page.evaluate((path) => fetch(path, { credentials: 'omit', cache: 'no-store' }).then((answer) => answer.status), SESSION_PATH);
    assert.equal(omitted, 401, 'without the cookie the session guard answers 401');
    // Only the session path: the viewer frame may load the document meanwhile (also with the cookie).
    const observed = handled(fromRead).filter((line) => line.startsWith(`GET ${SESSION_PATH} `));
    t.diagnostic(`server request log after the session opened (no values): ${[...guarded, ...observed].join('; ')}`);
    assert.deepEqual(observed, [`GET ${SESSION_PATH} readRecipientSession 200`, `GET ${SESSION_PATH} readRecipientSession 401`], 'the server accepted the cookie-bearing read as a session and refused the same read without it');
    assert.equal(await page.evaluate(() => document.cookie.includes('__Host-opensig_rs')), false, 'HttpOnly: page script cannot read it');
    assert.equal(requests.some((request) => request.url.includes('opensig_rs')), false, 'the cookie never appears in a URL');
  } finally {
    await close();
  }
});

test('[AG-02] document review: the exact bytes are checked against the digest before the built-in viewer shows them, the download is those bytes, and the schematic outlines every page with the field boxes', async () => {
  const fields = [
    { key: 'sig_r', recipient_ordinal: 1, page: 1, type: 'signature', rect: { x: 0.1, y: 0.7, width: 0.3, height: 0.1 } },
    { key: 'date_r', recipient_ordinal: 1, page: 4, type: 'date', rect: { x: 0.6, y: 0.82, width: 0.2, height: 0.06 } },
  ];
  const sent = await world.sentEnvelope({ document: 'rotated-pages.pdf', fields });
  const { page, requests, close } = await openPage(browser);
  try {
    const state = await signIn(page, world, sent);
    assert.equal(state.document.digest, sent.entry.sha256);
    assert.equal(await page.locator('#document-digest').textContent(), sent.entry.sha256);
    assert.match(await page.locator('#document-check').textContent(), /^Checked: these are the exact document bytes/);

    const reads = requests.filter((request) => request.url === `${world.origin}${DOCUMENT_PATH}`);
    assert.ok(reads.length >= 1, 'the shell read the document bytes');
    const frame = page.locator('iframe#document-frame');
    assert.equal(await frame.getAttribute('src'), DOCUMENT_PATH, 'the built-in viewer shows the checked document');
    assert.ok(((await frame.getAttribute('title')) ?? '').length > 0, 'the viewer frame has a title');
    assert.equal(await frame.getAttribute('tabindex'), '-1', 'the embedded viewer is not a tab stop (no focus trap)');

    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: 'Download the document (PDF)' }).click()]);
    const downloaded = readFileSync(await download.path());
    assert.equal(sha256(downloaded), sent.entry.sha256, 'the download is the exact frozen bytes');
    assert.equal(await page.locator('#document-open').getAttribute('href'), DOCUMENT_PATH);

    const outlines = page.locator('figure.schematic svg.page-outline');
    assert.equal(await outlines.count(), sent.entry.pages.length, 'one outline per page');
    for (const [index, geometry] of sent.entry.pages.entries()) {
      const outline = outlines.nth(index);
      assert.equal(await outline.getAttribute('viewBox'), `0 0 ${num(geometry.width)} ${num(geometry.height)}`, `page ${geometry.number} has its displayed size`);
      assert.match(await outline.locator('title').textContent(), new RegExp(`^Page ${geometry.number} of ${sent.entry.pages.length}`));
      const boxes = outline.locator('rect.field');
      const mine = fields.filter((field) => field.page === geometry.number);
      assert.equal(await boxes.count(), mine.length, `page ${geometry.number} shows its fields`);
      for (const [boxIndex, field] of mine.entries()) {
        const box = boxes.nth(boxIndex);
        assert.equal(await box.getAttribute('data-field'), field.key);
        assert.deepEqual(
          [await box.getAttribute('x'), await box.getAttribute('y'), await box.getAttribute('width'), await box.getAttribute('height')],
          [num(field.rect.x * geometry.width), num(field.rect.y * geometry.height), num(field.rect.width * geometry.width), num(field.rect.height * geometry.height)],
          `field ${field.key} is placed on the displayed page`,
        );
        assert.equal(await box.getAttribute('class'), `field field-${field.type}`);
      }
    }
    const listed = await page.locator('ul.field-list li').allTextContents();
    const describe = (field) => (field.type === 'signature' ? `Signature (field ${field.key}) on page ${field.page}` : `Date, set by the server when you approve (field ${field.key}) on page ${field.page}`);
    assert.deepEqual(listed, state.fields.map(describe), 'every field is listed, in the order the session gives');
    assert.deepEqual([...listed].sort(), fields.map(describe).sort(), "exactly this recipient's fields");
  } finally {
    await close();
  }
});

test('[AG-02] bytes that do not match the session digest are never shown in the viewer and never approved', async () => {
  const sent = await world.sentEnvelope();
  const { page, requests, close } = await openPage(browser);
  try {
    // The browser receives other bytes for the document (as a tampering proxy would send).
    const tampered = Buffer.concat([sent.pdf, Buffer.from('\n% tampered\n', 'latin1')]);
    await page.route(`${world.origin}${DOCUMENT_PATH}`, (route) => route.fulfill({ status: 200, contentType: 'application/pdf', body: tampered }));
    await page.goto(sent.url);
    await step(page, 'invitation');
    const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
    await page.getByRole('button', { name: 'Email me a code' }).click();
    assert.equal((await challenge).status(), 202);
    const code = await world.code(sent.recipients[0]);
    await step(page, 'code');
    await page.getByRole('textbox', { name: 'One-time code' }).fill(code);
    await page.getByRole('button', { name: 'Continue' }).click();
    await step(page, 'review');
    await page.locator('#document-check', { hasText: 'The document does not match its digest. Do not approve it.' }).waitFor();
    await page.locator('#alert', { hasText: 'The document does not match the digest recorded for it.' }).waitFor();
    assert.equal(await page.locator('iframe#document-frame').getAttribute('src'), null, 'the viewer is never pointed at unverified bytes');

    await page.getByRole('textbox', { name: 'Type your full name' }).fill('Ada Example');
    await page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).check();
    await page.getByRole('button', { name: 'Approve the document' }).click();
    await page.locator('#alert', { hasText: 'The document has not been verified.' }).waitFor();
    assert.equal(
      requests.some((request) => request.url.endsWith('/v1/recipient-session/approval')),
      false,
      'no approval is sent for unverified bytes',
    );
  } finally {
    await close();
  }
});
