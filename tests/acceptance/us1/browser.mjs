// SPDX-License-Identifier: Apache-2.0
//
// The locked browser and the recipient's side of the US1 acceptance flows (T011). T011's own
// helpers: nothing is imported from tests/browser/autograph/; the rules proven at the T009 gate
// are restated here.
//
// Locked browser. The tests launch exactly the Chromium the runner's chromium capability probes
// (scripts/verify.mjs probeChromium), resolved by the same rule: the chromium revision in
// playwright-core's browsers.json (1228 for the pinned Playwright 1.61.1), under
// PLAYWRIGHT_BROWSERS_PATH ('0' meaning the package's .local-browsers; unset, the default
// cache), the first chrome-linux*/chrome there that is executable. That path is passed as
// executablePath, so no other revision in any cache can be picked, with no launch arguments of
// the tests' own (no bypass flag of any kind), and browser.version() must be 149.0.7827.55.
// The evidence records the revision, the version and the executable relative to the browsers
// directory, never a host path.
//
// Session cookie. The jar is read UNFILTERED, context.cookies() with no URL: Playwright 1.61.1's
// client-side URL filter (filterCookies, isLocalHostname) hides Secure cookies for an http: URL
// unless the host is localhost, so a URL-filtered read cannot see the cookie on
// http://127.0.0.1 even when the browser holds it. The cookie is selected by exact host
// (127.0.0.1, host-only), name and path, and holding it proves nothing alone: proveCookieSent()
// shows the server accepting it on a follow-up request, in the server's own request log.
//
// Touch. Every touch of a mobile flow goes through ONE CDP session (Input.dispatchTouchEvent),
// taps and strokes alike, every touch ended, for consistency (dispatch-T011-prep Addendum A4).
// The single path is not what makes a tap after a drawing click: the finger rest before each
// lift is (FINGER_REST_MS below; the T009 recheck's R15 and R16).
//
// Every page gets a request log and counters of trusted pointer, mouse and touch input,
// installed before any page script.

import assert from 'node:assert/strict';
import { accessSync, constants, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, resolve } from 'node:path';

import { chromium } from 'playwright';

import { COOKIE, CORRELATION_HEADER, PATHS, REPO, sha256 } from './harness.mjs';

export const TIMEOUT_MS = 30_000;
/** The locked build (T027: playwright 1.61.1, Chromium revision 1228). */
export const LOCKED_REVISION = '1228';
export const LOCKED_VERSION = '149.0.7827.55';

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/** The Chromium the capability probe names: { revision, version, executablePath, relative, source }. */
export function lockedChromium() {
  const packageDir = ['playwright-core', 'playwright'].map((name) => join(REPO, 'node_modules', name)).find((dir) => isFile(join(dir, 'browsers.json')));
  assert.ok(packageDir !== undefined, 'the pinned Playwright (playwright-core) is installed');
  const pinned = (JSON.parse(readFileSync(join(packageDir, 'browsers.json'), 'utf8')).browsers ?? []).find((browser) => browser.name === 'chromium');
  assert.ok(pinned?.revision && pinned?.browserVersion, 'browsers.json pins a chromium revision and version');
  const configured = process.env.PLAYWRIGHT_BROWSERS_PATH;
  const base = configured === '0' ? join(packageDir, '.local-browsers') : configured ? resolve(configured) : join(homedir(), '.cache', 'ms-playwright');
  const dir = join(base, `chromium-${pinned.revision}`);
  let layouts = [];
  try {
    layouts = readdirSync(dir).filter((entry) => entry.startsWith('chrome-linux'));
  } catch {
    assert.fail(`chromium revision ${pinned.revision} is not installed under the browsers directory`);
  }
  for (const layout of layouts) {
    const executablePath = join(dir, layout, 'chrome');
    try {
      accessSync(executablePath, constants.X_OK);
      return {
        revision: pinned.revision,
        version: pinned.browserVersion,
        executablePath,
        relative: relative(base, executablePath),
        source: configured ? 'PLAYWRIGHT_BROWSERS_PATH' : 'default-cache',
      };
    } catch {
      // The next layout, as the probe does.
    }
  }
  return assert.fail(`chromium revision ${pinned.revision} has no executable in the browsers directory`);
}

/** Launch the locked Chromium by executablePath, headless, with no launch arguments; asserts the build. */
export async function launchLocked() {
  const locked = lockedChromium();
  assert.equal(locked.revision, LOCKED_REVISION, 'browsers.json locks Chromium revision 1228');
  assert.equal(locked.version, LOCKED_VERSION, 'browsers.json names version 149.0.7827.55');
  const browser = await chromium.launch({ executablePath: locked.executablePath, headless: true });
  try {
    assert.equal(browser.version(), LOCKED_VERSION, 'the launched browser is the locked build, Chromium 149.0.7827.55 (revision 1228)');
  } catch (error) {
    await browser.close();
    throw error;
  }
  return { browser, locked };
}

function installCounters() {
  const counts = { pointerdown: 0, mousedown: 0, touchstart: 0, pointerTypes: [] };
  Object.defineProperty(window, '__us1InputCounts', { value: counts });
  for (const type of ['pointerdown', 'mousedown', 'touchstart']) {
    window.addEventListener(
      type,
      (event) => {
        if (!event.isTrusted) return;
        counts[type] += 1;
        if (type === 'pointerdown' && !counts.pointerTypes.includes(event.pointerType)) counts.pointerTypes.push(event.pointerType);
      },
      { capture: true },
    );
  }
}

/** A new context and page with a request log; options go to browser.newContext(). */
export async function openPage(browser, options = {}) {
  const context = await browser.newContext({ acceptDownloads: true, ...options });
  await context.addInitScript(installCounters);
  const page = await context.newPage();
  page.setDefaultTimeout(TIMEOUT_MS);
  const requests = [];
  page.on('request', (req) => requests.push({ method: req.method(), url: req.url(), body: req.postData() ?? '' }));
  return { context, page, requests, close: () => context.close() };
}

export function inputCounts(page) {
  return page.evaluate(() => {
    const counts = window.__us1InputCounts;
    return { pointerdown: counts.pointerdown, mousedown: counts.mousedown, touchstart: counts.touchstart, pointerTypes: [...counts.pointerTypes] };
  });
}

/** Wait for the shell to show step `name` (the data-step of #app; src/autograph/flow.ts:115). */
export async function step(page, name) {
  await page.locator(`#app[data-step="${name}"]`).waitFor();
}

/** Wait until the review step has checked the document bytes against their digest (flow.ts:378). */
export async function verified(page) {
  await page.locator('#document-check', { hasText: 'Checked:' }).waitFor();
}

export function responseTo(page, origin, path, method) {
  return page.waitForResponse((response) => response.url() === `${origin}${path}` && response.request().method() === method);
}

export function focused(page) {
  return page.evaluate(() => {
    const element = document.activeElement;
    if (element === null || element === document.body) return 'body';
    return `${element.tagName.toLowerCase()}#${element.id || ''}`;
  });
}

export async function tabTo(page, selector, { key = 'Tab', max = 80 } = {}) {
  for (let press = 0; press < max; press += 1) {
    if (await page.evaluate((wanted) => document.activeElement?.matches(wanted) === true, selector)) return;
    await page.keyboard.press(key);
  }
  assert.fail(`focus did not reach ${selector} within ${max} presses of ${key}`);
}

/**
 * Open the invitation link and authenticate mailbox control: Email me a code, then the code.
 * With `keyboard`, only keys are used. (The mobile case drives the same steps by touch itself,
 * mobile.test.mjs.) Returns the RecipientSessionState of the 201.
 */
export async function openSession(page, world, invitation, to, { keyboard = false } = {}) {
  await page.goto(invitation.url);
  await step(page, 'invitation');
  const challenge = responseTo(page, world.origin, PATHS.challenge, 'POST');
  const requestCode = page.getByRole('button', { name: 'Email me a code' });
  if (keyboard) {
    await tabTo(page, '#request-code');
    await page.keyboard.press('Enter');
  } else await requestCode.click();
  assert.equal((await challenge).status(), 202, 'requestChallenge answers 202');
  await step(page, 'code');
  const code = await world.code(to);
  const created = responseTo(page, world.origin, PATHS.session, 'POST');
  if (keyboard) {
    await tabTo(page, '#code');
    await page.keyboard.type(code);
    await page.keyboard.press('Enter');
  } else {
    await page.getByRole('textbox', { name: 'One-time code' }).fill(code);
    await page.getByRole('button', { name: 'Continue' }).click();
  }
  const response = await created;
  assert.equal(response.status(), 201, 'createRecipientSession answers 201');
  const state = await response.json();
  await step(page, 'review');
  await verified(page);
  return state;
}

/** The session cookie as the jar holds it for `origin`'s host: unfiltered, exact host, name and path. */
async function jarCookie(context, origin) {
  const host = new URL(origin).hostname;
  const matches = (await context.cookies()).filter((cookie) => cookie.name === COOKIE && cookie.domain === host && cookie.path === '/');
  assert.ok(matches.length <= 1, 'at most one session cookie for the host');
  return matches[0] ?? null;
}

/**
 * The real session cookie as the browser holds it (row LOOPBACK-COOKIE): every production
 * attribute, over plain http://127.0.0.1, with no bypass flag. Returns its attributes, never
 * its value.
 */
export async function assertRealCookie(context, world) {
  const cookie = await jarCookie(context, world.origin);
  assert.ok(cookie !== null, `the browser holds the ${COOKIE} cookie for 127.0.0.1 (unfiltered jar; exact host, name and path)`);
  const { value, ...attributes } = cookie;
  assert.deepEqual(
    { ...attributes, hasValue: typeof value === 'string' && value.length > 0 },
    { name: COOKIE, domain: '127.0.0.1', path: '/', expires: -1, httpOnly: true, secure: true, sameSite: 'Strict', hasValue: true },
    'the browser holds the real cookie with every production attribute: host-only, Path=/, Secure, HttpOnly, SameSite=Strict, a session cookie',
  );
  return attributes;
}

/** `Cookie: __Host-opensig_rs=...` from the jar, for a request a test sends itself. Kept in memory only. */
export async function cookieHeader(context, world) {
  const cookie = await jarCookie(context, world.origin);
  assert.ok(cookie !== null, 'the browser holds the session cookie');
  return `${COOKIE}=${cookie.value}`;
}

/**
 * The browser sends the cookie and the server accepts it: from the page, readRecipientSession
 * with the page's own credentials answers 200, and the same request without credentials 401,
 * each found by its correlation id in the server's request log. HttpOnly holds: page script
 * cannot read the cookie.
 */
export async function proveCookieSent(page, world) {
  const probe = await page.evaluate(
    async ({ path, header, name }) => {
      const withCookie = await fetch(path, { credentials: 'same-origin', cache: 'no-store' });
      const without = await fetch(path, { credentials: 'omit', cache: 'no-store' });
      return {
        withCookie: { status: withCookie.status, correlation: withCookie.headers.get(header) },
        without: { status: without.status, correlation: without.headers.get(header) },
        scriptSees: document.cookie.includes(name),
      };
    },
    { path: PATHS.session, header: CORRELATION_HEADER, name: COOKIE },
  );
  assert.equal(probe.scriptSees, false, 'HttpOnly: page script cannot read the session cookie');
  const accepted = await world.loggedRequest(probe.withCookie.correlation);
  assert.deepEqual(
    accepted && { method: accepted.method, path: accepted.path, operation: accepted.operation, status: accepted.status },
    { method: 'GET', path: PATHS.session, operation: 'readRecipientSession', status: 200 },
    'the server accepted the cookie the browser sent (readRecipientSession 200, in its request log)',
  );
  const refused = await world.loggedRequest(probe.without.correlation);
  assert.deepEqual(
    refused && { method: refused.method, path: refused.path, operation: refused.operation, status: refused.status },
    { method: 'GET', path: PATHS.session, operation: 'readRecipientSession', status: 401 },
    'and refused the same request sent without it (401, in its request log)',
  );
}

/**
 * approveAsHuman sent from `page` with the page's own credentials (whatever the context holds)
 * and the page's Origin; returns { status, code, correlation }.
 */
export function approveFromPage(page, body, csrfToken = null) {
  return page.evaluate(
    async ({ path, header, payload, csrf }) => {
      const headers = { 'content-type': 'application/json' };
      if (csrf !== null) headers['x-csrf-token'] = csrf;
      const response = await fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers, body: JSON.stringify(payload) });
      let code = null;
      try {
        code = (await response.json()).code ?? null;
      } catch {
        code = null;
      }
      return { status: response.status, code, correlation: response.headers.get(header) };
    },
    { path: PATHS.approval, header: CORRELATION_HEADER, payload: body, csrf: csrfToken },
  );
}

/** An Approval body built from a session state, as the review shell would send it, with a typed signature. */
export function approvalFromState(state, signatureKey, name) {
  return {
    expected_version: state.envelope_version,
    document_digest: state.document.digest,
    manifest_digest: state.manifest_digest,
    prior_approval_digest: state.prior_approval_digest,
    consent_version: state.consent.version,
    consent_text_digest: state.consent.text_digest,
    consent: true,
    field_values: state.fields.map((field) => (field.key === signatureKey ? { key: field.key, type: 'signature', mode: 'typed', text: name } : { key: field.key, type: field.type })),
  };
}

/** Approve from the review step with a typed name (pointer or keyboard); returns { body, receipt }. */
export async function approveTyped(page, world, requests, key, name, { keyboard = false } = {}) {
  const answer = responseTo(page, world.origin, PATHS.approval, 'POST');
  if (keyboard) {
    await tabTo(page, `#typed-${key}`);
    await page.keyboard.type(name);
    await tabTo(page, '#consent');
    await page.keyboard.press('Space');
    await tabTo(page, '#approve');
    await page.keyboard.press('Enter');
  } else {
    await page.locator(`#typed-${key}`).fill(name);
    await page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).check();
    await page.getByRole('button', { name: 'Approve the document' }).click();
  }
  const response = await answer;
  assert.equal(response.status(), 200, 'approveAsHuman answers 200');
  const sent = requests.filter((entry) => entry.url === `${world.origin}${PATHS.approval}`);
  return { body: JSON.parse(sent[sent.length - 1].body), receipt: await response.json() };
}

/**
 * The receipt's exact wording for a fully approved envelope, pinned (request #37): T009's
 * FULLY_APPROVED, src/autograph/flow.ts:48-49, shown in #approval-outcome (flow.ts:437). Its
 * explanatory negation ("not completed yet ... completed only after the organization seal ...")
 * is what "distinct from completed" means. A change to the wording fails here and is reviewed.
 */
export const FULLY_APPROVED_RECEIPT =
  'Fully approved: every required approval is recorded. The document is not completed yet: it is completed only after the organization seal is applied and verified.';

/**
 * Wording that claims the envelope is completed or sealed (request #37: no completion or seal
 * claim). The word "sealed" is forbidden outright; an affirmative "is completed" is forbidden
 * unless it is the pinned negation's "completed only after".
 */
const COMPLETION_CLAIMS = Object.freeze([/\b(?:is|was|has been|have been|now)\s+(?:now\s+)?completed\b(?!\s+only after)/i, /^\s*completed\b/im, /\bsealed\b/i]);

/** The receipt of a fully approved envelope (flow.ts:432-447): the pinned wording, and no completion or seal claim on the page. */
export async function assertFullyApprovedNotCompleted(page) {
  await step(page, 'approved');
  assert.equal(await page.locator('#step-title').textContent(), 'Approval recorded', 'the receipt step (flow.ts:435)');
  assert.equal(await page.locator('#approval-outcome').textContent(), FULLY_APPROVED_RECEIPT, "the receipt's exact wording (flow.ts:48-49)");
  const shown = await page.locator('body').innerText();
  for (const claim of COMPLETION_CLAIMS) assert.doesNotMatch(shown, claim, `the page claims no completion or seal (${claim})`);
}

/**
 * Watch the review step's viewer iframe load the document (request #37 (a)). From before the
 * session opens, one CDP session intercepts, at the response stage, the browser's own Document
 * request for the document path (Fetch.enable; the shell's own fetch() of the same path is a
 * Fetch request and is not matched). The response is read in flight (status, headers, body)
 * and continued unchanged, so the iframe receives exactly what the server sent. result(ms)
 * resolves with what was seen, or with { missing: true } if no such request came within `ms`.
 * Whether the viewer draws the PDF is not observable headless and is recorded as not observed.
 */
export async function watchFrameDocument(page) {
  const cdp = await page.context().newCDPSession(page);
  const { frameTree } = await cdp.send('Page.getFrameTree');
  const mainFrameId = frameTree.frame.id;
  let settle;
  const seen = new Promise((resolveSeen) => {
    settle = resolveSeen;
  });
  cdp.on('Fetch.requestPaused', async (event) => {
    try {
      const body = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
      const bytes = Buffer.from(body.body, body.base64Encoded ? 'base64' : 'utf8');
      const headers = Object.fromEntries((event.responseHeaders ?? []).map(({ name, value }) => [name.toLowerCase(), value]));
      settle({
        path: new URL(event.request.url).pathname,
        method: event.request.method,
        resourceType: event.resourceType,
        subframe: event.frameId !== mainFrameId,
        status: event.responseStatusCode,
        headers,
        sha256: sha256(bytes),
        bytes: bytes.length,
      });
    } catch (error) {
      settle({ error: `${error?.message ?? error}` });
    } finally {
      await cdp.send('Fetch.continueRequest', { requestId: event.requestId }).catch(() => undefined);
    }
  });
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: `*${PATHS.document}`, resourceType: 'Document', requestStage: 'Response' }] });
  return {
    result(ms) {
      return Promise.race([seen, new Promise((resolveLate) => setTimeout(() => resolveLate({ missing: true }), ms))]);
    },
    async stop() {
      await cdp.send('Fetch.disable').catch(() => undefined);
      await cdp.detach().catch(() => undefined);
    },
  };
}

/** No sideways scrolling, stated precisely (SC004-02). Returns the measurements. */
export async function assertNoHorizontalOverflow(page, label) {
  const measured = await page.evaluate(() => {
    const root = document.documentElement;
    const client = root.clientWidth;
    let widest = 0;
    let culprit = '';
    for (const element of document.querySelectorAll('body *')) {
      if (element.closest('.skip-link') !== null) continue;
      if (element.getClientRects().length === 0) continue;
      const right = element.getBoundingClientRect().right + window.scrollX;
      if (right > widest) {
        widest = right;
        culprit = `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ''}`;
      }
    }
    window.scrollTo(client * 4, window.scrollY);
    const scrolledX = window.scrollX;
    window.scrollTo(0, window.scrollY);
    return { client, documentWidth: root.scrollWidth, bodyWidth: document.body.scrollWidth, widest, culprit, scrolledX };
  });
  assert.ok(measured.documentWidth <= measured.client && measured.bodyWidth <= measured.client, `${label}: the page is no wider than the viewport (${measured.documentWidth} of ${measured.client})`);
  assert.ok(measured.widest <= measured.client + 0.5, `${label}: no rendered element ends past the viewport's right edge (${measured.culprit} at ${measured.widest} of ${measured.client})`);
  assert.equal(measured.scrolledX, 0, `${label}: a sideways scroll does not move the page`);
  return measured;
}

/**
 * How long a finger rests on the surface before it lifts at the end of a stroke. At the T009
 * gate, without this rest the tap after a drawing failed: in run04 the consent box was never
 * checked, and run05 counted 0 trusted clicks on Approve. The recheck separated the changes
 * (R15: one CDP path without the rest failed; R16: a Playwright tap after CDP strokes, with the
 * rest, passed), so the rest is the cure. Why an instant lift drops the next tap's click is
 * unproven; the reviewer's hypothesis, not established, is that Chromium reads it as a fling
 * and suppresses the next tap's click (row FLICK-TAP, a recorded limit T011 does not test).
 */
const FINGER_REST_MS = 120;
const pause = (ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms));

/**
 * Real touch input on `page` through ONE CDP session (Input.dispatchTouchEvent): tap() controls
 * and draw() strokes on a pad, every touch ended, then detach(). A mobile flow uses this one
 * path for every touch, from its first tap to its last, for consistency; each stroke's finger
 * rests before it lifts (FINGER_REST_MS), which is what lets the taps after it click.
 */
export async function touchInput(page) {
  const cdp = await page.context().newCDPSession(page);
  const send = (type, touchPoints) => cdp.send('Input.dispatchTouchEvent', { type, touchPoints });
  return {
    /** Tap the centre of `locator`, after checking that the element is what is hit there. */
    async tap(locator) {
      await locator.waitFor({ state: 'visible' });
      await locator.scrollIntoViewIfNeeded();
      const box = await locator.boundingBox();
      assert.ok(box, 'the tap target is rendered');
      const point = { x: box.x + box.width / 2, y: box.y + box.height / 2 };
      const hit = await locator.evaluate((element, at) => {
        const found = document.elementFromPoint(at.x, at.y);
        return found !== null && (found === element || element.contains(found));
      }, point);
      assert.equal(hit, true, 'the tap point hits the target');
      await send('touchStart', [point]);
      await send('touchEnd', []);
    },
    /** Draw `strokes` (arrays of [x, y] fractions of the surface) on field `key` (pad.ts:54-59). */
    async draw(key, strokes) {
      const surface = page.locator(`svg.pad-surface[data-field="${key}"]`);
      await surface.scrollIntoViewIfNeeded();
      const box = await surface.boundingBox();
      assert.ok(box, 'the drawing surface is rendered');
      for (const stroke of strokes) {
        const points = stroke.map(([x, y]) => ({ x: box.x + x * box.width, y: box.y + y * box.height }));
        await send('touchStart', [points[0]]);
        for (const point of points.slice(1)) await send('touchMove', [point]);
        await pause(FINGER_REST_MS);
        await send('touchEnd', []);
      }
    },
    detach: () => cdp.detach(),
  };
}

/** Draw `strokes` (fractions of the surface) with the mouse. */
export async function drawWithMouse(page, key, strokes) {
  const surface = page.locator(`svg.pad-surface[data-field="${key}"]`);
  await surface.scrollIntoViewIfNeeded();
  const box = await surface.boundingBox();
  assert.ok(box, 'the drawing surface is rendered');
  for (const [first, ...rest] of strokes) {
    await page.mouse.move(box.x + first[0] * box.width, box.y + first[1] * box.height);
    await page.mouse.down();
    for (const [x, y] of rest) await page.mouse.move(box.x + x * box.width, box.y + y * box.height, { steps: 4 });
    await page.mouse.up();
  }
}

/**
 * Merge this file's results into the run's evidence (.verify-out/us1/evidence.json): the labels
 * the frozen runner checks (browser_engine, browser_version, tree_digest from
 * OPENSIG_VERIFY_TREE_DIGEST) and the cases that reached their last assertion. Outside the
 * runner (no OPENSIG_VERIFY_OUT) nothing is written. No host path, no cookie or token value.
 */
export function recordEvidence({ browser, locked, caseId, cookie = null, prefetch = null, frame = null }) {
  const out = process.env.OPENSIG_VERIFY_OUT;
  if (!out) return;
  const treeDigest = process.env.OPENSIG_VERIFY_TREE_DIGEST;
  assert.match(treeDigest ?? '', /^[0-9a-f]{64}$/, 'the runner passed the tree digest');
  const path = join(out, 'evidence.json');
  let previous = {};
  try {
    previous = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    previous = {};
  }
  const version = browser.version();
  if (previous.browser_version !== undefined) assert.equal(previous.browser_version, version, 'one browser version for the whole run');
  const evidence = {
    mode: 'us1',
    browser_engine: 'chromium',
    browser_version: version,
    tree_digest: treeDigest,
    chromium_revision: locked.revision,
    browser_executable: locked.relative,
    browsers_directory: locked.source,
    playwright_version: JSON.parse(readFileSync(join(REPO, 'node_modules', 'playwright', 'package.json'), 'utf8')).version,
    headless: true,
    launch_arguments: [],
    session_cookie:
      cookie === null
        ? (previous.session_cookie ?? null)
        : { name: cookie.name, host_only_domain: cookie.domain, path: cookie.path, secure: cookie.secure, http_only: cookie.httpOnly, same_site: cookie.sameSite, transport: 'loopback-http', accepted_by_server: true },
    browser_prefetch: prefetch === null ? (previous.browser_prefetch ?? null) : prefetch,
    viewer_iframe_document: frame === null ? (previous.viewer_iframe_document ?? null) : frame,
    viewer_pdf_drawing: 'not observed (headless)',
    cases_completed: [...new Set([...(previous.cases_completed ?? []), caseId])].sort(),
  };
  mkdirSync(out, { recursive: true });
  writeFileSync(path, `${JSON.stringify(evidence, null, 2)}\n`);
}
