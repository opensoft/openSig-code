// SPDX-License-Identifier: Apache-2.0
//
// The locked browser and the recipient's side of an SC001 flow (T017). T017's own helpers: nothing
// is imported from tests/acceptance/us1/ or tests/browser/autograph/; the rules proven there
// (T009 gate, T011, rows LOOPBACK-COOKIE and US1-MASK) are restated in T017's own code.
//
// Locked browser: exactly the Chromium the runner's chromium probe finds (scripts/verify.mjs
// probeChromium): the revision in playwright-core's browsers.json, under PLAYWRIGHT_BROWSERS_PATH
// ('0' = the package's .local-browsers; unset = the default cache), the first executable
// chrome-linux*/chrome. It is launched by executablePath, headless, with no launch arguments, and
// browser.version() must be 149.0.7827.55. A missing browser fails the test; the runner's probe has
// already turned an absent one into CAPABILITY_ABSENT before any test runs.
//
// The bytes the browser received (the T017 line: the approval's document_digest equals the SHA-256
// of the bytes the browser received). From before the invitation link opens, one CDP session per
// page intercepts, at the response stage, every response to the document path
// (/v1/recipient-session/document), correlated to the exact expected-origin GET and frame through
// Network's request identity. Network Fetch and Fetch-domain XHR name the same checked read in
// the locked browser; a subframe Document identifies the viewer. Every body is read, hashed and
// continued unchanged, with inline/CSP checks on the viewer, so the page receives
// exactly what the server sent. The approval's document_digest is read from the request the
// browser itself sent (its POST body, from the page's request log), and the flow compares it with
// every captured hash, the session state, the stored approval row and the package's manifest.
//
// Navigation samples for SC005-01 (indicative-local), measured on the test's monotonic clock:
// - open-invitation: page.goto(link) until the invitation step shows; no authentication in it;
// - review-reload: with the session already held, page.reload() until the review step shows the
//   checked document; no authentication or mail delay in it (SC-005: measured separately from
//   authentication and email delay).
// Status samples (readEnvelope) are taken in harness.mjs.
//
// Waits and first errors (the row US1-MASK lesson): every wait for the answer to a request a step
// causes starts together with its action (respondedTo), and guardPages records the first error,
// browser.isConnected() and each page's state before anything closes, runs each close in its own
// guard, and rethrows the first error. The record is first-error-<case>.json in the runner's
// per-mode output (request #48 C1): never committed, never evidence of a PASS.

import assert from 'node:assert/strict';
import { accessSync, constants, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

import { chromium } from 'playwright';

import { assertRecordClean, PATHS, REPO, scrub, sha256 } from './harness.mjs';

export const PAGE_TIMEOUT_MS = 30_000;
export const LOCKED = Object.freeze({ revision: '1228', version: '149.0.7827.55' });
const CONSENT_BOX = 'I have read the consent text above and I agree to it.';
const STROKE = Object.freeze([
  [0.08, 0.6],
  [0.28, 0.2],
  [0.48, 0.75],
  [0.68, 0.25],
  [0.9, 0.55],
]);

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function isExecutable(path) {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** The Chromium the runner's probe names: { revision, version, executablePath, relative }. */
export function lockedChromium() {
  const packageDir = ['playwright-core', 'playwright'].map((name) => join(REPO, 'node_modules', name)).find((dir) => isFile(join(dir, 'browsers.json')));
  assert.ok(packageDir !== undefined, 'the pinned Playwright is installed (playwright-core browsers.json)');
  const pinned = (JSON.parse(readFileSync(join(packageDir, 'browsers.json'), 'utf8')).browsers ?? []).find((browser) => browser.name === 'chromium');
  assert.ok(pinned?.revision && pinned?.browserVersion, 'browsers.json pins a chromium revision and version');
  const configured = process.env.PLAYWRIGHT_BROWSERS_PATH;
  const base = configured === '0' ? join(packageDir, '.local-browsers') : configured ? resolve(configured) : join(homedir(), '.cache', 'ms-playwright');
  const dir = join(base, `chromium-${pinned.revision}`);
  let layouts = [];
  try {
    layouts = readdirSync(dir).filter((entry) => entry.startsWith('chrome-linux'));
  } catch {
    layouts = [];
  }
  for (const layout of layouts) {
    const executablePath = join(dir, layout, 'chrome');
    if (isExecutable(executablePath)) return { revision: pinned.revision, version: pinned.browserVersion, executablePath, relative: relative(base, executablePath) };
  }
  return assert.fail(`chromium revision ${pinned.revision} has no executable in the browsers directory; the runner probed it, so this is a failure, never a skip`);
}

/** Launch the locked Chromium, headless, with no launch arguments, and check its build. */
export async function launchLocked() {
  const locked = lockedChromium();
  assert.equal(locked.revision, LOCKED.revision, `browsers.json locks Chromium revision ${LOCKED.revision}, not ${locked.revision}`);
  const browser = await chromium.launch({ executablePath: locked.executablePath, headless: true });
  if (browser.version() !== LOCKED.version) {
    const found = browser.version();
    await browser.close();
    assert.fail(`the launched browser is Chromium ${LOCKED.version} (revision ${LOCKED.revision}), not ${found}`);
  }
  return { browser, locked };
}

/** A new context and page with a request log. */
export async function openContext(browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(PAGE_TIMEOUT_MS);
  const requests = [];
  page.on('request', (req) => requests.push({ method: req.method(), url: req.url(), body: req.postData() ?? '' }));
  return { context, page, requests, close: () => context.close() };
}

/** Wait for the shell's step `name` (#app[data-step]). */
export async function step(page, name) {
  await page.locator(`#app[data-step="${name}"]`).waitFor();
}

/** Wait until the review step has checked the fetched bytes against document.digest. */
export async function documentChecked(page) {
  await page.locator('#document-check', { hasText: 'Checked:' }).waitFor();
}

/**
 * Wait for the PDF loaded by the current review's own iframe. The Checked notice establishes
 * document identity, while the viewer navigation and its load event arrive separately.
 * Replacing the review before the iframe loads can cancel its paused PDF response.
 */
async function documentViewerReady(page, origin) {
  const iframe = await page.$('#document-frame');
  assert.ok(iframe, 'the checked review has a document iframe');
  try {
    assert.equal(await iframe.getAttribute('src'), PATHS.document, 'the document iframe uses the exact viewer endpoint');
    const frame = await iframe.contentFrame();
    assert.ok(frame && frame.parentFrame() === page.mainFrame() && !frame.isDetached(), 'the document iframe is attached to the current review');
    const expectedUrl = new URL(PATHS.document, origin).href;
    assert.ok(frame.url() === 'about:blank' || frame.url() === expectedUrl, 'the document iframe has no unexpected navigation');
    await frame.waitForURL(expectedUrl, { waitUntil: 'load', timeout: PAGE_TIMEOUT_MS });
    const current = await page.evaluate(({ element, path }) =>
      element.isConnected && element === document.getElementById('document-frame') && element.getAttribute('src') === path,
    { element: iframe, path: PATHS.document });
    assert.ok(current && await iframe.contentFrame() === frame && !frame.isDetached() && frame.url() === expectedUrl,
      'the exact loaded document frame still belongs to the current review');
  } finally {
    await iframe.dispose();
  }
}

/**
 * The response to `method` `path` that `action` causes. The wait is created first and the action
 * started at once; both are awaited as one, so the first failure is the one thrown and no wait is
 * ever left without a handler.
 */
export async function respondedTo(page, origin, path, method, action) {
  const waiting = page.waitForResponse((response) => response.url() === `${origin}${path}` && response.request().method() === method);
  const acting = Promise.resolve().then(action);
  const [response] = await Promise.all([waiting, acting]);
  return response;
}

/**
 * One diagnostic record per recipient, separate from the ten-entry flows.json contract.
 * Only booleans, HTTP method/type tokens, byte counts and digests are retained; no URL, header
 * value containing a link, credential, body or host path is written.
 */
function recordCapturedDocuments(caseId, recipient, seen) {
  const out = process.env.OPENSIG_VERIFY_OUT;
  if (!out) return;
  const path = join(out, 'browser-captures.json');
  let records = {};
  try {
    records = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  records[caseId] ??= {};
  records[caseId][String(recipient)] = seen;
  const text = JSON.stringify(records, null, 2) + '\n';
  assertRecordClean(text, 'browser-captures.json');
  mkdirSync(out, { recursive: true });
  writeFileSync(path, text);
}

/**
 * Require the two actual document paths and their security metadata. Network request identity,
 * frame and method establish the role; the Fetch-domain type is retained rather than assumed
 * equal to Network's type. Every body is still checked against the posted approval below.
 */
export function assertDocumentTransport(received, label) {
  for (const seen of received) {
    assert.equal(seen.error ?? null, null, label + ': the intercepted body is readable (' + (seen.bodyError ?? seen.error ?? 'no error') + ')');
    const identity = {
      network_id: seen.networkIdPresent,
      request: seen.networkCorrelated,
      frame: seen.frameCorrelated,
      network_method: seen.networkMethodMatches,
      origin: seen.originMatches,
      path: seen.pathMatches,
      method: seen.method,
    };
    assert.deepEqual(identity, { network_id: true, request: true, frame: true, network_method: true, origin: true, path: true, method: 'GET' }, label + ': each body belongs to the exact expected-origin GET document request, correlated by networkId and frame (' + JSON.stringify(identity) + ')');
    assert.equal(seen.status, 200, label + ': the correlated document response answers 200 (' + seen.status + ')');
    assert.equal(seen.pdf, true, label + ': the correlated document response is application/pdf (' + seen.contentType + ')');
    if (seen.role === 'viewer') {
      const viewer = { network: seen.networkResourceType, paused: seen.resourceType, subframe: seen.subframe, inline: seen.inline, frame_ancestors_self: seen.frameAncestorsSelf, csp_no_inline_or_eval: seen.cspNoInlineOrEval };
      assert.deepEqual(viewer, { network: 'Document', paused: 'Document', subframe: true, inline: true, frame_ancestors_self: true, csp_no_inline_or_eval: true }, label + ': the viewer receives its own subframe Document response with inline and CSP protections (' + JSON.stringify(viewer) + ')');
    } else {
      const checked = { role: seen.role, network: ['Fetch', 'XHR'].includes(seen.networkResourceType), paused: ['Fetch', 'XHR'].includes(seen.resourceType), subframe: seen.subframe };
      assert.deepEqual(checked, { role: 'checked-read', network: true, paused: true, subframe: false }, label + ': the shell checked read is a correlated main-frame Fetch/XHR response (Network ' + seen.networkResourceType + ', Fetch domain ' + seen.resourceType + '; ' + JSON.stringify(checked) + ')');
    }
  }
  const roles = [...new Set(received.map((seen) => seen.role))].sort();
  assert.deepEqual(roles, ['checked-read', 'viewer'], label + ': both the shell checked read and viewer document were captured (' + JSON.stringify(received.map((seen) => [seen.role, seen.networkResourceType, seen.resourceType, seen.subframe, seen.status])) + ')');
}

/**
 * Capture every intended PDF response at the response stage and continue its body unchanged.
 * Network.requestWillBeSent supplies identity, method, type and frame for paused.networkId.
 * The locked browser reports main-frame Network Fetch with Fetch-domain XHR, so neither label
 * alone stands in for identity. Missing correlation, unsupported roles or body errors remain
 * visible and fail assertDocumentTransport. settle() and the consent actions keep their order.
 */
export async function captureDocument(page, { origin, caseId, recipient }) {
  assert.equal(new URL(origin).origin, origin, 'document capture takes a normalized expected origin');
  assert.match(caseId, /^[A-Za-z][A-Za-z0-9_-]{0,40}$/, 'document capture names its flow or separate diagnostic with a simple identifier');
  assert.ok(recipient === 1 || recipient === 2, 'document capture names recipient 1 or 2 (found ' + recipient + ')');
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Page.enable');
  let mainFrame = (await cdp.send('Page.getFrameTree')).frameTree.frame.id;
  const requests = new Map();
  const seen = [];
  const reading = new Set();
  const identityOf = (value) => {
    try {
      const url = new URL(value);
      return { originMatches: url.origin === origin, pathMatches: url.pathname === PATHS.document && url.search === '' };
    } catch {
      return { originMatches: false, pathMatches: false };
    }
  };
  cdp.on('Page.frameNavigated', (event) => {
    if (!event.frame.parentId) mainFrame = event.frame.id;
  });
  cdp.on('Network.requestWillBeSent', (event) => {
    const identity = identityOf(event.request.url);
    if (!identity.pathMatches) return;
    requests.set(event.requestId, { ...identity, method: event.request.method, frameId: event.frameId, resourceType: event.type ?? null });
  });
  cdp.on('Fetch.requestPaused', (event) => {
    const work = (async () => {
      const networkIdPresent = typeof event.networkId === 'string' && event.networkId.length > 0;
      const request = networkIdPresent ? requests.get(event.networkId) : undefined;
      const paused = identityOf(event.request.url);
      const frameCorrelated = request !== undefined && request.frameId === event.frameId;
      const subframe = request === undefined ? null : request.frameId !== mainFrame;
      const networkResourceType = request?.resourceType ?? null;
      const role = frameCorrelated && subframe === false && ['Fetch', 'XHR'].includes(networkResourceType)
        ? 'checked-read'
        : frameCorrelated && subframe === true && networkResourceType === 'Document'
          ? 'viewer'
          : null;
      const header = (name) => {
        const values = (event.responseHeaders ?? []).filter((entry) => entry.name.toLowerCase() === name).map((entry) => entry.value);
        return values.length === 1 ? values[0] : null;
      };
      const contentType = header('content-type');
      const disposition = header('content-disposition');
      const csp = header('content-security-policy');
      const ancestors = (csp ?? '').split(';').map((directive) => directive.trim()).filter((directive) => /^frame-ancestors(?:\s|$)/i.test(directive));
      const media = (contentType ?? '').split(';')[0].trim().toLowerCase();
      const entry = {
        resourceType: event.resourceType,
        networkResourceType,
        role,
        networkIdPresent,
        networkCorrelated: request !== undefined,
        frameCorrelated,
        networkMethodMatches: request !== undefined && request.method === event.request.method,
        originMatches: paused.originMatches && request?.originMatches === true,
        pathMatches: paused.pathMatches && request?.pathMatches === true,
        method: event.request.method,
        subframe,
        status: event.responseStatusCode ?? null,
        pdf: media === 'application/pdf',
        contentType: /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(media) ? media : 'invalid-or-missing',
        inline: /^\s*inline(?:\s*;|$)/i.test(disposition ?? ''),
        frameAncestorsSelf: ancestors.length === 1 && /^frame-ancestors\s+'self'$/i.test(ancestors[0]),
        cspNoInlineOrEval: csp !== null && !/'unsafe-(?:inline|eval)'/i.test(csp),
      };
      try {
        const body = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
        const bytes = Buffer.from(body.body, body.base64Encoded ? 'base64' : 'utf8');
        seen.push({ ...entry, sha256: sha256(bytes), bytes: bytes.length });
      } catch (error) {
        const bodyError = String(error?.message ?? '').endsWith('Invalid InterceptionId.') ? 'invalid-interception-id' : 'body-read-failed';
        seen.push({ ...entry, error: 'body-unavailable', bodyError });
      } finally {
        await cdp.send('Fetch.continueRequest', { requestId: event.requestId }).catch(() => undefined);
      }
    })();
    reading.add(work);
    work.then(() => reading.delete(work));
  });
  await cdp.send('Network.enable');
  await cdp.send('Fetch.enable', { patterns: ['Fetch', 'XHR', 'Document'].map((resourceType) => ({ urlPattern: origin + PATHS.document, resourceType, requestStage: 'Response' })) });
  let stopped;
  return {
    seen,
    settle: () => Promise.all([...reading]),
    stop() {
      stopped ??= (async () => {
        await cdp.send('Fetch.disable').catch(() => undefined);
        await cdp.detach().catch(() => undefined);
        await Promise.all([...reading]);
        recordCapturedDocuments(caseId, recipient, seen);
      })();
      return stopped;
    },
  };
}

async function drawWithMouse(page, key) {
  const surface = page.locator(`svg.pad-surface[data-field="${key}"]`);
  await surface.scrollIntoViewIfNeeded();
  const box = await surface.boundingBox();
  assert.ok(box, `the drawing surface of ${key} is rendered`);
  const [first, ...rest] = STROKE;
  await page.mouse.move(box.x + first[0] * box.width, box.y + first[1] * box.height);
  await page.mouse.down();
  for (const [x, y] of rest) await page.mouse.move(box.x + x * box.width, box.y + y * box.height, { steps: 4 });
  await page.mouse.up();
}

/**
 * One recipient's turn in the browser: open the mailed link, ask for a code, enter it, review
 * (the document checked), reload the review once as a pure review navigation, sign (typed or
 * drawn), consent and approve. Returns { state, receipt, body }: the session state of the 201, the
 * approval receipt, and the approval body exactly as the browser sent it.
 */
export async function approveInBrowser(party, { world, invitation, to, ordinal, signature, flow }) {
  const { page, requests } = party;
  const who = `${flow}, recipient ${ordinal}`;
  const opening = performance.now();
  await page.goto(invitation.url);
  await step(page, 'invitation');
  world.samples.push({ flow, kind: 'open-invitation', ms: performance.now() - opening });

  const challenge = await respondedTo(page, world.origin, PATHS.challenge, 'POST', () => page.getByRole('button', { name: 'Email me a code' }).click());
  assert.equal(challenge.status(), 202, `${who}: requestChallenge answers 202, not ${challenge.status()}`);
  await step(page, 'code');
  const code = await world.code(to);
  const created = await respondedTo(page, world.origin, PATHS.session, 'POST', async () => {
    await page.getByRole('textbox', { name: 'One-time code' }).fill(code);
    await page.getByRole('button', { name: 'Continue' }).click();
  });
  assert.equal(created.status(), 201, `${who}: createRecipientSession answers 201, not ${created.status()}`);
  const state = await created.json();
  assert.equal(state.turn, 'yours', `${who}: it is this recipient's turn (${state.turn})`);
  await step(page, 'review');
  await documentChecked(page);
  await documentViewerReady(page, world.origin);

  const reloading = performance.now();
  await page.reload();
  await step(page, 'review');
  await documentChecked(page);
  world.samples.push({ flow, kind: 'review-reload', ms: performance.now() - reloading });
  await documentViewerReady(page, world.origin);

  const key = `sig_${ordinal}`;
  if (signature === 'drawn') {
    const drawMode = page.getByRole('radio', { name: 'Draw my signature' });
    // Finish scrolling before restoring radio focus for the ordinary pointer action.
    await drawMode.scrollIntoViewIfNeeded();
    const focused = await drawMode.evaluate((radio) => {
      radio.focus({ preventScroll: true });
      return radio.isConnected && radio.ownerDocument.activeElement === radio && radio.matches(':focus');
    });
    assert.ok(focused, who + ': the drawn signature radio has focus before selection');
    await drawMode.check();
    await drawWithMouse(page, key);
  } else {
    await page.locator(`#typed-${key}`).fill(`Synthetic Recipient ${ordinal}`);
  }
  await page.getByRole('checkbox', { name: CONSENT_BOX }).check();
  const approved = await respondedTo(page, world.origin, PATHS.approval, 'POST', () => page.getByRole('button', { name: 'Approve the document' }).click());
  assert.equal(approved.status(), 200, `${who}: approveAsHuman answers 200, not ${approved.status()}`);
  const receipt = await approved.json();
  const posted = requests.filter((entry) => entry.method === 'POST' && entry.url === `${world.origin}${PATHS.approval}`);
  assert.equal(posted.length, 1, `${who}: the browser sent exactly one approval (found ${posted.length})`);
  return { state, receipt, body: JSON.parse(posted[0].body) };
}

/** Browser facts for evidence.json: engine, version, revision and the executable relative to the browsers directory. */
export function browserEvidence(browser, locked) {
  return { browser_engine: 'chromium', browser_version: browser.version(), chromium_revision: locked.revision, browser_executable: locked.relative, headless: true, launch_arguments: [] };
}

function describe(error) {
  return { name: typeof error?.name === 'string' ? error.name : typeof error, message: scrub(error?.message ?? error).slice(0, 2000) };
}

function pageState(page) {
  let path = null;
  let closed = null;
  try {
    const url = new URL(page.url());
    path = url.protocol === 'http:' || url.protocol === 'https:' ? scrub(url.pathname) : `${url.protocol} (not recorded)`;
  } catch {
    path = null;
  }
  try {
    closed = page.isClosed();
  } catch {
    closed = null;
  }
  return { closed, path };
}

async function closeEach(closers) {
  const failed = [];
  for (const close of [...closers]) {
    try {
      await close();
    } catch (error) {
      failed.push(error);
    }
  }
  return failed;
}

function publish(error, record) {
  try {
    const pages = Object.entries(record.pages).map(([label, state]) => `page ${label} ${state.closed ? 'closed' : 'open'} at ${state.path}`);
    const line = `[${record.case} first error, ${record.raised_by === 'cleanup' ? 'raised by cleanup' : 'recorded before cleanup'} in "${record.section}": browser.isConnected()=${record.browser_connected}; ${pages.join('; ')}; cleanup errors: ${record.cleanup_errors.length}]`;
    if (error instanceof Error) error.message = `${error.message}\n${line.replace(/[\r\n]+/g, ' ')}`;
  } catch {
    // The file below still keeps the record.
  }
  try {
    const out = process.env.OPENSIG_VERIFY_OUT;
    if (!out || !/^[A-Za-z0-9._-]+$/.test(record.case)) return;
    const path = join(out, `first-error-${record.case}.json`);
    let records = [];
    try {
      const read = JSON.parse(readFileSync(path, 'utf8'));
      if (Array.isArray(read)) records = read;
    } catch {
      records = [];
    }
    records.push(record);
    mkdirSync(out, { recursive: true });
    writeFileSync(path, `${JSON.stringify(records, null, 2)}\n`);
  } catch {
    // Recording never replaces the error it records.
  }
}

/**
 * The part of a flow where pages are open. `pages` ({ label: page }) and `closers` may be filled
 * while `body` runs; both are read when an error is recorded and when the closes run. The first
 * error (from the body, or else from the first failing close) is recorded at once, with the
 * browser's and pages' state, before any close; every close then runs in its own guard, and the
 * first error is rethrown with one line appended after its unchanged original message.
 */
export async function guardPages({ caseId, section, browser, pages, closers }, body) {
  const capture = (error, raisedBy) => {
    let connected = null;
    try {
      connected = browser.isConnected();
    } catch {
      connected = null;
    }
    const states = {};
    for (const [label, page] of Object.entries(pages)) states[label] = pageState(page);
    return { case: caseId, section: scrub(section), raised_by: raisedBy, recorded_at: new Date().toISOString(), error: describe(error), browser_connected: connected, pages: states, cleanup_errors: [] };
  };
  let outcome;
  try {
    outcome = await body();
  } catch (error) {
    const record = capture(error, 'section');
    record.cleanup_errors.push(...(await closeEach(closers)).map(describe));
    publish(error, record);
    throw error;
  }
  const failed = await closeEach(closers);
  if (failed.length > 0) {
    const [first, ...rest] = failed;
    const record = capture(first, 'cleanup');
    record.cleanup_errors.push(...rest.map(describe));
    publish(first, record);
    throw first;
  }
  return outcome;
}

/** Close what a before() hook opened, each close in its own guard; then throw the failure, if any. */
export async function closeAll(closers) {
  const failed = await closeEach(closers);
  if (failed.length === 1) throw failed[0];
  if (failed.length > 1) throw new AggregateError(failed, `${failed.length} closes failed; the first: ${failed[0]?.message ?? failed[0]}`);
}
