// SPDX-License-Identifier: Apache-2.0
//
// Browser helpers of the review-shell tests (T009): Playwright (the pinned devDependency,
// 1.61.1) driving the locked Chromium build (request #35). The executable is resolved exactly
// as the runner's chromium capability probe resolves it (scripts/verify.mjs probeChromium):
// the chromium revision in playwright-core's browsers.json, under PLAYWRIGHT_BROWSERS_PATH
// ('0' meaning the package's .local-browsers; unset, ~/.cache/ms-playwright), the first
// chrome-linux*/chrome there that is executable. It is the full build, which has the built-in
// PDF viewer (the headless shell has none), launched by executablePath with no launch
// arguments of the tests' own, and its version is asserted. Each test file launches one
// browser and closes it in its after hook; each test closes its context in finally.
// Every page gets a request log and input-event counters installed before any page script,
// so a test can prove what was sent and that a path used the keyboard or touch only.

import assert from 'node:assert/strict';
import { accessSync, constants, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, resolve } from 'node:path';

import { chromium } from 'playwright';

import { CHALLENGE_PATH, ROOT, SESSION_PATH } from './world.mjs';

export const TIMEOUT_MS = 30_000;
/** The locked build (T027: playwright 1.61.1, Chromium revision 1228). */
export const LOCKED_REVISION = '1228';
export const LOCKED_VERSION = '149.0.7827.55';
export const SESSION_COOKIE = '__Host-opensig_rs';

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * The locked Chromium, resolved as the runner's chromium probe resolves it. Returns the
 * revision and browser version browsers.json names, the executable path, and that path
 * relative to the browsers directory (the only form a report or diagnostic shows).
 */
export function lockedChromium() {
  const packageDir = ['playwright-core', 'playwright'].map((name) => join(ROOT, 'node_modules', name)).find((dir) => isFile(join(dir, 'browsers.json')));
  assert.ok(packageDir !== undefined, 'the pinned Playwright (playwright-core) is installed');
  const entry = (JSON.parse(readFileSync(join(packageDir, 'browsers.json'), 'utf8')).browsers ?? []).find((browser) => browser.name === 'chromium');
  assert.ok(entry?.revision, 'playwright-core browsers.json names a chromium revision');
  const configured = process.env.PLAYWRIGHT_BROWSERS_PATH;
  const base = configured === '0' ? join(packageDir, '.local-browsers') : configured ? resolve(configured) : join(homedir(), '.cache', 'ms-playwright');
  const dir = join(base, `chromium-${entry.revision}`);
  let layouts = [];
  try {
    layouts = readdirSync(dir).filter((name) => name.startsWith('chrome-linux'));
  } catch {
    assert.fail(`chromium revision ${entry.revision} is not installed under the browsers directory`);
  }
  for (const layout of layouts) {
    const executablePath = join(dir, layout, 'chrome');
    try {
      accessSync(executablePath, constants.X_OK);
      return { revision: entry.revision, browserVersion: entry.browserVersion, executablePath, relativePath: relative(base, executablePath) };
    } catch {
      // Try the next layout, as the probe does.
    }
  }
  return assert.fail(`chromium revision ${entry.revision} has no executable`);
}

/** Launch the locked Chromium by executablePath, with no launch arguments, and check its version. */
export async function launchBrowser() {
  const locked = lockedChromium();
  assert.equal(locked.revision, LOCKED_REVISION, 'browsers.json locks Chromium revision 1228');
  assert.equal(locked.browserVersion, LOCKED_VERSION, 'browsers.json names version 149.0.7827.55');
  const browser = await chromium.launch({ executablePath: locked.executablePath, headless: true });
  try {
    assert.equal(browser.version(), LOCKED_VERSION, 'the launched browser is the locked build');
  } catch (error) {
    await browser.close();
    throw error;
  }
  return browser;
}

/**
 * The session cookie as the browser holds it for `origin`'s host, without its value (only
 * whether it has one): name, domain, path, expires, httpOnly, secure and sameSite. Null when
 * there is none. The jar is read UNFILTERED (context.cookies() with no URL): Playwright's own
 * URL filter drops Secure cookies for an http: URL unless the host is localhost, so a URL-
 * filtered read cannot see a Secure cookie on http://127.0.0.1 even when the browser holds it
 * (dispatch Addendum 5). The cookie is selected by exact host (host-only: no leading dot, so
 * no Domain attribute), name and path. Holding it proves nothing on its own: the cookie test
 * proves that the browser sends it, at the server.
 */
export async function sessionCookie(context, origin) {
  const host = new URL(origin).hostname;
  const matches = (await context.cookies()).filter((candidate) => candidate.name === SESSION_COOKIE && candidate.domain === host && candidate.path === '/');
  assert.ok(matches.length <= 1, 'at most one session cookie for the host');
  const cookie = matches[0];
  if (cookie === undefined) return null;
  const { value, ...attributes } = cookie;
  return { ...attributes, hasValue: typeof value === 'string' && value.length > 0 };
}

/** Counters of pointer, mouse and touch input, read with inputCounts(page). */
function installCounters() {
  const counts = { pointerdown: 0, pointermove: 0, mousedown: 0, touchstart: 0, pointerTypes: [] };
  Object.defineProperty(window, '__opensigInputCounts', { value: counts });
  for (const type of ['pointerdown', 'pointermove', 'mousedown', 'touchstart']) {
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
  page.on('request', (request) => {
    requests.push({ method: request.method(), url: request.url(), headers: request.headers(), body: request.postData() ?? '' });
  });
  return { context, page, requests, close: () => context.close() };
}

export function inputCounts(page) {
  return page.evaluate(() => {
    const counts = window.__opensigInputCounts;
    return { pointerdown: counts.pointerdown, pointermove: counts.pointermove, mousedown: counts.mousedown, touchstart: counts.touchstart, pointerTypes: [...counts.pointerTypes] };
  });
}

/**
 * Count the trusted click events whose target is inside `selector` from now on; the returned
 * function reads the count. A diagnostic for touch taps, whose clicks the browser synthesizes.
 */
export async function countClicks(page, selector) {
  const key = `__opensigClicks${Math.random().toString(36).slice(2)}`;
  await page.evaluate(
    ({ name, wanted }) => {
      window[name] = 0;
      document.addEventListener(
        'click',
        (event) => {
          if (event.isTrusted && event.target instanceof Element && event.target.closest(wanted) !== null) window[name] += 1;
        },
        { capture: true },
      );
    },
    { name: key, wanted: selector },
  );
  return () => page.evaluate((name) => window[name], key);
}

/** Wait for the shell to show `name` (the data-step of #app). */
export async function step(page, name) {
  await page.locator(`#app[data-step="${name}"]`).waitFor();
}

/** Wait until the review step has checked the document bytes against their digest. */
export async function verified(page) {
  await page.locator('#document-check', { hasText: 'Checked:' }).waitFor();
}

export function responseTo(page, origin, path, method) {
  return page.waitForResponse((response) => response.url() === `${origin}${path}` && response.request().method() === method);
}

/** Open the invitation, ask for a code, enter it: the review step, verified. Returns the session state. */
export async function signIn(page, world, sent, { typedCode } = {}) {
  await page.goto(sent.url);
  await step(page, 'invitation');
  const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
  await page.getByRole('button', { name: 'Email me a code' }).click();
  assert.equal((await challenge).status(), 202);
  const code = await world.code(sent.recipients[0]);
  await step(page, 'code');
  await page.getByRole('textbox', { name: 'One-time code' }).fill(typedCode === undefined ? code : typedCode(code));
  const created = responseTo(page, world.origin, SESSION_PATH, 'POST');
  await page.getByRole('button', { name: 'Continue' }).click();
  const response = await created;
  assert.equal(response.status(), 201, 'the code opens a session');
  const state = await response.json();
  await step(page, 'review');
  await verified(page);
  return state;
}

/**
 * The same as signIn, by keyboard alone: Tab to "Email me a code" and press Enter, Tab to the
 * code field, type the code and press Enter. Returns the session state.
 */
export async function signInByKeyboard(page, world, sent) {
  await page.goto(sent.url);
  await step(page, 'invitation');
  assert.equal(await focused(page), 'body', 'loading the page moves no focus');
  await tabTo(page, '#request-code');
  const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
  await page.keyboard.press('Enter');
  assert.equal((await challenge).status(), 202);
  await step(page, 'code');
  assert.equal(await focused(page), 'h2#step-title[]', 'the code step heading takes focus');
  const code = await world.code(sent.recipients[0]);
  await tabTo(page, '#code');
  await page.keyboard.type(code);
  const created = responseTo(page, world.origin, SESSION_PATH, 'POST');
  await page.keyboard.press('Enter');
  const response = await created;
  assert.equal(response.status(), 201, 'the code opens a session');
  const state = await response.json();
  await step(page, 'review');
  await verified(page);
  assert.equal(await focused(page), 'h2#step-title[]', 'the review heading takes focus');
  return state;
}

/** A short description of the focused element, comparable across calls. */
export function focused(page) {
  return page.evaluate(() => {
    const element = document.activeElement;
    if (element === null || element === document.body) return 'body';
    return `${element.tagName.toLowerCase()}#${element.id || ''}[${element.getAttribute('name') ?? ''}]`;
  });
}

/**
 * The sequential focus order the page should have: every element that is focusable, rendered
 * and not inside a closed details or hidden subtree, with tabindex 0 or none, in DOM order; a
 * radio group contributes its checked radio (or its first). Each entry says whether it comes
 * after the focused element. None of the shell's elements uses a positive tabindex, which the
 * function asserts.
 */
export function expectedTabOrder(page) {
  return page.evaluate(() => {
    const selector = 'a[href], button, input, select, textarea, summary, iframe, [tabindex]';
    const active = document.activeElement;
    const describe = (element) => `${element.tagName.toLowerCase()}#${element.id || ''}[${element.getAttribute('name') ?? ''}]`;
    const seenGroups = new Set();
    const order = [];
    for (const element of document.querySelectorAll(selector)) {
      const tabindex = element.getAttribute('tabindex');
      if (tabindex !== null && Number(tabindex) > 0) throw new Error(`positive tabindex on ${element.tagName}`);
      if (tabindex !== null && Number(tabindex) < 0) continue;
      if (element.matches(':disabled')) continue;
      if (element.closest('[hidden], [inert]') !== null) continue;
      const details = element.closest('details');
      if (details !== null && !details.open && element.tagName !== 'SUMMARY') continue;
      if (element.tagName === 'SUMMARY' && element.parentElement?.tagName !== 'DETAILS') continue;
      const box = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      if (style.visibility === 'hidden' || style.display === 'none' || (box.width === 0 && box.height === 0)) continue;
      let target = element;
      if (element instanceof HTMLInputElement && element.type === 'radio') {
        if (seenGroups.has(element.name)) continue;
        seenGroups.add(element.name);
        const group = [...document.querySelectorAll(`input[type="radio"][name="${CSS.escape(element.name)}"]`)];
        target = group.find((radio) => radio.checked) ?? group[0];
      }
      const after = active !== null && active !== document.body && (active.compareDocumentPosition(target) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
      order.push({ name: describe(target), after });
    }
    return order;
  });
}

/** Press `key` until the focused element matches `selector`; at most `max` presses. */
export async function tabTo(page, selector, { key = 'Tab', max = 80 } = {}) {
  for (let press = 0; press < max; press += 1) {
    if (await page.evaluate((wanted) => document.activeElement?.matches(wanted) === true, selector)) return;
    await page.keyboard.press(key);
  }
  assert.fail(`focus did not reach ${selector} within ${max} presses of ${key}`);
}

/** The strokes the preview of field `key` shows, parsed from its path data. */
export function previewStrokes(page, key) {
  return page.evaluate((field) => {
    const paths = document.querySelectorAll(`g.preview[data-field="${field}"] path.stroke`);
    return [...paths].map((path) => [...(path.getAttribute('d') ?? '').matchAll(/[ML](\d+) (\d+)/g)].map((match) => [Number(match[1]), Number(match[2])]));
  }, key);
}

/** Draw `strokes` (arrays of [x, y] fractions of the surface) on field `key` with the mouse. */
export async function drawWithMouse(page, key, strokes) {
  const surface = page.locator(`svg.pad-surface[data-field="${key}"]`);
  await surface.scrollIntoViewIfNeeded();
  const box = await surface.boundingBox();
  assert.ok(box, 'the drawing surface is rendered');
  for (const stroke of strokes) {
    const [first, ...rest] = stroke;
    await page.mouse.move(box.x + first[0] * box.width, box.y + first[1] * box.height);
    await page.mouse.down();
    for (const [x, y] of rest) await page.mouse.move(box.x + x * box.width, box.y + y * box.height, { steps: 4 });
    await page.mouse.up();
  }
}

/**
 * How long a finger rests on the surface before it lifts at the end of a stroke. This rest is
 * what makes the next tap's click arrive (dispatch Addendum 8). Without it, the tap after a
 * drawing produced no click in run04 and run05. The recheck separated the two changes, each run
 * once: R15, this one CDP touch path WITHOUT the rest, failed (no trusted click on the consent
 * label); R16, a Playwright locator.tap() after CDP strokes WITH the rest, passed. So the rest
 * is the cure, not the touch path. Why an instant lift drops the next tap's click is unproven.
 * The reviewer's hypothesis, not established: Chromium reads an instant lift after movement as
 * a fling and suppresses the next tap's click.
 */
const FINGER_REST_MS = 120;
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Real touch input on `page` through ONE CDP session (Input.dispatchTouchEvent, the same events
 * page.touchscreen.tap sends): draw() strokes on a pad and tap() controls, every touch ended,
 * then detach(). From a drawing on, every touch of a flow goes through this one path for
 * consistency, not as the cure: the recheck's R16 passed with a Playwright tap after these
 * strokes. What lets the tap after a drawing click is the finger rest before each lift
 * (FINGER_REST_MS above: run04, run05, R15, R16; dispatch Addendum 8).
 */
export async function touchInput(page) {
  const cdp = await page.context().newCDPSession(page);
  const send = (type, touchPoints) => cdp.send('Input.dispatchTouchEvent', { type, touchPoints });
  return {
    /** Draw `strokes` (arrays of [x, y] fractions of the surface) on field `key`. */
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
    detach: () => cdp.detach(),
  };
}

/**
 * Record the trusted touch, pointer and click events the page receives from now on, in order,
 * as `type(pointerType)@target`; the returned function reads the log. Moves are left out.
 */
export async function touchLog(page) {
  const key = `__opensigTouchLog${Math.random().toString(36).slice(2)}`;
  await page.evaluate((name) => {
    const log = [];
    window[name] = log;
    const describe = (target) => {
      if (!(target instanceof Element)) return String(target);
      const id = target.id ? `#${target.id}` : '';
      const forId = target.getAttribute('for');
      return `${target.tagName.toLowerCase()}${id}${forId ? `[for=${forId}]` : ''}`;
    };
    for (const type of ['touchstart', 'touchend', 'touchcancel', 'pointerdown', 'pointerup', 'pointercancel', 'click']) {
      window.addEventListener(
        type,
        (event) => {
          if (event.isTrusted) log.push(`${type}${typeof event.pointerType === 'string' && event.pointerType !== '' ? `(${event.pointerType})` : ''}@${describe(event.target)}`);
        },
        { capture: true },
      );
    }
  }, key);
  return () => page.evaluate((name) => [...window[name]], key);
}

/** True when the page needs no sideways scrolling at its current viewport. */
export function fitsWidth(page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth && document.body.scrollWidth <= window.innerWidth);
}

/** The full accessibility tree of the main frame (CDP Accessibility.getFullAXTree). */
export async function accessibilityTree(page) {
  const cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send('Accessibility.enable');
    const { nodes } = await cdp.send('Accessibility.getFullAXTree');
    return nodes;
  } finally {
    await cdp.detach();
  }
}

/** Every request whose URL is on the server's /v1 API. */
export function apiRequests(requests, origin) {
  return requests.filter((request) => request.url.startsWith(`${origin}/v1/`));
}
