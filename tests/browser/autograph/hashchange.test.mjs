// SPDX-License-Identifier: Apache-2.0
//
// T009 review shell: an invitation link followed in a tab already on /sign (A-010
// SHELL-HASHCHANGE, request #38). Such a follow is a same-document fragment navigation: nothing
// reloads, so the shell must handle the hashchange itself.
//   AG-08  (an extra case beyond the frozen AG-01..AG-06 minimum)
//          (a) a tab on /sign follows /sign#i=<A>: the follow is handled in the same document (a
//              window marker set before it survives, one hashchange is observed, and no
//              main-frame document request is made; dispatch Addendum 3), the invitation step
//              appears, the address bar is scrubbed at once (synchronously, in the shell's own
//              hashchange listener), no
//              navigation-history entry holds the token (CDP Page.getNavigationHistory), focus
//              moves to the new heading, and neither the page nor the server sees any request
//              until the recipient's explicit "Email me a code";
//          (b) a second follow, to <B>, while A's review is shown with A's session cookie in the
//              jar: the same same-document proof, a clean restart to B's own invitation step,
//              nothing of A shown, no request to the server;
//              B's own code then opens B's session and B's document, never A's;
//          (c) stale async: A's explicit challenge request is held at the browser (Playwright
//              routing), B is followed, then A's request is released: B's step is untouched,
//              and B still needs its own explicit action;
//          (d) a non-invitation fragment (the skip link) triggers no restart and no scrub, and
//              focus moves to the main content as before;
//          (d2) a fragment with a duplicate or malformed invitation parameter is scrubbed at once
//              (no history entry holds either value) and changes nothing else: no restart, no
//              request, focus and the current step's guards unchanged (dispatch Addendum 1);
//          (e) neither token appears in a history entry, the address bar, the DOM text or
//              attributes, a live region, a console message or page error, a request URL or
//              header, or the server log; only the explicit challenge and code requests carry
//              it, in their JSON bodies (the contract's ChallengeRequest and SessionCreate).
// Tokens, codes and full addresses are never printed: diagnostics and assertion messages carry
// only ids, masked addresses, digests, booleans and counts (row AG08-ORACLE, requests #70 and #71).
// The sessions are told apart by their envelope and recipient ids, never by comparing their masked
// addresses, which can be equal. Each session's shown mask must equal the product's own maskEmail
// of the address the test created for that recipient (request #71).

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { maskEmail } from '../../../src/api/recipients/index.ts';
import { focused, launchBrowser, openPage, responseTo, sessionCookie, step, tabTo, verified } from './browser.mjs';
import { CHALLENGE_PATH, SESSION_PATH, startWorld } from './world.mjs';

let world;
let browser;

before(async () => {
  world = await startWorld();
  browser = await launchBrowser();
});

after(async () => {
  await browser?.close();
  await world?.close();
});

/** How long a step is waited for after a follow before the state is read anyway. */
const SETTLE_MS = 5_000;
/** How long the page is left alone after a follow before "no request" is read. */
const QUIET_MS = 750;
const pause = (ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms));

/** The state a follow must produce: the invitation step, scrubbed, no history entry with the token, focus on the new heading. */
const FOLLOWED = Object.freeze({ step: 'invitation', addressHasFragment: false, addressHoldsToken: false, historyEntriesHoldingToken: 0, focus: 'h2#step-title[]' });

/** Request lines of the server's own log since line `from`, as `METHOD path operation status`. */
function serverRequests(from) {
  return world.lines
    .slice(from)
    .map((line) => JSON.parse(line))
    .filter((record) => record.event === 'request')
    .map((record) => `${record.method} ${record.path} ${record.operation} ${record.status}`);
}

/**
 * The page's requests since index `from`, split: those to the server (as `METHOD path`) and the
 * rest (browser-internal resources, such as the built-in PDF viewer's own page, as
 * `scheme:path`). Only requests to the server count as "a request"; the rest are reported.
 */
function pageRequests(requests, from) {
  const toServer = [];
  const other = [];
  for (const entry of requests.slice(from)) {
    const url = new URL(entry.url);
    if (url.origin === world.origin) toServer.push(`${entry.method} ${url.pathname}`);
    else other.push(`${url.protocol}${url.pathname}`);
  }
  return { toServer, other };
}

/** Wait, at most `ms`, until the server log since `from` holds `count` request lines of `operation`. */
async function serverOperations(from, operation, count, ms = SETTLE_MS) {
  for (let waited = 0; waited <= ms; waited += 25) {
    if (serverRequests(from).filter((line) => line.split(' ')[2] === operation).length >= count) return true;
    await pause(25);
  }
  return false;
}

/** Every navigation-history entry's URL (CDP Page.getNavigationHistory). */
async function historyUrls(page) {
  const cdp = await page.context().newCDPSession(page);
  try {
    const { entries } = await cdp.send('Page.getNavigationHistory');
    return entries.map((entry) => entry.url);
  } finally {
    await cdp.detach();
  }
}

/**
 * Register a hashchange listener AFTER the shell's own (main.ts registers its listener when the
 * page loads), so it runs after the shell's: it records whether an invitation fragment was still
 * in the address when it ran. A synchronous scrub leaves none.
 */
async function watchScrub(page) {
  await page.evaluate(() => {
    window.__ag08Scrub = [];
    window.addEventListener('hashchange', () => {
      const hash = window.location.hash;
      window.__ag08Scrub.push({ invitationFragmentLeft: /^#(?:.*&)?i=/.test(hash), hash: hash === '' ? 'none' : /^#(?:.*&)?i=/.test(hash) ? 'invitation' : hash });
    });
  });
  return () => page.evaluate(() => (Array.isArray(window.__ag08Scrub) ? [...window.__ag08Scrub] : null));
}

/**
 * Same-document proof for a follow (dispatch Addendum 3), read after the follow has settled:
 * the marker set on window before it is still there, `hashchanges` more hashchange events were
 * seen by the listener watchScrub() registered (a fresh document would have neither), and the
 * main frame made no document (navigation) request since `navigationsFrom`.
 */
async function sameDocumentProof(page, scrubs, navigations, navigationsFrom, hashchangesBefore) {
  const recorded = await scrubs();
  return {
    marker: await page.evaluate(() => window.__ag08Marker ?? null),
    hashchanges: (recorded ?? []).length - hashchangesBefore,
    documentRequests: navigations.slice(navigationsFrom),
  };
}

/** After a follow: the step (waited for), the address, the history entries holding `token`, and focus. */
async function afterFollow(page, token) {
  await page
    .locator('#app[data-step="invitation"]')
    .waitFor({ timeout: SETTLE_MS })
    .catch(() => undefined);
  const urls = await historyUrls(page);
  return {
    step: await page.locator('#app').getAttribute('data-step'),
    addressHasFragment: new URL(page.url()).hash !== '',
    addressHoldsToken: page.url().includes(token),
    historyEntriesHoldingToken: urls.filter((url) => url.includes(token)).length,
    focus: await focused(page),
  };
}

/** What the shell shows now: step, heading, live regions, and whether any review or code control is present. */
function shown(page) {
  return page.evaluate(() => ({
    step: document.getElementById('app')?.getAttribute('data-step') ?? null,
    heading: document.getElementById('step-title')?.textContent ?? null,
    status: document.getElementById('status')?.textContent ?? null,
    alert: document.getElementById('alert')?.textContent ?? null,
    review: document.querySelector('#document-digest, #document-frame, #consent, #approve') !== null,
    code: document.getElementById('code') !== null,
  }));
}

/** Tag the current step section, so a later check can tell whether the shell re-rendered it. */
function markSection(page) {
  return page.evaluate(() => {
    window.__ag08Section = document.querySelector('#app > section');
  });
}

function sameSection(page) {
  return page.evaluate(() => document.querySelector('#app > section') === window.__ag08Section);
}

/** Ask for a code, enter it, and reach the verified review step. Returns the session state. */
async function codeToReview(page, recipient) {
  const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
  await page.getByRole('button', { name: 'Email me a code' }).click();
  assert.equal((await challenge).status(), 202, 'requestChallenge answers 202');
  await step(page, 'code');
  await page.getByRole('textbox', { name: 'One-time code' }).fill(await world.code(recipient));
  const created = responseTo(page, world.origin, SESSION_PATH, 'POST');
  await page.getByRole('button', { name: 'Continue' }).click();
  const response = await created;
  assert.equal(response.status(), 201, 'the code opens a session');
  const state = await response.json();
  await step(page, 'review');
  await verified(page);
  return state;
}

test('[AG-08] a tab on /sign follows an invitation link: the invitation step, the address scrubbed at once, no history entry holding the token, no request until the explicit action; a second link restarts cleanly to its own steps; the token leaks nowhere', async (t) => {
  // The test keeps the addresses it creates, to check each session's shown mask (request #71).
  const addressA = world.address('hash-a');
  const a = await world.sentEnvelope({ document: 'agreement-multipage.pdf', recipients: [addressA] });
  const addressB = world.address('hash-b');
  const b = await world.sentEnvelope({ document: 'single-page.pdf', recipients: [addressB] });
  assert.notEqual(a.entry.sha256, b.entry.sha256, 'A and B carry different documents');
  const { page, context, requests, close } = await openPage(browser);
  const consoleText = [];
  page.on('console', (message) => consoleText.push(message.text()));
  page.on('pageerror', (error) => consoleText.push(String(error?.message ?? error)));
  // Every main-frame document (navigation) request, as its path.
  const navigations = [];
  // Every request not to the server, with its frame and resource type (browser-internal resources, such as the PDF viewer's own).
  const foreign = [];
  page.on('request', (request) => {
    if (request.isNavigationRequest() && request.frame() === page.mainFrame()) navigations.push(`${request.method()} ${new URL(request.url()).pathname}`);
    const url = new URL(request.url());
    if (url.origin !== world.origin) foreign.push(`${url.protocol}${url.pathname} (${request.frame() === page.mainFrame() ? 'main frame' : 'child frame'}, ${request.resourceType()})`);
  });
  try {
    await page.goto(`${world.origin}/sign`);
    await step(page, 'no-invitation');
    const scrubs = await watchScrub(page);

    // (a) Follow A in this tab.
    let mark = world.lines.length;
    let pageMark = requests.length;
    let navigationsFrom = navigations.length;
    await page.evaluate(() => {
      window.__ag08Marker = 'set before the follow';
    });
    await page.goto(a.url);
    const seenA = await afterFollow(page, a.token);
    const proofA = await sameDocumentProof(page, scrubs, navigations, navigationsFrom, 0);
    t.diagnostic(`same-document proof after following A: ${JSON.stringify(proofA)}`);
    assert.deepEqual(proofA, { marker: 'set before the follow', hashchanges: 1, documentRequests: [] }, 'following A is handled in the same document: the window marker survives, one hashchange is observed, no document request is made');
    t.diagnostic(`after following A from /sign: ${JSON.stringify(seenA)}`);
    assert.deepEqual(seenA, FOLLOWED, 'following A from /sign: the invitation step, the address scrubbed, no history entry holding the token, focus on the new heading');
    assert.deepEqual(await scrubs(), [{ invitationFragmentLeft: false, hash: 'none' }], "the shell scrubbed the fragment synchronously in its own hashchange listener (it was gone when the next listener ran)");
    await pause(QUIET_MS);
    const afterA = pageRequests(requests, pageMark);
    if (afterA.other.length > 0) t.diagnostic(`browser-internal requests after following A: ${JSON.stringify(afterA.other)}`);
    assert.deepEqual(afterA.toServer, [], 'the page sent no request to the server after following A');
    assert.deepEqual(serverRequests(mark), [], 'the server saw no request between the follow and the explicit action');

    // A's explicit action, A's code, A's session and review (A's document).
    const reviewMark = world.lines.length;
    const stateA = await codeToReview(page, a.recipients[0]);
    // A's session names A's envelope and A's recipient, by id, and shows the mask of A's own address
    // (row AG08-ORACLE; request #71).
    const idsA = {
      envelopeId: stateA.envelope_id,
      expectedEnvelopeId: a.envelope.id,
      recipientId: stateA.recipient.id,
      expectedRecipientId: a.envelope.recipients[0].id,
      ordinal: stateA.recipient.ordinal,
      masked: stateA.recipient.email_masked,
      expectedMasked: maskEmail(addressA),
      documentDigest: stateA.document.digest,
      expectedDocumentDigest: a.entry.sha256,
    };
    t.diagnostic(`A's session: ${JSON.stringify(idsA)}`);
    assert.equal(stateA.envelope_id, a.envelope.id, `A's session names A's envelope: ${JSON.stringify(idsA)}`);
    assert.equal(stateA.recipient.id, a.envelope.recipients[0].id, `A's session is A's recipient: ${JSON.stringify(idsA)}`);
    assert.equal(stateA.recipient.email_masked, maskEmail(addressA), `A's session shows the mask of A's own address: ${JSON.stringify(idsA)}`);
    assert.equal(await page.locator('#document-digest').textContent(), a.entry.sha256, "A's review shows A's document");
    // The viewer loads the document once the bytes are checked; let that request finish first.
    assert.equal(await serverOperations(reviewMark, 'readRecipientDocument', 2), true, "A's document was read twice (checked bytes, then the viewer)");

    // (b) Follow B while A's review is shown and A's session cookie is in the jar.
    assert.equal((await sessionCookie(context, world.origin))?.hasValue, true, "A's session cookie is in the jar (unfiltered read)");
    mark = world.lines.length;
    pageMark = requests.length;
    await markSection(page);
    navigationsFrom = navigations.length;
    await page.goto(b.url);
    const seenB = await afterFollow(page, b.token);
    const proofB = await sameDocumentProof(page, scrubs, navigations, navigationsFrom, 1);
    t.diagnostic(`same-document proof after following B: ${JSON.stringify(proofB)}`);
    assert.deepEqual(proofB, { marker: 'set before the follow', hashchanges: 1, documentRequests: [] }, "following B on A's review is handled in the same document: the window marker survives, one more hashchange is observed, no document request is made");
    t.diagnostic(`after following B on A's review: ${JSON.stringify(seenB)}`);
    assert.deepEqual(seenB, FOLLOWED, "following B on A's review: B's invitation step, the address scrubbed, no history entry holding the token, focus on the new heading");
    assert.equal(await sameSection(page), false, 'the shell restarted (a new step section)');
    assert.deepEqual(await shown(page), { step: 'invitation', heading: 'Confirm your mailbox', status: '', alert: '', review: false, code: false }, "nothing of A's flow is shown after following B");
    await pause(QUIET_MS);
    const afterB = pageRequests(requests, pageMark);
    t.diagnostic(`requests not to the server, whole test so far: ${JSON.stringify(foreign)}`);
    assert.deepEqual(afterB.toServer, [], 'the page sent no request to the server after following B: the old session is not read');
    assert.deepEqual(serverRequests(mark), [], 'the server saw no request between the follow and the explicit action');
    assert.deepEqual(await scrubs(), [{ invitationFragmentLeft: false, hash: 'none' }, { invitationFragmentLeft: false, hash: 'none' }], 'both follows were scrubbed synchronously');

    // B's own explicit action and code: B's session shows B's document, never A's.
    const stateB = await codeToReview(page, b.recipients[0]);
    // B's session names B's envelope and B's recipient, by id, and not A's recipient (row AG08-ORACLE),
    // and shows the mask of B's own address (request #71). The masked addresses of two random identities
    // can be equal, so A's and B's are reported, never compared with each other.
    const idsB = {
      envelopeId: stateB.envelope_id,
      expectedEnvelopeId: b.envelope.id,
      recipientId: stateB.recipient.id,
      expectedRecipientId: b.envelope.recipients[0].id,
      recipientIdOfA: stateA.recipient.id,
      ordinal: stateB.recipient.ordinal,
      masked: stateB.recipient.email_masked,
      expectedMasked: maskEmail(addressB),
      maskedOfA: stateA.recipient.email_masked,
      documentDigest: stateB.document.digest,
      expectedDocumentDigest: b.entry.sha256,
      envelopeIsB: stateB.envelope_id === b.envelope.id,
      sameRecipientId: stateB.recipient.id === stateA.recipient.id,
      sameMask: stateB.recipient.email_masked === stateA.recipient.email_masked,
    };
    t.diagnostic(`B's session: ${JSON.stringify(idsB)}`);
    assert.equal(stateB.envelope_id, b.envelope.id, `B's session names B's envelope: ${JSON.stringify(idsB)}`);
    assert.equal(stateB.recipient.id, b.envelope.recipients[0].id, `B's session is B's recipient: ${JSON.stringify(idsB)}`);
    assert.notEqual(stateB.recipient.id, stateA.recipient.id, `B's session is not A's recipient: ${JSON.stringify(idsB)}`);
    assert.equal(stateB.recipient.email_masked, maskEmail(addressB), `B's session shows the mask of B's own address: ${JSON.stringify(idsB)}`);
    assert.equal(stateB.document.digest, b.entry.sha256, "B's session binds B's document");
    assert.equal(await page.locator('#document-digest').textContent(), b.entry.sha256, "B's review shows B's document, not A's");

    // (e) Neither token leaks anywhere.
    const urls = await historyUrls(page);
    for (const [label, token] of [
      ['A', a.token],
      ['B', b.token],
    ]) {
      assert.equal(urls.some((url) => url.includes(token)), false, `${label}: no navigation-history entry holds the token`);
      assert.equal(page.url().includes(token), false, `${label}: the address bar does not hold the token`);
      const dom = await page.evaluate((secret) => {
        const live = [...document.querySelectorAll('[aria-live], [role="status"], [role="alert"]')].map((node) => node.textContent ?? '').join('\n');
        const attributes = [...document.querySelectorAll('*')].some((element) => [...element.attributes].some((attribute) => attribute.value.includes(secret)));
        return { text: document.documentElement.outerHTML.includes(secret), liveRegion: live.includes(secret), attributes };
      }, token);
      assert.deepEqual(dom, { text: false, liveRegion: false, attributes: false }, `${label}: the token is in no DOM text, attribute or live region`);
      assert.equal(consoleText.some((text) => text.includes(token)), false, `${label}: no console message or page error holds the token`);
      const carrying = requests.filter((entry) => entry.url.includes(token) || entry.body.includes(token) || Object.values(entry.headers).some((value) => value.includes(token)));
      assert.equal(carrying.some((entry) => entry.url.includes(token) || Object.values(entry.headers).some((value) => value.includes(token))), false, `${label}: no request URL or header holds the token`);
      assert.deepEqual(
        carrying.map((entry) => `${entry.method} ${new URL(entry.url).pathname}`),
        [`POST ${CHALLENGE_PATH}`, `POST ${SESSION_PATH}`],
        `${label}: only the explicit challenge and code requests carry the token, in their bodies`,
      );
      assert.equal(world.lines.some((line) => line.includes(token)), false, `${label}: the server log never holds the token`);
    }
  } finally {
    await close();
  }
});

test("[AG-08] stale async: A's explicit challenge request is held, B is followed, then A's request is released: B's step is untouched and B still needs its own explicit action", async (t) => {
  const a = await world.sentEnvelope({ recipients: [world.address('stale-a')] });
  const b = await world.sentEnvelope({ recipients: [world.address('stale-b')] });
  const { page, close } = await openPage(browser);
  let held = null;
  let markHeld;
  const heldRequest = new Promise((resolveHeld) => {
    markHeld = resolveHeld;
  });
  let release;
  const released = new Promise((resolveRelease) => {
    release = resolveRelease;
  });
  let continued = 'not released';
  try {
    // Hold the first challenge request (A's) at the browser until released; later ones pass.
    await page.route(`${world.origin}${CHALLENGE_PATH}`, async (route) => {
      if (held !== null) return route.continue();
      held = route;
      markHeld(route.request());
      await released;
      try {
        await route.continue();
        continued = 'route.continue() resolved';
      } catch {
        continued = 'route.continue() threw';
      }
    });
    await page.goto(`${world.origin}/sign`);
    await step(page, 'no-invitation');
    await page.goto(a.url);
    await step(page, 'invitation');
    await page.getByRole('button', { name: 'Email me a code' }).click();
    const request = await heldRequest;
    const outcome = new Promise((resolveOutcome) => {
      page.on('requestfinished', (finished) => finished === request && resolveOutcome('finished'));
      page.on('requestfailed', (failed) => failed === request && resolveOutcome('failed'));
    });
    assert.equal(await page.locator('#status').textContent(), 'Asking for a code...', "A's challenge request is in flight");

    // Follow B while A's request is held: a restart to B's invitation step.
    await markSection(page);
    const mark = world.lines.length;
    await page.goto(b.url);
    const seenB = await afterFollow(page, b.token);
    assert.deepEqual(seenB, FOLLOWED, "following B while A's request is held: B's invitation step, scrubbed, focus on the new heading");
    assert.equal(await sameSection(page), false, 'the shell restarted (a new step section)');
    assert.deepEqual(await shown(page), { step: 'invitation', heading: 'Confirm your mailbox', status: '', alert: '', review: false, code: false }, "B's step starts clean: A's in-flight status is cleared");

    // Release A's request; whatever comes back must not touch B's step.
    release();
    const settled = await Promise.race([outcome, pause(SETTLE_MS).then(() => 'unsettled')]);
    await pause(QUIET_MS);
    await world.composition.ceremony.drain();
    const challengesAtServer = serverRequests(mark).filter((line) => line.startsWith(`POST ${CHALLENGE_PATH}`)).length;
    t.diagnostic(`A's held request after release: browser ${settled}; ${continued}; challenge requests at the server since B's follow: ${challengesAtServer}`);
    assert.deepEqual(await shown(page), { step: 'invitation', heading: 'Confirm your mailbox', status: '', alert: '', review: false, code: false }, "B's step is untouched by A's late response");
    assert.equal(world.takeMails('recipient_challenge', b.recipients[0]).length, 0, 'B has no code yet: B still needs its own explicit action');
    assert.equal(challengesAtServer <= 1, true, "at most A's own challenge reached the server");

    // B's own explicit action works.
    await page.unroute(`${world.origin}${CHALLENGE_PATH}`);
    const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
    await page.getByRole('button', { name: 'Email me a code' }).click();
    assert.equal((await challenge).status(), 202, "B's explicit request for a code answers 202");
    await step(page, 'code');
    assert.match(await world.code(b.recipients[0]), /^[0-9A-Z]{10}$/, "B's code is mailed to B");
  } finally {
    release?.();
    await close();
  }
});

test('[AG-08] a duplicate or malformed invitation fragment is scrubbed at once and changes nothing else: no restart, no request, focus and the current step unchanged; neither value leaks', async (t) => {
  const a = await world.sentEnvelope({ recipients: [world.address('dup-a')] });
  const b = await world.sentEnvelope({ recipients: [world.address('dup-b')] });
  const malformed = b.token.slice(0, 20);
  const { page, requests, close } = await openPage(browser);
  const consoleText = [];
  page.on('console', (message) => consoleText.push(message.text()));
  page.on('pageerror', (error) => consoleText.push(String(error?.message ?? error)));
  try {
    await page.goto(`${world.origin}/sign`);
    await step(page, 'no-invitation');
    await page.goto(a.url);
    await step(page, 'invitation');
    const scrubs = await watchScrub(page);
    for (const [label, fragment, values] of [
      ['duplicate i', `#i=${a.token}&i=${b.token}`, [a.token, b.token]],
      ['malformed i', `#i=${malformed}`, [malformed]],
    ]) {
      await markSection(page);
      const focusBefore = await focused(page);
      const mark = world.lines.length;
      const pageMark = requests.length;
      await page.goto(`${world.origin}/sign${fragment}`);
      await pause(QUIET_MS);
      const urls = await historyUrls(page);
      const sent = pageRequests(requests, pageMark);
      const seen = {
        addressHasFragment: new URL(page.url()).hash !== '',
        historyEntriesHoldingAValue: urls.filter((url) => values.some((value) => url.includes(value))).length,
        step: await page.locator('#app').getAttribute('data-step'),
        sameSection: await sameSection(page),
        focusUnchanged: (await focused(page)) === focusBefore,
        pageRequestsToServer: sent.toServer,
        serverRequests: serverRequests(mark),
      };
      t.diagnostic(`${label}: ${JSON.stringify(seen)}`);
      assert.deepEqual(
        seen,
        { addressHasFragment: false, historyEntriesHoldingAValue: 0, step: 'invitation', sameSection: true, focusUnchanged: true, pageRequestsToServer: [], serverRequests: [] },
        `${label}: scrubbed at once, no history entry holds either value, no restart, focus unchanged, no request`,
      );
    }
    assert.deepEqual(
      await scrubs(),
      [
        { invitationFragmentLeft: false, hash: 'none' },
        { invitationFragmentLeft: false, hash: 'none' },
      ],
      "both were scrubbed synchronously in the shell's own hashchange listener",
    );
    for (const [label, value] of [
      ['B (duplicate)', b.token],
      ['the malformed value', malformed],
    ]) {
      const dom = await page.evaluate((secret) => {
        const live = [...document.querySelectorAll('[aria-live], [role="status"], [role="alert"]')].map((node) => node.textContent ?? '').join('\n');
        const attributes = [...document.querySelectorAll('*')].some((element) => [...element.attributes].some((attribute) => attribute.value.includes(secret)));
        return { text: document.documentElement.outerHTML.includes(secret), liveRegion: live.includes(secret), attributes };
      }, value);
      assert.deepEqual(dom, { text: false, liveRegion: false, attributes: false }, `${label}: in no DOM text, attribute or live region`);
      assert.equal(consoleText.some((text) => text.includes(value)), false, `${label}: in no console message or page error`);
      assert.equal(world.lines.some((line) => line.includes(value)), false, `${label}: never in the server log`);
    }

    // The current step and its guards are as they were: A's own explicit action works, and only A gets a code.
    const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
    await page.getByRole('button', { name: 'Email me a code' }).click();
    assert.equal((await challenge).status(), 202, "A's explicit request for a code answers 202");
    await step(page, 'code');
    assert.match(await world.code(a.recipients[0]), /^[0-9A-Z]{10}$/, "A's code is mailed to A");
    await world.composition.ceremony.drain();
    assert.deepEqual(world.takeMails('recipient_challenge', b.recipients[0]), [], 'B gets nothing');
  } finally {
    await close();
  }
});

test('[AG-08] a non-invitation fragment (the skip link) triggers no restart and no scrub, and focus moves to the main content as before', async () => {
  const a = await world.sentEnvelope({ recipients: [world.address('skip')] });
  const { page, close } = await openPage(browser);
  try {
    await page.goto(a.url);
    await step(page, 'invitation');
    await markSection(page);
    const mark = world.lines.length;
    await tabTo(page, '#skip-link');
    await page.keyboard.press('Enter');
    await page
      .waitForFunction(() => document.activeElement?.id === 'main', null, { timeout: SETTLE_MS })
      .catch(() => undefined);
    await pause(QUIET_MS);
    const seen = {
      hash: new URL(page.url()).hash,
      step: await page.locator('#app').getAttribute('data-step'),
      sameSection: await sameSection(page),
      focus: await focused(page),
    };
    assert.deepEqual(seen, { hash: '#main', step: 'invitation', sameSection: true, focus: 'main#main[]' }, 'the skip link: its fragment stays in the address, no restart, focus on the main content');
    assert.deepEqual(serverRequests(mark), [], 'and no request');
  } finally {
    await close();
  }
});

