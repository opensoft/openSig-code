// SPDX-License-Identifier: Apache-2.0
//
// T011 SC004-03: consent and organization-seal wording visible, in Chromium against the
// composed server (harness.mjs). The exact texts:
// - the tenant's consent text in force (ConsentText: version, text, text_digest), seeded at
//   test runtime with a line break and a non-ASCII apostrophe, so equality is byte for byte;
// - the assurance statement and the organization-seal notice, the fixed texts of
//   src/domain/consent (ASSURANCE.statement, SEAL_NOTICE; spec.md clarification on consent
//   evidence), which the session state carries as assurance.statement and seal_notice.
// The review shell shows them in #consent-text, #consent-version, #assurance-statement and
// #seal-notice (src/autograph/flow.ts:340-343), before the consent checkbox (flow.ts:313, 344)
// and the Approve button (flow.ts:314). "Visible" means, for each: present exactly once; the
// element's text equals the exact text; rendered (Playwright isVisible); scrolled into view it
// lies inside the viewport with a non-zero box; the element at its centre is itself or a
// descendant (nothing covers it); opaque; and it comes before the Approve button. The approval
// then binds the consent version and digest the browser saw, in the server's own record.
// Row US1-MASK (request #48): the part with the page open runs under browser.mjs whilePagesOpen
// (first error recorded before any close, each close guarded), and after() uses closeAll.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { approveTyped, assertFullyApprovedNotCompleted, closeAll, launchLocked, openPage, openSession, recordEvidence, whilePagesOpen } from './browser.mjs';
import { ASSURANCE, CONSENT_TEXT, CONSENT_VERSION, SEAL_NOTICE, sha256, startWorld } from './harness.mjs';

let world;
let browser;
let locked;

before(async () => {
  world = await startWorld();
  ({ browser, locked } = await launchLocked());
});

after(() => closeAll([() => browser?.close(), () => world?.close()]));

async function assertShown(page, selector, exact, label) {
  const element = page.locator(selector);
  assert.equal(await element.count(), 1, `${label}: present exactly once`);
  assert.equal(await element.textContent(), exact, `${label}: the exact text`);
  assert.equal(await element.isVisible(), true, `${label}: rendered`);
  await element.scrollIntoViewIfNeeded();
  const seen = await element.evaluate((node) => {
    const box = node.getBoundingClientRect();
    const style = getComputedStyle(node);
    const hit = document.elementFromPoint(box.left + box.width / 2, box.top + Math.min(box.height / 2, 8));
    const approve = document.getElementById('approve');
    return {
      inViewport: box.width > 0 && box.height > 0 && box.top >= 0 && box.left >= 0 && box.right <= document.documentElement.clientWidth,
      uncovered: hit !== null && (hit === node || node.contains(hit)),
      opaque: style.visibility === 'visible' && Number(style.opacity) >= 0.99,
      beforeApprove: approve !== null && (node.compareDocumentPosition(approve) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0,
    };
  });
  assert.deepEqual(seen, { inViewport: true, uncovered: true, opaque: true, beforeApprove: true }, `${label}: visible to the reader before Approve`);
}

test('[SC004-03] the exact consent text with its version, the assurance statement and the organization-seal notice are visible before Approve, and the approval binds what was shown', async () => {
  const recipient = world.address('consent');
  const sent = await world.sentEnvelope({ recipients: [recipient] });
  const { page, requests, close } = await openPage(browser);
  await whilePagesOpen({ caseId: 'SC004-03', section: 'recipient', browser, pages: { page }, closers: [close] }, async () => {
    const state = await openSession(page, world, sent.invitation, recipient);
    assert.deepEqual(state.consent, { version: CONSENT_VERSION, text_digest: sha256(Buffer.from(CONSENT_TEXT, 'utf8')), text: CONSENT_TEXT }, 'the session carries the tenant consent text in force');
    assert.equal(state.assurance.statement, ASSURANCE.statement, 'the session carries the exact assurance statement');
    assert.equal(state.seal_notice, SEAL_NOTICE, 'the session carries the exact organization-seal notice');
    await assertShown(page, '#consent-text', CONSENT_TEXT, 'consent text');
    assert.equal(await page.locator('#consent-version').textContent(), `Consent text version ${CONSENT_VERSION}.`, 'the consent version is shown');
    await assertShown(page, '#assurance-statement', ASSURANCE.statement, 'assurance statement');
    await assertShown(page, '#seal-notice', SEAL_NOTICE, 'organization-seal notice');
    assert.equal(await page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).isChecked(), false, 'consent starts unchecked');

    const { body } = await approveTyped(page, world, requests, 'sig_1', 'Ada Consent');
    assert.equal(body.consent_version, CONSENT_VERSION);
    assert.equal(body.consent_text_digest, world.consent.digest);
    await assertFullyApprovedNotCompleted(page);
    assert.match((await page.locator('#approval-outcome').textContent()) ?? '', /organization seal/, 'the receipt names the organization seal');
  });
  const [approval] = world.rows('approvals', sent.envelope.id);
  assert.ok(approval, 'the approval is recorded');
  assert.equal(approval.consent_version, CONSENT_VERSION, "the server's record binds the consent version shown");
  assert.equal(approval.consent_text_digest, world.consent.digest, 'and the digest of the exact text shown');
  recordEvidence({ browser, locked, caseId: 'SC004-03' });
});
