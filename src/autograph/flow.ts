// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// The review shell's flow (T009). Steps, each one section headed by an h2 that takes focus
// when the step changes (never at first load), with spoken status and alert regions:
//
//   load: #i=<token> in the fragment ----> invitation   (no request at all)
//         no token -> readRecipientSession: 200 -> by turn below; else -> no-invitation
//   invitation --[Email me a code]--> requestChallenge (generic 202) --> code
//   code --[Continue]--> createRecipientSession: 201 -> by turn; 401 wrong code; 429 locked
//   by turn: yours -> review; waiting-for-prior -> waiting; done -> done; closed -> closed
//   review --[Approve]--> approveAsHuman: 200 -> approved; 409 -> re-read and review again;
//          403 -> re-read (fresh CSRF token) and retry; 401 -> ended
//   review --[Decline]--> declineAsRecipient: 200 -> declined
//   any session step --[End this session]--> endRecipientSession -> ended
//
// Opening, reloading or prefetching the page sends nothing that changes state: only a code
// request, a code, an approval, a decline or ending the session do, each on an explicit action.
// The invitation token lives in this object only until a session exists; the CSRF token only
// in the session state held here.
//
// Review shows: the document's size and digest; the exact bytes fetched and checked against
// document.digest (and the manifest bytes against manifest_digest) before the browser's own PDF
// viewer is pointed at them; a download link and a new-tab link to the same bytes; the
// page-outline schematic; one control per field (a signature: Type my name, the keyboard path
// and the default, or Draw my signature; a date: labelled as set by the server); the exact
// consent text with its version, checked against its digest, the assurance statement and the
// organization-seal notice; and Approve. "Fully approved" is said distinctly from completed.

import { DOCUMENT_PATH, recipientApi, type RecipientApi } from './api.js';
import { approvalBody, approvalProblems, type SignatureInput } from './approval.js';
import { sha256Hex, textDigest } from './digest.js';
import { el, replace, type Child } from './dom.js';
import { normalizeCode } from './invitation.js';
import { DrawingPad } from './pad.js';
import { fieldDescription, schematic } from './schematic.js';
import { budgetPerValue } from './strokes.js';
import type { ApprovalReceipt, DeclineReason, EnvelopeState, Field, PageGeometry, SessionState } from './types.js';

export type Step = 'no-invitation' | 'invitation' | 'code' | 'review' | 'waiting' | 'done' | 'closed' | 'approved' | 'declined' | 'ended';

export interface ShellPage {
  readonly app: HTMLElement;
  readonly status: HTMLElement;
  readonly alert: HTMLElement;
}

const FULLY_APPROVED =
  'Fully approved: every required approval is recorded. The document is not completed yet: it is completed only after the organization seal is applied and verified.';

const CLOSED: Readonly<Record<EnvelopeState, string>> = {
  sent: 'This invitation is no longer valid. Use the most recent invitation email.',
  'in-progress': 'This invitation is no longer valid. Use the most recent invitation email.',
  finalizing: FULLY_APPROVED,
  completed: 'This document is completed.',
  declined: 'This document was declined. Nothing more can be signed.',
  expired: 'This document expired. Ask the sender for a new invitation.',
  voided: 'The sender withdrew this document.',
};

const DECLINE_REASONS: ReadonlyArray<readonly [DeclineReason, string]> = [
  ['not-my-document', 'This document is not meant for me'],
  ['disagree', 'I do not agree with the document'],
  ['other', 'Another reason'],
];

interface SignatureControl {
  input(): SignatureInput;
}

export class ReviewShell {
  readonly #page: ShellPage;
  readonly #api: RecipientApi;
  #invitation: string | null = null;
  #state: SessionState | null = null;
  #documentDigest: string | null = null;
  #consentOk = false;
  #busy = false;
  #signatures = new Map<string, SignatureControl>();
  #consent: HTMLInputElement | null = null;
  #reasons: ReadonlyArray<readonly [DeclineReason, HTMLInputElement]> = [];

  constructor(page: ShellPage, api: RecipientApi = recipientApi) {
    this.#page = page;
    this.#api = api;
  }

  /** Start with the invitation read from the fragment (or none). */
  async start(invitation: string | null): Promise<void> {
    this.#invitation = invitation;
    this.#state = null;
    this.#clearAlert();
    if (invitation !== null) {
      this.#showInvitation(false);
      return;
    }
    const read = await this.#api.readSession();
    if (read.ok) await this.#afterSession(read.value, false);
    else this.#showNoInvitation(false);
  }

  #announce(text: string): void {
    this.#page.status.textContent = text;
  }

  #fail(text: string): void {
    this.#page.alert.textContent = text;
  }

  #clearAlert(): void {
    this.#page.alert.textContent = '';
  }

  #render(step: Step, title: string, focus: boolean, ...content: Child[]): void {
    this.#page.app.setAttribute('data-step', step);
    const heading = el('h2', { id: 'step-title', tabindex: '-1' }, title);
    replace(this.#page.app, el('section', { class: `step step-${step}`, 'aria-labelledby': 'step-title' }, heading, ...content));
    if (focus) heading.focus();
  }

  #endButton(): HTMLButtonElement {
    const button = el('button', { type: 'button', class: 'secondary', id: 'end-session' }, 'End this session');
    button.addEventListener('click', () => void this.#endSession());
    return button;
  }

  #showNoInvitation(focus: boolean): void {
    this.#render(
      'no-invitation',
      'Open your invitation link',
      focus,
      el('p', {}, 'This page opens from the link in your invitation email. Open that link again.'),
      el('p', {}, 'This page keeps no copy of the link, so reloading or going back cannot reopen it.'),
    );
  }

  #showInvitation(focus: boolean): void {
    const request = el('button', { type: 'button', id: 'request-code' }, 'Email me a code');
    request.addEventListener('click', () => void this.#requestCode());
    this.#render(
      'invitation',
      'Confirm your mailbox',
      focus,
      el('p', {}, 'To open the document, confirm that you control the mailbox this invitation was sent to: we email you a one-time code.'),
      el('p', {}, 'Opening this page and asking for a code change nothing on the document.'),
      request,
    );
  }

  async #requestCode(): Promise<void> {
    const invitation = this.#invitation;
    if (this.#busy) return;
    if (invitation === null) {
      this.#showNoInvitation(true);
      return;
    }
    this.#busy = true;
    this.#clearAlert();
    this.#announce('Asking for a code...');
    const result = await this.#api.requestChallenge(invitation);
    this.#busy = false;
    if (result.ok) {
      this.#showCode(true, 'If your link is valid, we emailed you a code. It works for 10 minutes.');
      return;
    }
    this.#announce('');
    if (result.status === 429) this.#fail('Too many codes were requested. Wait a few minutes, then try again.');
    else if (result.status === 400) this.#fail('This link is not valid. Open the link from your invitation email again.');
    else this.#fail('The code could not be requested. Try again.');
  }

  #showCode(focus: boolean, notice: string): void {
    const input = el('input', {
      id: 'code',
      name: 'code',
      type: 'text',
      inputmode: 'text',
      autocomplete: 'one-time-code',
      autocapitalize: 'characters',
      spellcheck: 'false',
      maxlength: 24,
      'aria-describedby': 'code-hint',
    });
    const form = el(
      'form',
      { id: 'code-form', novalidate: true },
      el('label', { for: 'code' }, 'One-time code'),
      el('p', { id: 'code-hint', class: 'hint' }, 'The 10 letters and digits from the email. Spaces and dashes are ignored.'),
      input,
      el('div', { class: 'actions' }, el('button', { type: 'submit', id: 'submit-code' }, 'Continue')),
    );
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      void this.#submitCode(input);
    });
    const again = el('button', { type: 'button', class: 'secondary', id: 'request-again' }, 'Email me a new code');
    again.addEventListener('click', () => void this.#requestCode());
    this.#render('code', 'Enter your code', focus, el('p', { id: 'code-notice' }, notice), form, again);
    this.#announce(notice);
  }

  async #submitCode(input: HTMLInputElement): Promise<void> {
    if (this.#busy) return;
    const invitation = this.#invitation;
    if (invitation === null) {
      this.#showNoInvitation(true);
      return;
    }
    const code = normalizeCode(input.value);
    if (code === null) {
      this.#fail('Enter the 10 letters and digits from the email.');
      input.focus();
      return;
    }
    this.#busy = true;
    this.#clearAlert();
    this.#announce('Checking the code...');
    const result = await this.#api.createSession(invitation, code);
    this.#busy = false;
    if (result.ok) {
      this.#invitation = null;
      await this.#afterSession(result.value, true);
      return;
    }
    this.#announce('');
    if (result.status === 401) this.#fail('That code did not work. Check it, or ask for a new code.');
    else if (result.status === 429) this.#fail('Too many attempts. Ask for a new code later.');
    else if (result.status === 400) this.#fail('Enter the 10 letters and digits from the email.');
    else this.#fail('The code could not be checked. Try again.');
    input.focus();
  }

  async #afterSession(state: SessionState, focus: boolean): Promise<void> {
    this.#state = state;
    this.#documentDigest = null;
    this.#consentOk = (await textDigest(state.consent.text)) === state.consent.text_digest;
    this.#clearAlert();
    this.#announce('');
    if (state.turn === 'yours') this.#showReview(focus);
    else if (state.turn === 'waiting-for-prior') this.#render('waiting', 'Not your turn yet', focus, el('p', {}, 'Another recipient approves first. We email you when it is your turn.'), this.#endButton());
    else if (state.turn === 'done') this.#render('done', 'You have already approved', focus, el('p', {}, 'Your approval is recorded. Nothing more is needed from you.'), this.#endButton());
    else this.#render('closed', 'This document is closed', focus, el('p', { id: 'closed-reason' }, CLOSED[state.envelope_state]), this.#endButton());
  }

  #pageOf(state: SessionState, field: Field): PageGeometry {
    return state.document.pages.find((page) => page.number === field.page) ?? { number: field.page, width: 612, height: 792, rotate: 0 };
  }

  #signatureControl(field: Field, page: PageGeometry, budget: number): HTMLElement {
    const key = field.key;
    const typedRadio = el('input', { type: 'radio', name: `mode-${key}`, id: `mode-typed-${key}`, value: 'typed', checked: true });
    const drawnRadio = el('input', { type: 'radio', name: `mode-${key}`, id: `mode-drawn-${key}`, value: 'drawn' });
    const typed = el('input', { type: 'text', id: `typed-${key}`, autocomplete: 'name', spellcheck: 'false', maxlength: 160, 'aria-describedby': `typed-hint-${key}` });
    const typedPanel = el(
      'div',
      { class: 'typed-panel', id: `typed-panel-${key}` },
      el('label', { for: `typed-${key}` }, 'Type your full name'),
      el('p', { class: 'hint', id: `typed-hint-${key}` }, 'It appears in the document in a standard font (Helvetica), up to 80 characters.'),
      typed,
    );
    const pad = new DrawingPad({ key, width: field.rect.width * page.width, height: field.rect.height * page.height, budget, announce: (text) => this.#announce(text), onChange: () => undefined });
    const drawPanel = el('div', { class: 'draw-panel', id: `draw-panel-${key}`, hidden: true }, pad.element);
    const sync = (): void => {
      typedPanel.hidden = drawnRadio.checked;
      drawPanel.hidden = !drawnRadio.checked;
    };
    typedRadio.addEventListener('change', sync);
    drawnRadio.addEventListener('change', sync);
    this.#signatures.set(key, {
      input: (): SignatureInput => (drawnRadio.checked ? { mode: 'drawn', strokes: pad.strokes() } : { mode: 'typed', text: typed.value }),
    });
    return el(
      'fieldset',
      { class: 'signature-field', 'data-field': key },
      el('legend', {}, fieldDescription(field)),
      el(
        'fieldset',
        { class: 'modes' },
        el('legend', {}, 'How do you want to sign?'),
        el('span', { class: 'mode' }, typedRadio, el('label', { for: `mode-typed-${key}` }, 'Type my name')),
        el('span', { class: 'mode' }, drawnRadio, el('label', { for: `mode-drawn-${key}` }, 'Draw my signature')),
      ),
      typedPanel,
      drawPanel,
    );
  }

  #showReview(focus: boolean): void {
    const state = this.#state;
    if (state === null) return;
    this.#signatures = new Map();
    const signatureFields = state.fields.filter((field) => field.type === 'signature').length;
    const budget = budgetPerValue(signatureFields);
    const check = el('p', { id: 'document-check', class: 'check', 'aria-live': 'polite' }, 'Checking that these are the exact document bytes...');
    const pageCount = state.document.pages.length;
    // Out of the tab order, so focus can never be trapped in the browser's viewer; the named
    // links right after it open and download the same document (A-010 request #34 B3).
    const frame = el('iframe', {
      id: 'document-frame',
      class: 'document-frame',
      title: `The document under review (PDF, ${pageCount} page${pageCount === 1 ? '' : 's'}), in the browser's PDF viewer`,
      tabindex: '-1',
    });
    const fields = state.fields.map((field) =>
      field.type === 'signature'
        ? this.#signatureControl(field, this.#pageOf(state, field), budget)
        : el(
            'p',
            { class: 'date-field', 'data-field': field.key },
            `${fieldDescription(field)}. The server sets it to its own UTC date when you approve: an unsigned server time, not a trusted timestamp.`,
          ),
    );
    this.#consent = el('input', { type: 'checkbox', id: 'consent', 'aria-describedby': 'consent-text consent-version' });
    const approve = el('button', { type: 'button', id: 'approve' }, 'Approve the document');
    approve.addEventListener('click', () => void this.#approve());
    this.#reasons = DECLINE_REASONS.map(([value]) => [value, el('input', { type: 'radio', name: 'decline-reason', id: `decline-${value}`, value, checked: value === 'other' })] as const);
    const reasons = DECLINE_REASONS.map(([value, label], index) => el('span', { class: 'mode' }, this.#reasons[index]?.[1], el('label', { for: `decline-${value}` }, label)));
    const decline = el('button', { type: 'button', id: 'decline', class: 'secondary' }, 'Decline the document');
    decline.addEventListener('click', () => void this.#decline());

    this.#render(
      'review',
      'Review and approve',
      focus,
      el('p', { class: 'recipient' }, `Invitation for ${state.recipient.email_masked}.`),
      el('h3', { id: 'document-title' }, 'The document'),
      el('p', {}, `${pageCount} page${pageCount === 1 ? '' : 's'}, ${state.document.bytes} bytes. SHA-256: `, el('code', { class: 'digest', id: 'document-digest' }, state.document.digest)),
      check,
      frame,
      el(
        'p',
        { class: 'document-links' },
        el('a', { id: 'document-download', href: DOCUMENT_PATH, download: 'opensig-document.pdf' }, 'Download the document (PDF)'),
        el('a', { id: 'document-open', href: DOCUMENT_PATH, target: '_blank', rel: 'noopener noreferrer' }, 'Open the document in a new tab'),
      ),
      schematic(state.document.pages, state.fields),
      el('h3', { id: 'sign-title' }, 'Sign'),
      ...fields,
      el('h3', { id: 'consent-title' }, 'Consent'),
      el('div', { id: 'consent-text', class: 'consent-text' }, state.consent.text),
      el('p', { id: 'consent-version', class: 'hint' }, `Consent text version ${state.consent.version}.`),
      el('p', { id: 'assurance-statement', class: 'notice' }, state.assurance.statement),
      el('p', { id: 'seal-notice', class: 'notice' }, state.seal_notice),
      el('p', { class: 'consent-choice' }, this.#consent, el('label', { for: 'consent' }, 'I have read the consent text above and I agree to it.')),
      el('h3', { id: 'approve-title' }, 'Approve'),
      el(
        'p',
        { id: 'approve-explained' },
        'Approving records your consent, your signature and the date the server sets. It does not complete the document: that happens only after every recipient approves and the organization seal is applied and verified.',
      ),
      approve,
      el('details', { class: 'decline' }, el('summary', {}, 'Decline instead'), el('fieldset', {}, el('legend', {}, 'Why are you declining?'), ...reasons), decline),
      el('p', { class: 'hint' }, `Your session closes after 30 minutes without activity (server time ${state.session_expires_at}, unsigned).`),
      this.#endButton(),
    );
    if (!this.#consentOk) this.#fail('The consent text does not match its digest. Do not approve: ask the sender for a new invitation.');
    void this.#verifyDocument(state, check, frame);
  }

  async #verifyDocument(state: SessionState, check: HTMLElement, frame: HTMLIFrameElement): Promise<void> {
    const pdf = await this.#api.document();
    if (this.#state !== state) return;
    if (!pdf.ok) {
      if (pdf.status === 401) return this.#sessionEnded();
      check.textContent = 'The document could not be loaded. Do not approve it.';
      return;
    }
    const digest = await sha256Hex(pdf.value);
    const manifest = await this.#api.manifest();
    const manifestOk = manifest.ok && (await sha256Hex(manifest.value)) === state.manifest_digest;
    if (this.#state !== state) return;
    if (digest !== state.document.digest || pdf.value.byteLength !== state.document.bytes || !manifestOk) {
      check.textContent = 'The document does not match its digest. Do not approve it.';
      this.#fail('The document does not match the digest recorded for it. Do not approve it.');
      return;
    }
    this.#documentDigest = digest;
    check.textContent = 'Checked: these are the exact document bytes recorded for this invitation.';
    frame.setAttribute('src', DOCUMENT_PATH);
  }

  #inputs(): Map<string, SignatureInput> {
    const inputs = new Map<string, SignatureInput>();
    for (const [key, control] of this.#signatures) inputs.set(key, control.input());
    return inputs;
  }

  async #approve(): Promise<void> {
    const state = this.#state;
    if (this.#busy || state === null) return;
    if (!this.#consentOk) {
      this.#fail('The consent text does not match its digest. Do not approve: ask the sender for a new invitation.');
      return;
    }
    const inputs = this.#inputs();
    const consented = this.#consent?.checked === true;
    const problems = approvalProblems(state, this.#documentDigest, consented, inputs);
    const digest = this.#documentDigest;
    if (problems.length > 0 || digest === null) {
      this.#fail(problems.map((problem) => problem.message).join(' '));
      return;
    }
    this.#busy = true;
    this.#clearAlert();
    this.#announce('Sending your approval...');
    const result = await this.#api.approve(state.csrf_token, approvalBody(state, digest, inputs));
    this.#busy = false;
    if (result.ok) {
      this.#showApproved(result.value);
      return;
    }
    this.#announce('');
    if (result.status === 401) return this.#sessionEnded();
    if (result.status === 403 || result.status === 409) {
      const read = await this.#api.readSession();
      if (!read.ok) return this.#sessionEnded();
      if (result.status === 403 && read.value.envelope_version === state.envelope_version && read.value.turn === 'yours') {
        this.#state = read.value;
        this.#fail('Your session needed refreshing. Choose Approve the document again.');
        return;
      }
      await this.#afterSession(read.value, true);
      this.#fail('Something changed before your approval was recorded. Review the document again before you approve.');
      return;
    }
    if (result.status === 422) this.#fail('Your typed signature has characters the document font cannot show. Change it and try again.');
    else if (result.status === 429) this.#fail('Too many requests. Wait a minute, then try again.');
    else if (result.status === 400) this.#fail('The approval was not accepted. Check your fields and try again.');
    else this.#fail('Your approval could not be sent. Try again.');
  }

  #showApproved(receipt: ApprovalReceipt): void {
    this.#render(
      'approved',
      'Approval recorded',
      true,
      el('p', { id: 'approval-outcome' }, receipt.envelope_state === 'finalizing' ? FULLY_APPROVED : 'Your approval is recorded. The next recipient is invited to approve.'),
      el(
        'ul',
        { id: 'date-values' },
        ...receipt.date_values.map((date) => el('li', { 'data-field': date.key }, `Date in field ${date.key}: ${date.value}, set by the server (its UTC date: an unsigned server time).`)),
      ),
      el('p', { id: 'server-time' }, `Server time of your approval: ${receipt.server_time} (unsigned server time, not a trusted timestamp).`),
      el('p', {}, 'Approval reference: ', el('code', { class: 'digest', id: 'approval-id' }, receipt.approval_id)),
      this.#endButton(),
    );
    this.#announce('Approval recorded.');
  }

  async #decline(): Promise<void> {
    const state = this.#state;
    if (this.#busy || state === null) return;
    const chosen = this.#reasons.find(([, radio]) => radio.checked)?.[0];
    this.#busy = true;
    this.#clearAlert();
    const result = await this.#api.decline(state.csrf_token, chosen === undefined ? { expected_version: state.envelope_version } : { expected_version: state.envelope_version, reason_code: chosen });
    this.#busy = false;
    if (result.ok) {
      this.#render('declined', 'Document declined', true, el('p', { id: 'decline-outcome' }, 'You declined this document. Nothing was signed. The sender is told that it was declined.'));
      return;
    }
    if (result.status === 401) return this.#sessionEnded();
    if (result.status === 409) {
      const read = await this.#api.readSession();
      if (read.ok) await this.#afterSession(read.value, true);
      this.#fail('Something changed first. Review the document again.');
      return;
    }
    this.#fail('The decline could not be sent. Try again.');
  }

  async #endSession(): Promise<void> {
    const state = this.#state;
    this.#state = null;
    if (state !== null) await this.#api.endSession(state.csrf_token);
    this.#render('ended', 'Session ended', true, el('p', {}, 'Your session has ended. To continue, open the link from your invitation email again.'));
  }

  #sessionEnded(): void {
    this.#state = null;
    this.#render('ended', 'Your session ended', true, el('p', {}, 'Your session ended: it closes after 30 minutes without activity. Open the link from your invitation email again to continue.'));
  }
}
