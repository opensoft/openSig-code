// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// Entry point of the review shell (T009), loaded by index.html as the only script
// (type="module", from the build's immutable asset path). Order matters: the invitation is
// read from the fragment first, the address is scrubbed at once (no fragment and no query in
// the address bar or the session history), and only then does the flow start. Loading the
// page sends no request that changes anything (flow.ts).
//
// An invitation link followed in a tab already on /sign is a same-document fragment navigation:
// nothing reloads (A-010 SHELL-HASHCHANGE, request #38). On hashchange:
// - a fragment without the invitation parameter `i` (the skip link, an in-page anchor) is left
//   alone, with focus and skip-link behaviour unchanged;
// - any fragment with `i`, well formed or not (a duplicate or malformed `i` included), is read
//   with the same parser as at load and scrubbed at once, synchronously, before anything else
//   happens, exactly as at load, so neither the address bar nor any history entry keeps it;
// - only a valid invitation then restarts the flow (flow.ts restart). A duplicate or malformed
//   `i` changes nothing else: no restart, no request, the current step and its guards as they were.

import { ReviewShell } from './flow.js';
import { carriesInvitationParameter, invitationFromFragment, scrubLocation } from './invitation.js';

function region(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`the page has no #${id}`);
  return element;
}

const invitation = invitationFromFragment(window.location.hash);
scrubLocation(window.location, window.history);

const shell = new ReviewShell({ app: region('app'), status: region('status'), alert: region('alert') });

window.addEventListener('hashchange', () => {
  const hash = window.location.hash;
  if (!carriesInvitationParameter(hash)) return;
  const next = invitationFromFragment(hash);
  scrubLocation(window.location, window.history);
  if (next !== null) shell.restart(next);
});

void shell.start(invitation);
