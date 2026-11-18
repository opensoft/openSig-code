// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// Entry point of the review shell (T009), loaded by index.html as the only script
// (type="module", from the build's immutable asset path). Order matters: the invitation is
// read from the fragment first, the address is scrubbed at once (no fragment and no query in
// the address bar or the session history), and only then does the flow start. Loading the
// page sends no request that changes anything (flow.ts).

import { ReviewShell } from './flow.js';
import { invitationFromFragment, scrubLocation } from './invitation.js';

function region(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`the page has no #${id}`);
  return element;
}

const invitation = invitationFromFragment(window.location.hash);
scrubLocation(window.location, window.history);

const shell = new ReviewShell({ app: region('app'), status: region('status'), alert: region('alert') });
void shell.start(invitation);
