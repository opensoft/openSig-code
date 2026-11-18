// SPDX-License-Identifier: Apache-2.0
//
// T011, row US1-MASK (A-010 requests #47 and #48 B5): browser-free probes that keep the masking
// fix guarded in every us1 run. They use synthetic stand-ins for a page and a browser (no
// Chromium, no server, no network). Their names lead with the extra IDs US1-MASK-U1 and
// US1-MASK-U2, never with a required case ID, so a probe never stands in for a browser case.
// - U1, browser.mjs respondedTo: the response wait exists before the action is called; the first
//   rejection surfaces whether the action throws synchronously, rejects, or the wait fails first;
//   and nothing is left as an unhandled rejection, even when the wait is rejected later, as
//   cleanup closing a page does.
// - U2, browser.mjs whilePagesOpen and closeAll: the first error is recorded before any close
//   runs; the record line follows the original message, which stays first and unchanged; every
//   close runs in its own guard; a failing close joins the record and never replaces the first
//   error; a failing close with no earlier error is itself recorded and thrown; neither the line
//   nor the record file holds an invitation, a cookie value or a host path, and frames are
//   repository-relative. U2 writes its records to its own owner-only temporary directory, never
//   to the run's output, so no probe record can be mistaken for a browser case's.

import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';

import { closeAll, respondedTo, whilePagesOpen } from './browser.mjs';
import { COOKIE, PATHS, REPO } from './harness.mjs';

const ORIGIN = 'http://127.0.0.1:9';
/** A synthetic stand-in shaped like an invitation (48 base64url characters); it grants nothing. */
const INVITATION_SAMPLE = 'example-invitation-'.padEnd(48, 'z');
const CLOSED = 'Target page, context or browser has been closed';

/** A stand-in for the answer to the approval request. */
const ANSWER = Object.freeze({ url: () => `${ORIGIN}${PATHS.approval}`, request: () => ({ method: () => 'POST' }), status: () => 200 });

/** A stand-in page whose one response wait the probe settles by hand; `log` records the order of calls. */
function standInPage(log) {
  const wait = {};
  const page = {
    waitForResponse(predicate) {
      log.push('wait');
      wait.predicate = predicate;
      return new Promise((resolveWait, rejectWait) => Object.assign(wait, { resolve: resolveWait, reject: rejectWait }));
    },
  };
  return { page, wait };
}

/** A stand-in page for a record: its url, and closed once its closer has run. */
function standInOpenPage(url) {
  let closed = false;
  return {
    page: { url: () => url, isClosed: () => closed },
    close: () => {
      closed = true;
    },
  };
}

const nextTurn = () => new Promise((resolveTurn) => setImmediate(resolveTurn));

/**
 * Every unhandled rejection reported while `run` executes and for two turns of the event loop
 * after it. Node reports a rejection that has no handler once the microtask queue drains, so two
 * immediates later every such report has been made; nothing here waits on a clock.
 */
async function unhandledDuring(run) {
  const seen = [];
  const onUnhandled = (reason) => seen.push(reason?.message ?? String(reason));
  process.on('unhandledRejection', onUnhandled);
  try {
    await run();
    await nextTurn();
    await nextTurn();
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
  return seen;
}

test('[US1-MASK-U1] respondedTo starts the response wait before the action, surfaces the first rejection, and leaves no wait unhandled, even when the action throws synchronously', async () => {
  // The answer arrives: the wait was created first, the action was called at once, and the result is the response.
  {
    const log = [];
    const { page, wait } = standInPage(log);
    const pending = respondedTo(page, ORIGIN, PATHS.approval, 'POST', async () => {
      log.push('action');
    });
    assert.deepEqual(log, ['wait', 'action'], 'the wait exists before the action is called, and the action is called at once');
    assert.equal(wait.predicate(ANSWER), true, 'the wait matches the answer to its own request');
    assert.equal(wait.predicate({ url: ANSWER.url, request: () => ({ method: () => 'GET' }) }), false, 'and not another method on the same path');
    wait.resolve(ANSWER);
    assert.equal(await pending, ANSWER, 'the result is the response');
  }

  // The action fails first, synchronously or by rejecting; cleanup then closes the page, which rejects the wait.
  const failingActions = [
    [
      'synchronously',
      (failure) => () => {
        throw failure;
      },
    ],
    [
      'by rejecting',
      (failure) => async () => {
        throw failure;
      },
    ],
  ];
  for (const [how, makeAction] of failingActions) {
    const failure = new Error(`synthetic action failure, thrown ${how}`);
    const { page, wait } = standInPage([]);
    const unhandled = await unhandledDuring(async () => {
      await assert.rejects(respondedTo(page, ORIGIN, PATHS.approval, 'POST', makeAction(failure)), (error) => error === failure, `the action's own error surfaces when it fails ${how}`);
      wait.reject(new Error(CLOSED));
    });
    assert.deepEqual(unhandled, [], `the wait, rejected after the action failed ${how}, is handled`);
  }

  // The wait fails first (the page closed); the action fails after it. Both are settled before
  // the result is awaited, so a variant that awaits the action before the wait fails here at
  // once instead of waiting for ever.
  {
    const { page, wait } = standInPage([]);
    const closed = new Error(CLOSED);
    let failAction;
    const unhandled = await unhandledDuring(async () => {
      const pending = respondedTo(page, ORIGIN, PATHS.approval, 'POST', () =>
        new Promise((_resolveAction, rejectAction) => {
          failAction = rejectAction;
        }),
      );
      wait.reject(closed);
      failAction(new Error('synthetic action failure after the page closed'));
      await assert.rejects(pending, (error) => error === closed, "the wait's own error surfaces when it fails first");
    });
    assert.deepEqual(unhandled, [], 'the action, rejected after the wait failed, is handled');
  }
});

test('[US1-MASK-U2] whilePagesOpen records the first error before any close, appends one line after the unchanged original message, guards every close, and never lets a cleanup error replace the first error; closeAll guards every close', async () => {
  const out = mkdtempSync(join(tmpdir(), 'opensig-us1-mask-'));
  try {
    const recordsFile = join(out, 'first-error-US1-MASK-U2.json');
    const readRecords = () => JSON.parse(readFileSync(recordsFile, 'utf8'));

    // A section error, then three closes, the second of which fails.
    const invitation = `${ORIGIN}/sign#i=${INVITATION_SAMPLE}`;
    const one = standInOpenPage(invitation);
    const two = standInOpenPage('about:blank');
    const three = standInOpenPage(pathToFileURL(join(tmpdir(), 'synthetic.html')).href);
    const elsewhere = '/opt/synthetic-elsewhere/frame.mjs:1:1';
    const original = `locator.click: synthetic first failure at ${invitation} for '${PATHS.approval}' under ${REPO} near ${elsewhere} with ${COOKIE}=${INVITATION_SAMPLE}`;
    const first = new Error(original);
    first.stack = `Error: ${original}\n    at openSession (${pathToFileURL(join(REPO, 'tests', 'acceptance', 'us1', 'browser.mjs')).href}:200:3)\n    at elsewhere (node:internal/process/task_queues:105:5)`;
    const closeFailure = new Error(`browserContext.close: synthetic cleanup failure in ${join(tmpdir(), 'synthetic')}`);
    const ran = [];
    const closers = [
      () => {
        ran.push('one');
        one.close();
      },
      () => {
        ran.push('failing');
        throw closeFailure;
      },
      async () => {
        ran.push('two');
        two.close();
      },
    ];
    await assert.rejects(
      whilePagesOpen({ caseId: 'US1-MASK-U2', section: 'probe', browser: { isConnected: () => false }, pages: { one: one.page, two: two.page, three: three.page }, closers, out }, async () => {
        throw first;
      }),
      (error) => error === first,
      'the first error itself is rethrown, never the cleanup error',
    );
    assert.deepEqual(ran, ['one', 'failing', 'two'], 'every close ran, in order, each in its own guard');
    assert.ok(first.message.startsWith(`${original}\n`), 'the original message stays first and unchanged');
    const line = first.message.slice(original.length + 1);
    assert.equal(line.includes('\n'), false, 'exactly one line is appended');
    assert.equal(
      line,
      '[US1-MASK-U2 first error, recorded before cleanup in "probe": browser.isConnected()=false; page one open at /sign; page two open at about:blank; page three open at file: (location not recorded); cleanup errors: 1 (Error: browserContext.close: synthetic cleanup failure in <tmp>/synthetic)]',
      'the line: the browser and the pages as they were before any close (pathname only, never a fragment or a file location), then the cleanup error',
    );
    const [record, ...others] = readRecords();
    assert.equal(others.length, 0, 'one record for the one failure');
    assert.deepEqual(
      {
        case: record.case,
        section: record.section,
        raised_by: record.raised_by,
        browser_connected: record.browser_connected,
        pages: record.pages,
        name: record.error.name,
        frames: record.error.frames,
        cleanup: record.cleanup_errors.map((entry) => entry.message),
      },
      {
        case: 'US1-MASK-U2',
        section: 'probe',
        raised_by: 'section',
        browser_connected: false,
        pages: { one: { closed: false, path: '/sign' }, two: { closed: false, path: 'about:blank' }, three: { closed: false, path: 'file: (location not recorded)' } },
        name: 'Error',
        frames: ['at openSession (tests/acceptance/us1/browser.mjs:200:3)'],
        cleanup: ['browserContext.close: synthetic cleanup failure in <tmp>/synthetic'],
      },
      'the record file holds the same record, with repository-relative frames',
    );
    assert.equal(
      record.error.message,
      `locator.click: synthetic first failure at ${ORIGIN}/sign#<redacted> for '${PATHS.approval}' under <repo> near <abs> with ${COOKIE}=<redacted>`,
      "the recorded message holds no URL fragment, cookie value or host path: a known prefix is named, any other absolute path is <abs>, and the application's own URL path stays",
    );
    const written = `${readFileSync(recordsFile, 'utf8')}\n${line}`;
    for (const [what, forbidden] of [
      ['the invitation', INVITATION_SAMPLE],
      ['the repository path', REPO],
      ['the temporary directory path', tmpdir()],
      ['an unknown absolute path', '/opt/synthetic-elsewhere'],
      ['a file URL', 'file://'],
    ]) {
      assert.equal(written.includes(forbidden), false, `neither the line nor the record file holds ${what}`);
    }

    // The section succeeds, but a close fails: that failure is recorded and thrown after every close.
    const late = standInOpenPage(`${ORIGIN}/sign`);
    const cleanupOnly = new Error('browserContext.close: synthetic close failure with no earlier error');
    const after = [];
    const lateClosers = [
      () => {
        after.push('failing');
        throw cleanupOnly;
      },
      () => {
        after.push('late');
        late.close();
      },
    ];
    await assert.rejects(
      whilePagesOpen({ caseId: 'US1-MASK-U2', section: 'cleanup only', browser: { isConnected: () => true }, pages: { late: late.page }, closers: lateClosers, out }, async () => 'section result'),
      (error) => error === cleanupOnly,
      'with no earlier error, the failing close is the error thrown',
    );
    assert.deepEqual(after, ['failing', 'late'], 'after every close has run');
    assert.ok(cleanupOnly.message.startsWith('browserContext.close: synthetic close failure with no earlier error\n'), 'its original message stays first');
    assert.match(cleanupOnly.message, /\n\[US1-MASK-U2 first error, raised by the cleanup of "cleanup only": browser\.isConnected\(\)=true; page late closed at \/sign; cleanup errors: none\]$/, 'and its line says the cleanup raised it');
    assert.deepEqual(
      readRecords().map((entry) => [entry.section, entry.raised_by]),
      [
        ['probe', 'section'],
        ['cleanup only', 'cleanup'],
      ],
      'a second failure of the same case adds its own record to the same file',
    );

    // Nothing fails: the section's result is returned, the closes run, and nothing is recorded.
    const quiet = [];
    const result = await whilePagesOpen({ caseId: 'US1-MASK-U2', section: 'quiet', browser: { isConnected: () => true }, closers: [() => quiet.push('closed')], out }, async () => 'section result');
    assert.equal(result, 'section result', "with no error, the section's result is returned");
    assert.deepEqual(quiet, ['closed'], 'and its closes still run');
    assert.equal(readRecords().length, 2, 'and nothing more is recorded');
    assert.deepEqual(readdirSync(out), ['first-error-US1-MASK-U2.json'], 'records are files named per case, and nothing else is written');

    // closeAll, as the after() hooks use it: a failing close never stops the next one.
    const closing = [];
    const hookFailure = new Error('synthetic browser close failure in an after() hook');
    await assert.rejects(
      closeAll([
        () => {
          closing.push('browser');
          throw hookFailure;
        },
        async () => {
          closing.push('server');
        },
      ]),
      (error) => error === hookFailure,
      'closeAll throws the failing close',
    );
    assert.deepEqual(closing, ['browser', 'server'], 'after the browser close failed, the server is still closed');
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
