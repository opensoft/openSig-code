// SPDX-License-Identifier: Apache-2.0
//
// WK-02: the launch, the environment scrub, the descriptors and the import
// boundary of the isolated sealing worker (T037). What the child sees is
// proven from inside it: a probe entry launched through the worker's own
// launch reports its environment, argv, permission grants and descriptors
// while canaries (one shaped like a PEM private-key header) sit in this
// process's environment.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { sealComposedPdf } from '../../src/cryptograph/worker/index.ts';
import { CHILD_ENTRY, DEFAULT_SEAL_LIMITS, launchForTests, READ_GRANTS, resolveSealLimits, sealWorkerCommand } from '../../src/cryptograph/worker/testing.ts';
import { composeSynthetic, DASHES, EVIDENCE_DIGEST, keyPair, selfSignedCertificate, withSealKey } from './support.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..', '..');
const WORKER = join(ROOT, 'src', 'cryptograph', 'worker');
const PROBE = join(HERE, 'support', 'probe-child.mjs');
const pair = keyPair('seal');
const certificateDer = selfSignedCertificate(pair);

function request(composed) {
  return {
    document: composed.bytes,
    certificateDer,
    byteRange: composed.byteRange,
    contentsOffset: composed.contents.offset,
    contentsHexLength: composed.contents.hexLength,
    approvalEvidenceDigest: EVIDENCE_DIGEST,
  };
}

async function withCanaries(body) {
  const names = ['OPENSIG_T037_CANARY', 'OPENSIG_T037_PEM_CANARY', 'OPENSIG_SEAL_KEY_FILE'];
  const saved = names.map((name) => process.env[name]);
  process.env.OPENSIG_T037_CANARY = 'visible-only-to-the-parent';
  process.env.OPENSIG_T037_PEM_CANARY = `${DASHES}BEGIN PRIVATE KEY${DASHES}\nsynthetic\n`;
  process.env.OPENSIG_SEAL_KEY_FILE = join(HERE, 'not-a-key');
  try {
    return await body();
  } finally {
    names.forEach((name, i) => {
      if (saved[i] === undefined) delete process.env[name];
      else process.env[name] = saved[i];
    });
  }
}

test('[WK-02] the launch is the pinned Node with a fixed argv, read grants on the seal sources only, and an empty environment', () => {
  const command = sealWorkerCommand();
  assert.equal(command.file, process.execPath, 'the child is the same pinned Node binary');
  assert.deepEqual(command.env, {}, 'the environment is empty');
  assert.deepEqual(command.args, [
    `--max-old-space-size=${DEFAULT_SEAL_LIMITS.heapMiB}`,
    '--permission',
    `--allow-fs-read=${WORKER}${sep}`,
    `--allow-fs-read=${join(ROOT, 'src', 'cryptograph', 'cms')}${sep}`,
    `--allow-fs-read=${join(ROOT, 'src', 'cryptograph', 'keys')}${sep}`,
    `--allow-fs-read=${join(ROOT, 'src', 'cryptograph', 'compose', 'bounds.ts')}`,
    '--disallow-code-generation-from-strings',
    CHILD_ENTRY,
  ]);
  assert.equal(CHILD_ENTRY, join(WORKER, 'child.ts'));
  for (const grant of ['--allow-fs-write', '--allow-child-process', '--allow-worker', '--allow-addons', '--allow-wasi']) {
    assert.equal(command.args.some((arg) => arg.startsWith(grant)), false, `no ${grant}`);
  }
  assert.deepEqual(sealWorkerCommand(resolveSealLimits({ wallMs: 5 })).args, command.args, 'the argv carries no request value and no time limit');
  assert.deepEqual(sealWorkerCommand(DEFAULT_SEAL_LIMITS, PROBE).args.filter((a) => a.startsWith('--allow-fs-read=')), [`--allow-fs-read=${PROBE}`], 'a test entry gets a read grant on itself only');
  for (const bad of [{ wallMs: DEFAULT_SEAL_LIMITS.wallMs + 1 }, { heapMiB: DEFAULT_SEAL_LIMITS.heapMiB + 1 }, { wallMs: 0 }, { heapMiB: 1.5 }, { cpuMs: 1 }]) {
    assert.throws(() => resolveSealLimits(bad), (e) => e.name === 'SealError' && e.reason === 'input-invalid', 'limits only narrow');
  }
});

test('[WK-02] the child sees an empty environment, no argument, the permission model without write, child or worker grants, and the key file as fd 3 only', async () => {
  const composed = composeSynthetic(certificateDer);
  const outcome = await withCanaries(() => withSealKey(pair, ({ fd }) => launchForTests(PROBE, request(composed), fd)));
  assert.equal(outcome.code, 0, 'the probe exited normally');
  assert.equal(outcome.signal, null);
  const seen = JSON.parse(outcome.stdout.toString('utf8'));
  assert.deepEqual(seen.env, [], 'no environment variable reaches the child, canaries included');
  assert.deepEqual(seen.argv, [], 'no argument follows the entry');
  assert.deepEqual(seen.execArgv, sealWorkerCommand(DEFAULT_SEAL_LIMITS, PROBE).args.slice(0, -1), 'the flags are exactly the plan');
  assert.deepEqual(seen.permission, { active: true, fsWrite: false, child: false, worker: false, readsTmp: false });
  assert.ok(['socket', 'fifo'].includes(seen.fds[0].kind), 'fd 0 is the request pipe');
  assert.ok(['socket', 'fifo'].includes(seen.fds[1].kind), 'fd 1 is the reply pipe');
  assert.equal(seen.fds[2].kind, 'char', 'fd 2 is /dev/null');
  assert.deepEqual(seen.fds[3], { kind: 'file', mode: 0o600 }, 'fd 3 is the 0600 key file itself');
  // Node's own event loop holds descriptors from 4 up (epoll, eventfd, signal
  // pipes); none of them is a file or a directory.
  seen.fds.slice(4).forEach((fd, i) => assert.ok(!['file', 'dir'].includes(fd.kind), `fd ${i + 4} is not an inherited file or directory`));
  assert.equal(seen.keyReadable, true, 'fd 3 is readable under the permission model without a read grant on its path');
});

test('[WK-02] a seal succeeds while the parent environment holds a PEM-shaped value, which the child would refuse had it leaked', async () => {
  const composed = composeSynthetic(certificateDer);
  const sealed = await withCanaries(() => withSealKey(pair, ({ fd }) => sealComposedPdf({ composed, certificateDer, approvalEvidenceDigest: EVIDENCE_DIGEST, keyFd: fd })));
  assert.equal(sealed.bytes.length, composed.bytes.length, 'sealed');
});

test("[WK-02] the read grants are exactly the child's own modules: every import is granted, and every grant is imported", () => {
  const builtins = new Set();
  const seen = new Set();
  const pending = [CHILD_ENTRY];
  // `import ... from 'x'`, `import 'x'` and `export ... from 'x'` (an export without `from` is not an import).
  const SPECIFIER = /(?:^|\n)\s*(?:import\s*(?:[^'"`;]*?\sfrom\s*)?|export\s[^'"`;]*?\sfrom\s*)['"]([^'"]+)['"]/g;
  const granted = (file) => READ_GRANTS.some((grant) => (grant.endsWith(sep) ? file.startsWith(grant) : file === grant));
  while (pending.length > 0) {
    const file = pending.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    assert.ok(granted(file), `${file.slice(ROOT.length)} is granted`);
    for (const [, specifier] of readFileSync(file, 'utf8').matchAll(SPECIFIER)) {
      if (specifier.startsWith('node:')) builtins.add(specifier);
      else if (specifier.startsWith('.')) pending.push(resolve(dirname(file), specifier));
      else assert.fail(`bare specifier ${specifier} in ${file.slice(ROOT.length)}`);
    }
  }
  for (const grant of READ_GRANTS) {
    assert.ok([...seen].some((file) => (grant.endsWith(sep) ? file.startsWith(grant) : file === grant)), `${grant.slice(ROOT.length)} is used by the child`);
  }
  assert.ok(seen.has(join(ROOT, 'src', 'cryptograph', 'compose', 'bounds.ts')), "the child imports T036's bounds module");
  const forbidden = [['compose', 'index.ts'], ['compose', 'compose.ts'], ['pdf', 'service.ts'], ['pdf', 'sandbox.ts'], ['pdf', 'parser.ts'], ['pdf', 'worker.ts']].map((parts) => `${sep}${parts.join(sep)}`);
  assert.equal([...seen].some((file) => forbidden.some((tail) => file.endsWith(tail))), false, 'neither the composer nor the parse service is imported');
  for (const builtin of builtins) assert.ok(['node:fs', 'node:crypto', 'node:path', 'node:buffer'].includes(builtin), `${builtin} is allowed in the child`);
});
