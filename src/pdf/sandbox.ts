// SPDX-License-Identifier: Apache-2.0
//
// Sandbox launcher for the PDF parse worker (T033, A-009 LBR-1 and LBR-3).
//
// The worker runs in a user, network, mount, IPC, UTS and PID namespace with a minimal
// read-only root and no capabilities. Its input arrives over the stdio pipe. Two
// launchers are supported, both platform tools found at fixed absolute paths (PATH is
// never searched, and no caller can name another binary):
//
// - bubblewrap (preferred):
//     bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --clearenv
//           --ro-bind <src> <dest>... --ro-bind /dev/null /dev/null --remount-ro /
//           --chdir / -- <node> ...
// - the util-linux composition:
//     unshare --user --map-root-user --net --mount --ipc --uts --pid --fork --kill-child
//             -- /bin/sh -c <setup> ...
//   where the setup script mounts a tmpfs root, bind-mounts the same read-only set into it,
//   remounts the root read-only and execs `chroot <root> setpriv --no-new-privs
//   --inh-caps=-all --ambient-caps=-all --bounding-set=-all --securebits=... -- <node> ...`.
//
// The root holds only: the library directories the runtime needs (bound read-only), the
// Node binary, the worker's source files (each bound as a file, so nothing created later in
// the source directory appears) and, for util-linux, the setpriv binary; plus /dev holding
// only a read-only, nodev bind of /dev/null. Because of nodev that node exists but cannot be
// opened (the worker opens no device: its stdio are pipes). Nothing in the root is writable:
// there is no tmpfs /dev or /dev/shm, and no /proc, /run, /tmp, /var, /etc or home directory.
//
// What this does and does not give the worker:
// - IP connects (TCP, UDP) fail: the network namespace has only a down loopback interface.
// - Abstract AF_UNIX sockets are per network namespace, so host listeners are unreachable.
// - Pathname AF_UNIX sockets: host socket paths (for example a container daemon socket) do
//   not exist in the root, so they cannot be connected to or written. A socket placed inside
//   one of the bound library directories would be reachable; the binds therefore never
//   include the worker's directory or any writable location.
// - No capabilities, no writable file system (including /dev), no usable device node, no
//   view of host processes.
//
// The probe launches a check inside each candidate launcher with the same root and
// confirms isolation from inside (read-only root, host paths absent, no non-loopback
// interface, a nonce echoed) and from the host side (the sandboxed process has empty
// effective, permitted and bounding capability sets and different network and mount
// namespaces from the service). An exit status alone is never trusted. Bench availability
// is local evidence only; it never closes the production gate `parser-network-sandbox`.

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, realpathSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export type LauncherKind = 'bwrap' | 'util-linux';
export const LAUNCHER_KINDS: readonly LauncherKind[] = Object.freeze(['bwrap', 'util-linux']);

/** Fixed tool locations. These are the only binaries the service will run as launchers. */
export const TOOL_PATHS = Object.freeze({
  bwrap: Object.freeze(['/usr/bin/bwrap', '/bin/bwrap']),
  unshare: Object.freeze(['/usr/bin/unshare', '/bin/unshare']),
  mount: Object.freeze(['/usr/bin/mount', '/bin/mount']),
  chroot: Object.freeze(['/usr/sbin/chroot', '/usr/bin/chroot', '/sbin/chroot']),
  setpriv: Object.freeze(['/usr/bin/setpriv', '/bin/setpriv']),
});

const SHELL = '/bin/sh';
const PROBE_TIMEOUT_MS = 10_000;
/** Library directories bound read-only when they exist (the pinned runtime is linux-x64). */
const LIBRARY_DIRS: readonly string[] = Object.freeze(['/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu', '/lib64', '/usr/lib64']);

export interface Bind {
  /** Host path (resolved). */
  readonly source: string;
  /** Path inside the sandbox root. */
  readonly target: string;
  readonly kind: 'dir' | 'file';
}

export interface SandboxProbe {
  readonly available: boolean;
  readonly launcher: LauncherKind | null;
  /** Absolute tool paths used by the launcher. */
  readonly tools: Readonly<Record<string, string>>;
}

export interface IsolationEvidence {
  readonly launcher: LauncherKind;
  readonly rootWrite: string;
  readonly hiddenPaths: readonly string[];
  readonly nonLoopbackInterfaces: number;
  readonly capabilities: { readonly effective: string; readonly permitted: string; readonly bounding: string };
  readonly namespacesDiffer: { readonly net: boolean; readonly mnt: boolean };
}

const UNAVAILABLE: SandboxProbe = Object.freeze({ available: false, launcher: null, tools: Object.freeze({}) });

function firstExisting(candidates: readonly string[]): string | null {
  for (const candidate of candidates) if (candidate.startsWith('/') && existsSync(candidate)) return candidate;
  return null;
}

/** Tool paths for a launcher, or null when one of its tools is missing. */
export function launcherTools(kind: LauncherKind): Readonly<Record<string, string>> | null {
  const names = kind === 'bwrap' ? (['bwrap'] as const) : (['unshare', 'mount', 'chroot', 'setpriv'] as const);
  const tools: Record<string, string> = {};
  for (const name of names) {
    const found = firstExisting(TOOL_PATHS[name]);
    if (found === null) return null;
    tools[name] = found;
  }
  return Object.freeze(tools);
}

/** The read-only binds for a worker: library directories, the Node binary and `files`. */
export function rootBinds(files: readonly string[], extraFiles: readonly string[] = []): Bind[] {
  const binds: Bind[] = [];
  for (const dir of LIBRARY_DIRS) {
    if (!existsSync(dir)) continue;
    binds.push({ source: realpathSync(dir), target: dir, kind: 'dir' });
  }
  const seen = new Set<string>();
  for (const file of [process.execPath, ...files, ...extraFiles]) {
    const real = realpathSync(file);
    if (seen.has(real)) continue;
    seen.add(real);
    if (!lstatSync(real).isFile()) throw new Error('sandbox binds name regular files only');
    binds.push({ source: real, target: real, kind: 'file' });
  }
  return binds;
}

/** Regular files directly inside `dir` (the worker's own sources), resolved. */
export function sourceFiles(dir: string): string[] {
  const real = realpathSync(dir);
  return readdirSync(real)
    .sort()
    .map((name) => join(real, name))
    .filter((path) => lstatSync(path).isFile());
}

const UTIL_LINUX_SETUP = [
  'set -eu',
  'root=$1; mount=$2; chroot=$3; setpriv=$4; shift 4',
  '"$mount" -t tmpfs -o mode=0755,size=64k opensig-parse-root "$root"',
  'while [ "$1" != "--" ]; do',
  '  kind=$1; src=$2; dst=$3; shift 3',
  '  if [ "$kind" = d ]; then mkdir -p "$root$dst"; else mkdir -p "$root${dst%/*}"; : > "$root$dst"; fi',
  '  "$mount" --bind "$src" "$root$dst"',
  '  "$mount" -o remount,bind,ro,nosuid,nodev "$root$dst"',
  'done',
  'shift',
  'mkdir -p "$root/dev"; : > "$root/dev/null"; "$mount" --bind /dev/null "$root/dev/null"',
  '"$mount" -o remount,bind,ro,nosuid,nodev "$root/dev/null"',
  '"$mount" -o remount,bind,ro "$root"',
  'exec "$chroot" "$root" "$setpriv" --no-new-privs --inh-caps=-all --ambient-caps=-all --bounding-set=-all \\',
  '  --securebits=+noroot,+noroot_locked,+no_setuid_fixup,+no_setuid_fixup_locked,+keep_caps_locked -- "$@"',
].join('\n');

let mountPoint: string | null = null;

/** An empty host directory used as the tmpfs mount point inside each private mount namespace. */
function utilLinuxMountPoint(): string {
  if (mountPoint === null || !existsSync(mountPoint)) {
    mountPoint = mkdtempSync(join(tmpdir(), 'opensig-parse-root-'));
    const created = mountPoint;
    process.once('exit', () => {
      try {
        rmdirSync(created);
      } catch {
        // already gone
      }
    });
  }
  return mountPoint;
}

/** Wrap `file args...` in the launcher with the given read-only binds. */
export function launcherCommand(probe: SandboxProbe, binds: readonly Bind[], file: string, args: readonly string[]): { file: string; args: string[] } {
  if (!probe.available || probe.launcher === null) throw new Error('no sandbox launcher is available');
  const tools = probe.tools;
  if (probe.launcher === 'bwrap') {
    const bwrap = tools.bwrap;
    if (bwrap === undefined) throw new Error('bwrap path missing');
    return {
      file: bwrap,
      args: [
        '--unshare-all',
        '--die-with-parent',
        '--new-session',
        '--cap-drop',
        'ALL',
        '--clearenv',
        ...binds.flatMap((bind) => ['--ro-bind', bind.source, bind.target]),
        '--ro-bind',
        '/dev/null',
        '/dev/null',
        '--remount-ro',
        '/',
        '--chdir',
        '/',
        '--',
        file,
        ...args,
      ],
    };
  }
  const { unshare, mount, chroot, setpriv } = tools;
  if (unshare === undefined || mount === undefined || chroot === undefined || setpriv === undefined) throw new Error('util-linux tool path missing');
  const all = [...binds, { source: realpathSync(setpriv), target: setpriv, kind: 'file' as const }];
  return {
    file: unshare,
    args: [
      '--user',
      '--map-root-user',
      '--net',
      '--mount',
      '--ipc',
      '--uts',
      '--pid',
      '--fork',
      '--kill-child',
      '--propagation',
      'private',
      '--',
      SHELL,
      '-c',
      UTIL_LINUX_SETUP,
      'opensig-sandbox',
      utilLinuxMountPoint(),
      mount,
      chroot,
      setpriv,
      ...all.flatMap((bind) => [bind.kind === 'dir' ? 'd' : 'f', bind.source, bind.target]),
      '--',
      file,
      ...args,
    ],
  };
}

// --- host-side process inspection ---------------------------------------------------------

/** Every descendant of `root` (scanned from /proc), in breadth-first order. */
export function descendants(root: number): number[] {
  const children = new Map<number, number[]>();
  let names: string[];
  try {
    names = readdirSync('/proc');
  } catch {
    return [];
  }
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue;
    let stat: string;
    try {
      stat = readFileSync(`/proc/${name}/stat`, 'latin1');
    } catch {
      continue;
    }
    const ppid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
    const list = children.get(ppid) ?? [];
    list.push(Number(name));
    children.set(ppid, list);
  }
  const found: number[] = [];
  const queue = [root];
  while (queue.length > 0) {
    const pid = queue.shift() as number;
    for (const child of children.get(pid) ?? []) {
      found.push(child);
      queue.push(child);
    }
  }
  return found;
}

function statusField(pid: number, field: string): string | null {
  try {
    const match = new RegExp(`^${field}:\\s*(\\S+)`, 'm').exec(readFileSync(`/proc/${pid}/status`, 'latin1'));
    return match?.[1] ?? null;
  } catch {
    return null;
  }
}

function namespace(pid: number | 'self', kind: 'net' | 'mnt'): string | null {
  try {
    return readlinkSync(`/proc/${pid}/ns/${kind}`);
  } catch {
    return null;
  }
}

// --- isolation probe ---------------------------------------------------------------------

/** Runs inside the candidate sandbox: argv = [nonce, ...host paths that must be absent]. */
const PROBE_SCRIPT = [
  "const fs = require('node:fs'); const os = require('node:os');",
  'const [nonce, ...hidden] = process.argv.slice(1);',
  'const attempt = (fn) => { try { fn(); return "ok"; } catch (error) { return error.code ?? error.name; } };',
  'const out = {',
  '  nonce,',
  "  root_write: attempt(() => fs.writeFileSync('/opensig-probe', 'x')),",
  '  hidden: hidden.map((path) => attempt(() => fs.statSync(path))),',
  '  interfaces: Object.values(os.networkInterfaces()).flat().filter((entry) => !entry.internal).length,',
  "  root: fs.readdirSync('/').sort(),",
  '};',
  "process.stdout.write(JSON.stringify(out) + '\\n');",
  "process.stdin.resume(); process.stdin.on('end', () => process.exit(0));",
].join('\n');

const ZERO_CAPS = /^0+$/;

/** Host paths that exist outside, are not on the way to any bind, and must be absent inside. */
function hostPathsToHide(binds: readonly Bind[]): string[] {
  const candidates = ['/etc/passwd', '/proc/self', '/run', '/var', '/tmp', '/home', '/root'];
  return candidates.filter((path) => existsSync(path) && !binds.some((bind) => bind.target === path || bind.target.startsWith(`${path}/`)));
}

/**
 * Run the isolation probe through `build` (which wraps a command in a sandbox) and return
 * the evidence, or null when anything is not exactly as required. Exported for PL-19: a
 * wrapper that does not isolate (for example `true`, or no wrapper at all) is refused.
 */
export function confirmIsolation(kind: LauncherKind, build: (file: string, args: string[]) => { file: string; args: string[] }, binds: readonly Bind[]): Promise<IsolationEvidence | null> {
  const nonce = randomBytes(16).toString('hex');
  const hidden = hostPathsToHide(binds);
  const expectedRoot = new Set(['dev', ...binds.map((bind) => bind.target.split('/')[1] ?? '')]);
  const ownNet = namespace('self', 'net');
  const ownMnt = namespace('self', 'mnt');
  let command: { file: string; args: string[] };
  try {
    command = build(process.execPath, ['-e', PROBE_SCRIPT, nonce, ...hidden]);
  } catch {
    return Promise.resolve(null);
  }
  return new Promise((resolveProbe) => {
    let child;
    try {
      child = spawn(command.file, command.args, { env: {}, stdio: ['pipe', 'pipe', 'ignore'] });
    } catch {
      resolveProbe(null);
      return;
    }
    let settled = false;
    let evidence: IsolationEvidence | null = null;
    let output = '';
    const finish = (value: IsolationEvidence | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolveProbe(value);
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(null);
    }, PROBE_TIMEOUT_MS);
    child.on('error', () => finish(null));
    child.stdin.on('error', () => undefined);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      if (evidence !== null || output.length > 64 * 1024) return;
      output += chunk;
      const newline = output.indexOf('\n');
      if (newline < 0) return;
      let reported: Record<string, unknown>;
      try {
        reported = JSON.parse(output.slice(0, newline));
      } catch {
        child.kill('SIGKILL');
        return finish(null);
      }
      // Host-side view of the sandboxed process(es), taken while the probe waits on stdin.
      const tree = child.pid === undefined ? [] : descendants(child.pid);
      const leaves = tree.filter((pid) => descendants(pid).length === 0);
      const inspected = leaves.length > 0 ? leaves : child.pid === undefined ? [] : [child.pid];
      const caps = inspected.map((pid) => ({
        effective: statusField(pid, 'CapEff') ?? '?',
        permitted: statusField(pid, 'CapPrm') ?? '?',
        bounding: statusField(pid, 'CapBnd') ?? '?',
        net: namespace(pid, 'net'),
        mnt: namespace(pid, 'mnt'),
      }));
      const root = Array.isArray(reported.root) ? (reported.root as unknown[]) : null;
      const hiddenResults = Array.isArray(reported.hidden) ? (reported.hidden as unknown[]) : null;
      const ok =
        reported.nonce === nonce &&
        reported.root_write === 'EROFS' &&
        hiddenResults !== null &&
        hiddenResults.length === hidden.length &&
        hiddenResults.every((result) => result === 'ENOENT') &&
        reported.interfaces === 0 &&
        root !== null &&
        root.every((entry) => typeof entry === 'string' && expectedRoot.has(entry)) &&
        caps.length > 0 &&
        caps.every(
          (cap) =>
            ZERO_CAPS.test(cap.effective) &&
            ZERO_CAPS.test(cap.permitted) &&
            ZERO_CAPS.test(cap.bounding) &&
            cap.net !== null &&
            cap.mnt !== null &&
            ownNet !== null &&
            ownMnt !== null &&
            cap.net !== ownNet &&
            cap.mnt !== ownMnt,
        );
      if (ok) {
        const first = caps[0] as (typeof caps)[number];
        evidence = Object.freeze({
          launcher: kind,
          rootWrite: 'EROFS',
          hiddenPaths: Object.freeze([...hidden]),
          nonLoopbackInterfaces: 0,
          capabilities: Object.freeze({ effective: first.effective, permitted: first.permitted, bounding: first.bounding }),
          namespacesDiffer: Object.freeze({ net: true, mnt: true }),
        });
      }
      child.stdin.end();
    });
    child.on('close', (code) => finish(code === 0 ? evidence : null));
  });
}

const probes = new Map<string, Promise<SandboxProbe>>();

/**
 * Find the first launcher in `kinds` whose tools exist and whose sandbox is confirmed by
 * the isolation probe. Memoized per kind list for the life of the process.
 */
export function probeSandbox(kinds: readonly LauncherKind[] = LAUNCHER_KINDS, workerFiles: readonly string[] = []): Promise<SandboxProbe> {
  const key = kinds.join(',');
  let probe = probes.get(key);
  if (probe === undefined) {
    probe = (async () => {
      for (const kind of kinds) {
        if (!LAUNCHER_KINDS.includes(kind)) continue;
        const tools = launcherTools(kind);
        if (tools === null) continue;
        const candidate: SandboxProbe = Object.freeze({ available: true, launcher: kind, tools });
        const binds = rootBinds(workerFiles);
        const evidence = await confirmIsolation(kind, (file, args) => launcherCommand(candidate, binds, file, args), binds);
        if (evidence !== null) return candidate;
      }
      return UNAVAILABLE;
    })();
    probes.set(key, probe);
  }
  return probe;
}
