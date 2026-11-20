// SPDX-License-Identifier: Apache-2.0
//
// The review shell and its browser assets (T035), behind the seam in src/server/main.ts:
// loadStaticHandler imports this module when it exists and calls
// createStaticHandler({ config }), or createStaticHandler({ config, distDir }) when a test set
// StartOptions.distDir (row DIST-DIR, request #34: an absolute path, checked by startServer;
// production never sets it, so the repository's dist/ is served). createApp
// (src/server/app.ts) receives the result as `staticHandler` and calls it in exactly two
// places, on the public listener only:
// - GET or HEAD /sign, the openReviewShell route, whose registry handler is null
//   (ctx.operationId === 'openReviewShell'; a null answer there is the app's 501);
// - any other GET or HEAD path that matches no route (ctx.operationId === null; a null
//   answer is the uniform 404).
// The relay listener is built without a static handler, so it never serves either.
//
// Only what the build provenance manifest lists is served, never a path computed from the
// request (traversal safety by construction):
// - The manifest (dist/build-provenance.json, written by scripts/build-ui.mjs) and every
//   output it lists are read when the handler is created, and again at most every
//   RELOAD_INTERVAL_MS while no build is loaded. Links are refused, sizes are bounded and
//   every SHA-256 is checked, together with the asset and build digests; any mismatch and
//   nothing is served.
// - /sign is the shell (autograph/index.html). /assets/<asset digest>/<path> is a non-HTML
//   output. The asset digest covers every asset's path and digest, so a changed asset has
//   a new URL.
// - The lookup is an exact string match in a map built from the manifest: no "..", no
//   percent-decoding, no directory listing, no other digest, no dotfile, no source file.
//
// Headers stay with src/server/app.ts. Every response gets the strict CSP (script-src and
// style-src 'self', no inline or eval, frame-ancestors 'none'), nosniff, no-referrer and
// X-Frame-Options DENY. An asset result carries `cache: 'immutable'` (HandlerResult.cache):
// T031's one caching exception (A-010 row STATIC-CACHE, request #33) turns it into
// `Cache-Control: public, max-age=31536000, immutable`, and only for a 200 from this handler on
// a path that matches no route. The shell (a route, openReviewShell), the 503 and every other
// non-200 keep no-store. This module only sets the flag; it changes no T031 file.
// Without a valid build, /sign is a 503 (the uniform Error body) and asset paths are 404.

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, type Stats } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { ServerConfig } from './config.ts';
import { HttpError, type HandlerResult, type RequestContext, type StaticHandler } from './types.ts';

export const MANIFEST_FILE = 'build-provenance.json';
export const MANIFEST_SCHEMA = 'opensig.ui-build-provenance/1';
export const SHELL_OUTPUT = 'autograph/index.html';
export const ASSET_PREFIX = '/assets/';
export const DEFAULT_DIST_DIR: string = fileURLToPath(new URL('../../dist/', import.meta.url));
export const RELOAD_INTERVAL_MS = 10_000;

const OUTPUT_PREFIX = 'autograph/';
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_OUTPUTS = 512;
const HEX64 = /^[0-9a-f]{64}$/;
const OUTPUT_PATH = /^autograph\/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/){0,8}[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(?:html|js|css|svg)$/;
const ASSET_REQUEST = /^\/assets\/[0-9a-f]{64}\/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/){0,8}[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const HTML_TYPE = 'text/html; charset=utf-8';
const ASSET_TYPES: ReadonlyMap<string, string> = new Map([
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
]);

interface Served {
  readonly bytes: Uint8Array;
  readonly contentType: string;
}

/** A verified build: the shell and the assets by exact request path. */
export interface LoadedBuild {
  readonly buildDigest: string;
  readonly assetDigest: string;
  readonly shell: Served;
  readonly assets: ReadonlyMap<string, Served>;
}

interface OutputRecord {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

/** Why no build is served (the reason names no request content). */
export class StaticBuildError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = 'StaticBuildError';
    this.reason = reason;
  }
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** SHA-256 over sorted `name\0sha256\n` lines, as scripts/build-ui.mjs computes it. */
function digestLines(pairs: ReadonlyArray<readonly [string, string]>): string {
  const hash = createHash('sha256');
  const sorted = [...pairs].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (const [name, digest] of sorted) hash.update(`${name}\0${digest}\n`);
  return hash.digest('hex');
}

function lstatOrNull(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch {
    return null;
  }
}

function readRegular(path: string, max: number, what: string): Buffer {
  const stat = lstatOrNull(path);
  if (stat === null) throw new StaticBuildError(`${what} is missing`);
  if (stat.isSymbolicLink() || !stat.isFile()) throw new StaticBuildError(`${what} is not a regular file`);
  if (stat.size > max) throw new StaticBuildError(`${what} is too large`);
  const bytes = readFileSync(path);
  if (bytes.length !== stat.size) throw new StaticBuildError(`${what} changed while it was read`);
  return bytes;
}

function realDirectory(path: string, what: string): void {
  const stat = lstatOrNull(path);
  if (stat === null || stat.isSymbolicLink() || !stat.isDirectory()) throw new StaticBuildError(`${what} is not a real directory`);
}

function manifestRecords(value: unknown): { outputs: OutputRecord[]; assetDigest: string; buildDigest: string } {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new StaticBuildError('the build manifest is not an object');
  const manifest = value as Record<string, unknown>;
  if (manifest.schema !== MANIFEST_SCHEMA) throw new StaticBuildError('the build manifest has an unknown schema');
  const list = manifest.outputs;
  if (!Array.isArray(list) || list.length === 0 || list.length > MAX_OUTPUTS) throw new StaticBuildError('the build manifest lists no outputs, or too many');
  const seen = new Set<string>();
  const outputs: OutputRecord[] = [];
  for (const item of list as unknown[]) {
    if (typeof item !== 'object' || item === null) throw new StaticBuildError('a build manifest output is not an object');
    const entry = item as Record<string, unknown>;
    const { path, sha256, bytes } = entry;
    if (typeof path !== 'string' || !OUTPUT_PATH.test(path) || seen.has(path)) throw new StaticBuildError('a build manifest output path is unsafe or repeated');
    if (typeof sha256 !== 'string' || !HEX64.test(sha256)) throw new StaticBuildError('a build manifest output digest is malformed');
    if (typeof bytes !== 'number' || !Number.isSafeInteger(bytes) || bytes < 0 || bytes > MAX_OUTPUT_BYTES) throw new StaticBuildError('a build manifest output size is malformed');
    seen.add(path);
    outputs.push({ path, sha256, bytes });
  }
  const { asset_digest: assetDigest, build_digest: buildDigest } = manifest;
  if (typeof assetDigest !== 'string' || !HEX64.test(assetDigest)) throw new StaticBuildError('the build manifest asset digest is malformed');
  if (typeof buildDigest !== 'string' || !HEX64.test(buildDigest)) throw new StaticBuildError('the build manifest build digest is malformed');
  return { outputs, assetDigest, buildDigest };
}

/** Read and verify the build in `distDir`; throws StaticBuildError when it cannot be served. */
export function loadBuild(distDir: string): LoadedBuild {
  const root = resolve(distDir);
  if (lstatOrNull(root) === null) throw new StaticBuildError('no build: the output directory is missing');
  realDirectory(root, 'the output directory');
  const raw = readRegular(join(root, MANIFEST_FILE), MAX_MANIFEST_BYTES, 'the build manifest');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch {
    throw new StaticBuildError('the build manifest is not JSON');
  }
  const { outputs, assetDigest, buildDigest } = manifestRecords(parsed);

  const checkedDirectories = new Set<string>();
  const files = new Map<string, Buffer>();
  let total = 0;
  for (const output of outputs) {
    const segments = output.path.split('/');
    for (let depth = 1; depth < segments.length; depth += 1) {
      const directory = segments.slice(0, depth).join('/');
      if (checkedDirectories.has(directory)) continue;
      realDirectory(join(root, ...segments.slice(0, depth)), `output directory ${directory}`);
      checkedDirectories.add(directory);
    }
    const bytes = readRegular(join(root, ...segments), MAX_OUTPUT_BYTES, `output ${output.path}`);
    total += bytes.length;
    if (total > MAX_TOTAL_BYTES) throw new StaticBuildError('the build outputs are too large');
    if (bytes.length !== output.bytes || sha256Hex(bytes) !== output.sha256) throw new StaticBuildError(`output ${output.path} does not match its manifest digest`);
    files.set(output.path, bytes);
  }

  const shellBytes = files.get(SHELL_OUTPUT);
  if (shellBytes === undefined) throw new StaticBuildError('the build has no shell');
  const assetOutputs = outputs.filter((output) => output.path !== SHELL_OUTPUT);
  const assets = new Map<string, Served>();
  const assetPairs: Array<readonly [string, string]> = [];
  for (const output of assetOutputs) {
    const extension = output.path.slice(output.path.lastIndexOf('.'));
    const contentType = ASSET_TYPES.get(extension);
    if (contentType === undefined) throw new StaticBuildError('only the shell may be HTML');
    const within = output.path.slice(OUTPUT_PREFIX.length);
    assetPairs.push([within, output.sha256]);
    const bytes = files.get(output.path);
    if (bytes === undefined) throw new StaticBuildError(`output ${output.path} was not read`);
    assets.set(`${ASSET_PREFIX}${assetDigest}/${within}`, Object.freeze({ bytes, contentType }));
  }
  if (digestLines(assetPairs) !== assetDigest) throw new StaticBuildError('the asset digest does not match the outputs');
  if (digestLines(outputs.map((output) => [output.path, output.sha256] as const)) !== buildDigest) throw new StaticBuildError('the build digest does not match the outputs');
  return Object.freeze({ buildDigest, assetDigest, shell: Object.freeze({ bytes: shellBytes, contentType: HTML_TYPE }), assets });
}

export interface StaticHandlerOptions {
  /** Passed by src/server/main.ts (the seam); serving needs none of it. */
  readonly config: ServerConfig;
  /**
   * The build output root. main.ts passes StartOptions.distDir here only when a test set it
   * (A-010 row DIST-DIR, request #34), so tests serve a build in a temporary directory.
   * Absent: the repository's dist/ (DEFAULT_DIST_DIR).
   */
  readonly distDir?: string;
}

/** The seam's factory (src/server/main.ts loadStaticHandler). Never throws, even without a build. */
export function createStaticHandler(options: StaticHandlerOptions): StaticHandler {
  const distDir = resolve(options.distDir ?? DEFAULT_DIST_DIR);
  let build: LoadedBuild | null = null;
  let failure = 'not loaded';
  let lastAttempt = 0;
  const attempt = (): void => {
    lastAttempt = Date.now();
    try {
      build = loadBuild(distDir);
    } catch (error) {
      build = null;
      failure = error instanceof StaticBuildError ? error.reason : 'the build could not be read';
    }
  };
  attempt();

  const current = (ctx: RequestContext): LoadedBuild | null => {
    if (build === null && Date.now() - lastAttempt >= RELOAD_INTERVAL_MS) attempt();
    if (build === null) ctx.logger.warn('static_build_unavailable', { reason: failure });
    return build;
  };

  return async (ctx: RequestContext): Promise<HandlerResult | null> => {
    const method = ctx.request.method ?? 'GET';
    if (method !== 'GET' && method !== 'HEAD') return null;
    if (ctx.operationId === 'openReviewShell') {
      const loaded = current(ctx);
      if (loaded === null) throw new HttpError(503, 'internal');
      return { status: 200, body: loaded.shell.bytes, contentType: loaded.shell.contentType };
    }
    if (ctx.operationId !== null || !ASSET_REQUEST.test(ctx.path)) return null;
    const asset = current(ctx)?.assets.get(ctx.path);
    if (asset === undefined) return null;
    return { status: 200, body: asset.bytes, contentType: asset.contentType, cache: 'immutable' };
  };
}
