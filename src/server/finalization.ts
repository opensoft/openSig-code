// SPDX-License-Identifier: Apache-2.0
//
// The US2 composition's startup settings (T031 US2 composition slot; A-010 row ARTIFACT-ROUTES,
// requests #39 Part F, #44 and #46; the checks below are the T031 line's request #81 note, which
// confirmed PEM only, no symbolic links, an optional seal pair and at least one anchor in a set
// anchors file): T015's fault-hook flag on the command line (request #86 (4)), then
// OPENSIG_SEAL_KEY_FILE, OPENSIG_SEAL_CERT_FILE and OPENSIG_TRUST_ANCHORS_FILE, checked once by
// startServer (main.ts) before anything is composed. A refusal is a ServerConfigError that names
// the setting (or the flag) and the rule, never the path, a byte of the file, a value from the
// environment or an argument's value.
//
// The seal pair is set together or not at all.
// - Neither set: no finalization runner is composed (FinalizationSettings.seal is null). The
//   server starts and says so (`finalization_not_configured`, and `finalization` on the
//   `listening` line); approved envelopes wait in `finalizing`, their jobs still claimable by a
//   server that has the settings. The artifact and retry routes are served either way.
// - One set without the other: refused.
// - Both set, in this order:
//   1. KEY-02 (T013's refuseKeyMaterialInProcess): refused while PEM private-key text is
//      visible in this process's environment or arguments.
//   2. The key file's custody, never its bytes. The key never enters the main process (request
//      #39 Q6): T037's worker child reads it through T013's adapter at each attempt. Here: the
//      path exists; it is not a symbolic link and names a regular file, so a FIFO or device is
//      refused before anything opens it; it opens through the runner's own openSealKey()
//      (O_NOFOLLOW, O_NONBLOCK), the open every attempt makes; on that descriptor it is a
//      regular file owned by the server user, with no group or other permission bit (an
//      owner-only file, for example 0600 or 0400; request #30's rule), holding T013's
//      MIN_KEY_FILE_BYTES to MAX_KEY_FILE_BYTES. The descriptor is closed with nothing read.
//      The key's type, modulus, exponent and match with the certificate stay T013's and T037's
//      checks in the child at seal time (the retryable key-* reasons).
//   3. The certificate file: present, not a symbolic link, a regular file of at most
//      SEAL_CERT_FILE_LIMIT bytes of UTF-8 text holding exactly one PEM CERTIFICATE block and
//      nothing else (T014's splitPemCertificates: no private key, no other block, no stray
//      text). X509Certificate parses it, and T013's parseSignerCertificate accepts its DER: at
//      most MAX_SIGNER_CERTIFICATE_BYTES, an RSA key with a 3072-bit modulus and exponent
//      65537. Its validity period is not judged here: trust and time are T014's.
// The anchors file is optional and checked whether or not the seal pair is set. When set: present,
// not a symbolic link, a regular file of at most VERIFIER_LIMITS.maxAnchorsFileBytes of UTF-8
// text that T014's splitPemCertificates accepts (one to maxAnchors CERTIFICATE blocks and
// nothing else) and whose every item T014's parseAnchors accepts. So a configuration T014 would
// refuse at verification (anchors-invalid, a non-retryable failure of every attempt) is refused
// here instead. Without it there are no anchors, and trust is never `trusted`.
//
// developmentCertificate is always true: production key custody is the open
// `trusted-certificate-key-custody` gate, so every seal this MVP makes is a development seal.
//
// The fault-hook flag (request #86 (4), the T031 line): T015's fault hook
// (src/domain/finalization/fault-hook.ts) arms itself from the process's own command line at the
// first hook point it reaches (faultPoint reads process.argv), and main.ts ignores extra
// arguments. This server hosts the finalization runner, whose attempts reach those hook points,
// and an armed hook's hold is a synchronous read that would block the event loop. src/server/
// cannot withhold the flag from the hook, so the first startup check refuses it, whether or not
// the seal pair is set: any command-line argument equal to FAULT_HOOK_FLAG or starting with
// `FAULT_HOOK_FLAG=`, well-formed or not (the arguments the hook's parser reads). FAULT_HOOK_FLAG
// is imported read-only from T015's module, and nothing else of it is used here. The refusal
// names the flag and the rule, never the argument's value (which may hold a path). Nothing is
// composed, no listener binds, the runner never starts and the entrypoint exits 1.

import { X509Certificate } from 'node:crypto';
import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readSync, type Stats } from 'node:fs';

import { CertificateError, MAX_SIGNER_CERTIFICATE_BYTES, parseSignerCertificate } from '../cryptograph/cms/index.ts';
import { MAX_KEY_FILE_BYTES, MIN_KEY_FILE_BYTES, refuseKeyMaterialInProcess, SealKeyError } from '../cryptograph/keys/index.ts';
import { FAULT_HOOK_FLAG } from '../domain/finalization/fault-hook.ts';
import { openSealKey } from '../jobs/finalize.ts';
import { splitPemCertificates, VERIFIER_LIMITS, VerifierConfigError } from '../verifier/index.ts';
import { parseAnchors } from '../verifier/trust.ts';
import { ServerConfigError, type ServerConfig } from './config.ts';

/** The read bound of the certificate file: room for the PEM form of the largest certificate T013 accepts. */
export const SEAL_CERT_FILE_LIMIT = 2 * MAX_SIGNER_CERTIFICATE_BYTES;

/** What the composition hands T038's FinalizationRunner as its `seal` option. */
export interface SealSettings {
  readonly keyFile: string;
  readonly certificateDer: Uint8Array;
  readonly developmentCertificate: boolean;
}

export interface FinalizationSettings {
  /** The seal settings, or null when neither seal setting is set (no runner is composed). */
  readonly seal: SealSettings | null;
  /** The anchors' PEM certificates, one per item (T014 splitPemCertificates); empty without the setting. */
  readonly anchors: readonly string[];
}

type SettingName = 'OPENSIG_SEAL_KEY_FILE' | 'OPENSIG_SEAL_CERT_FILE' | 'OPENSIG_TRUST_ANCHORS_FILE';

const OWNER_ONLY = 'an owner-only file, with no group or other permission bit (for example 0600 or 0400)';

function refuse(name: SettingName, reason: string): never {
  throw new ServerConfigError(`${name} refused: ${reason}`);
}

/**
 * The first startup check (request #86 (4); see the header): refused when any argument equals
 * FAULT_HOOK_FLAG or starts with `FAULT_HOOK_FLAG=`, well-formed or not. The refusal names the
 * flag and the rule, never the argument.
 */
function refuseFaultHookFlag(argv: readonly string[]): void {
  const prefix = `${FAULT_HOOK_FLAG}=`;
  if (argv.some((arg) => arg === FAULT_HOOK_FLAG || arg.startsWith(prefix))) {
    throw new ServerConfigError(`${FAULT_HOOK_FLAG} refused: no command-line argument may equal ${FAULT_HOOK_FLAG} or start with ${prefix}, well-formed or not; the flag arms the test fault hook`);
  }
}

/** Before anything opens the path: it exists, is not a symbolic link and names a regular file. */
function inspect(name: SettingName, path: string): void {
  let stat: Stats;
  try {
    stat = lstatSync(path);
  } catch {
    refuse(name, 'the file does not exist or cannot be inspected');
  }
  if (stat.isSymbolicLink()) refuse(name, 'the path must not be a symbolic link');
  if (!stat.isFile()) refuse(name, 'the path must name a regular file');
}

/** One descriptor on the path that does not follow a final link and cannot block; `open` is the opener. */
function openChecked(name: SettingName, path: string, open: (path: string) => number): number {
  try {
    return open(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ELOOP') refuse(name, 'the path must not be a symbolic link');
    refuse(name, 'the file cannot be opened');
  }
}

/** Steps 1 and 2: KEY-02, then the key file's custody on its descriptor, with nothing read. */
function checkKeyCustody(path: string): void {
  const name = 'OPENSIG_SEAL_KEY_FILE';
  try {
    refuseKeyMaterialInProcess();
  } catch (error) {
    if (error instanceof SealKeyError) refuse(name, error.message);
    throw error;
  }
  inspect(name, path);
  const fd = openChecked(name, path, openSealKey);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) refuse(name, 'the path must name a regular file');
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) refuse(name, 'the file must be owned by the server user');
    if ((stat.mode & 0o077) !== 0) refuse(name, `the file is group- or other-accessible; it must be ${OWNER_ONLY}`);
    if (stat.size < MIN_KEY_FILE_BYTES || stat.size > MAX_KEY_FILE_BYTES) refuse(name, `the file must hold ${MIN_KEY_FILE_BYTES} to ${MAX_KEY_FILE_BYTES} bytes`);
  } finally {
    closeSync(fd);
  }
}

const openText = (path: string): number => openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);

/** A settings file of 1 to `limit` bytes, read whole through one checked descriptor, as UTF-8 text. */
function readText(name: SettingName, path: string, limit: number): string {
  inspect(name, path);
  const fd = openChecked(name, path, openText);
  let bytes: Buffer;
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) refuse(name, 'the path must name a regular file');
    if (stat.size < 1 || stat.size > limit) refuse(name, `the file must hold 1 to ${limit} bytes`);
    bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const read = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (read === 0) break;
      offset += read;
    }
    if (offset !== bytes.length) refuse(name, 'the file changed while it was read');
  } finally {
    closeSync(fd);
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    refuse(name, 'the file is not UTF-8 text');
  }
}

/** Step 3: the signer certificate's DER, from exactly one PEM CERTIFICATE block T013 accepts. */
function loadCertificate(path: string): Uint8Array {
  const name = 'OPENSIG_SEAL_CERT_FILE';
  const text = readText(name, path, SEAL_CERT_FILE_LIMIT);
  const single = 'the file must hold exactly one PEM certificate and nothing else';
  let items: string[];
  try {
    items = splitPemCertificates(text);
  } catch (error) {
    if (error instanceof VerifierConfigError) refuse(name, single);
    throw error;
  }
  const [pem] = items;
  if (items.length !== 1 || pem === undefined) refuse(name, single);
  let der: Uint8Array;
  try {
    der = new Uint8Array(new X509Certificate(pem).raw);
  } catch {
    refuse(name, 'the certificate cannot be parsed');
  }
  try {
    parseSignerCertificate(der);
  } catch (error) {
    if (error instanceof CertificateError) refuse(name, `the certificate is not usable for the seal (${error.code})`);
    throw error;
  }
  return der;
}

/** The anchors' PEM items, each accepted by T014's parseAnchors; none without the setting. */
function loadAnchors(path: string | null): readonly string[] {
  if (path === null) return Object.freeze([]);
  const name = 'OPENSIG_TRUST_ANCHORS_FILE';
  const text = readText(name, path, VERIFIER_LIMITS.maxAnchorsFileBytes);
  try {
    // splitPemCertificates refuses a file with no CERTIFICATE block; the check below states the
    // rule here too: a set anchors file holds at least one certificate (request #81 (10)), since
    // leaving the setting unset is how a server runs with no anchors.
    const items = splitPemCertificates(text);
    if (items.length < 1) throw new VerifierConfigError('anchors-invalid');
    parseAnchors(items);
    return Object.freeze(items);
  } catch (error) {
    if (error instanceof VerifierConfigError) refuse(name, `anchors-invalid: the file must hold 1 to ${VERIFIER_LIMITS.maxAnchors} PEM certificates and nothing else`);
    throw error;
  }
}

/**
 * The US2 startup checks (see the header): first the fault-hook flag on this process's own command
 * line (process.argv, the one the hook reads), then the seal pair, then the anchors file. Called
 * by startServer after the challenge key and before the authenticator, the database or the blob
 * store, so a refusal composes nothing.
 */
export function loadFinalizationSettings(config: ServerConfig): FinalizationSettings {
  refuseFaultHookFlag(process.argv);
  const { sealKeyFile, sealCertFile } = config;
  let seal: SealSettings | null = null;
  if (sealKeyFile !== null || sealCertFile !== null) {
    if (sealKeyFile === null) refuse('OPENSIG_SEAL_KEY_FILE', 'the setting is required when OPENSIG_SEAL_CERT_FILE is set (the two are set together or not at all)');
    if (sealCertFile === null) refuse('OPENSIG_SEAL_CERT_FILE', 'the setting is required when OPENSIG_SEAL_KEY_FILE is set (the two are set together or not at all)');
    checkKeyCustody(sealKeyFile);
    seal = Object.freeze({ keyFile: sealKeyFile, certificateDer: loadCertificate(sealCertFile), developmentCertificate: true });
  }
  return Object.freeze({ seal, anchors: loadAnchors(config.trustAnchorsFile) });
}
