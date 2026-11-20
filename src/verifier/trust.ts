// SPDX-License-Identifier: Apache-2.0
//
// Trust evaluation for the shipped verifier (T014). Trust is judged against the
// configured anchors ONLY. No default, system, bundled or environment store is
// ever consulted: this module reads no `node:tls` root list and no CA file, and
// VB-01 keeps it that way (the import allowlist and the store-name denylist).
//
// Where anchors come from (request #44): the setting OPENSIG_TRUST_ANCHORS_FILE,
// a regular file of PEM certificates that T038 reads (validated at startup) and
// passes in; splitPemCertificates() turns its text into anchor items. The
// verifier reads no file itself. Without the setting there are no anchors, and
// trust is never `trusted`.
//
// trust_anchor_ref is the lowercase hex SHA-256 of the DER of the anchor
// certificate the chain ends at, and null unless trust is `trusted`.
//
// Anchor configuration (row T012-ANCHORS, the product side):
// - omitted (undefined) means no anchors, so nothing is `trusted`;
// - null, a non-array, an empty or oversized item, an item that is not one
//   parsable certificate, a PEM bundle, or any text naming a private key is
//   REFUSED with VerifierConfigError('anchors-invalid'). A refused configuration
//   never yields a verdict, so it can never yield `trusted`.
//
// Path building, bounded by maxChainDepth and maxCertificates:
// - the signer certificate must be inside its validity period at the
//   validation time the caller supplies (the verifier reads no clock);
// - a signer that is byte-identical to an anchor is trusted directly;
// - otherwise each step needs an issuer that the child names (checkIssued),
//   whose key verifies the child's signature (verify), that is a CA (ca) and
//   valid at the validation time. A step may end on an anchor; it may pass
//   through certificates embedded in the CMS, which are never anchors.
// Key usage and extended key usage are not checked, as the oracle's trust call
// uses `-purpose any`. Revocation is not checked (`not-checked`).

import { Buffer } from 'node:buffer';
import { createHash, X509Certificate } from 'node:crypto';
import { VerifierConfigError } from './errors.ts';
import { VERIFIER_LIMITS } from './limits.ts';

export interface TrustAnchor {
  readonly certificate: X509Certificate;
  /** Lowercase SHA-256 hex of the anchor's DER: the report's trust_anchor_ref. */
  readonly sha256: string;
}

export const TRUST_DETAILS = [
  'anchor-direct',
  'anchor-chain',
  'no-anchor-configured',
  'no-path-to-anchor',
  'signer-outside-validity',
] as const;

export type TrustDetail = (typeof TRUST_DETAILS)[number];

export interface TrustResult {
  readonly trusted: boolean;
  readonly anchorRef: string | null;
  readonly detail: TrustDetail;
}

function refuse(): never {
  throw new VerifierConfigError('anchors-invalid');
}

/** Parse the configured anchors; throws VerifierConfigError('anchors-invalid'). */
export function parseAnchors(value: unknown): readonly TrustAnchor[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > VERIFIER_LIMITS.maxAnchors) refuse();
  return value.map((item: unknown) => {
    let input: Buffer;
    if (typeof item === 'string') input = Buffer.from(item, 'utf8');
    else if (item instanceof Uint8Array) input = Buffer.from(item);
    else return refuse();
    if (input.length === 0 || input.length > VERIFIER_LIMITS.maxAnchorBytes) refuse();
    const text = input.toString('latin1');
    if (text.includes('PRIVATE KEY')) refuse();
    if (text.split('-----BEGIN CERTIFICATE-----').length > 2) refuse();
    let certificate: X509Certificate;
    try {
      certificate = new X509Certificate(input);
    } catch {
      return refuse();
    }
    return { certificate, sha256: createHash('sha256').update(certificate.raw).digest('hex') };
  });
}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----\r?\n([A-Za-z0-9+/=\r\n]+?)-----END \1-----/g;

/**
 * Split the text of an anchors file (OPENSIG_TRUST_ANCHORS_FILE) into one PEM
 * certificate per item, for parseAnchors. The text must hold at least one
 * CERTIFICATE block and nothing but CERTIFICATE blocks and whitespace; a
 * private key, any other block, stray text or an oversized file is refused
 * with VerifierConfigError('anchors-invalid'). Each item is still parsed and
 * checked by parseAnchors.
 */
export function splitPemCertificates(text: unknown): string[] {
  if (typeof text !== 'string' || text.length === 0 || text.length > VERIFIER_LIMITS.maxAnchorsFileBytes) refuse();
  if (text.includes('PRIVATE KEY')) refuse();
  const items: string[] = [];
  let rest = text;
  for (const match of text.matchAll(PEM_BLOCK)) {
    if (match[1] !== 'CERTIFICATE') refuse();
    if (items.length >= VERIFIER_LIMITS.maxAnchors) refuse();
    items.push(`${match[0]}\n`);
    rest = rest.replace(match[0], '');
  }
  if (items.length === 0 || rest.trim().length !== 0) refuse();
  return items;
}

function validAt(certificate: X509Certificate, at: Date): boolean {
  const time = at.getTime();
  return certificate.validFromDate.getTime() <= time && time <= certificate.validToDate.getTime();
}

function issuedBy(child: X509Certificate, issuer: X509Certificate, at: Date): boolean {
  return issuer.ca && validAt(issuer, at) && child.checkIssued(issuer) && child.verify(issuer.publicKey);
}

/** Judge trust for a signer whose integrity is already valid. */
export function evaluateTrust(
  signer: X509Certificate,
  embedded: readonly X509Certificate[],
  anchors: readonly TrustAnchor[],
  at: Date,
): TrustResult {
  if (anchors.length === 0) return { trusted: false, anchorRef: null, detail: 'no-anchor-configured' };
  if (!validAt(signer, at)) return { trusted: false, anchorRef: null, detail: 'signer-outside-validity' };
  for (const anchor of anchors) {
    if (Buffer.compare(anchor.certificate.raw, signer.raw) === 0) {
      return { trusted: true, anchorRef: anchor.sha256, detail: 'anchor-direct' };
    }
  }
  const pool = embedded
    .filter((c) => Buffer.compare(c.raw, signer.raw) !== 0)
    .slice(0, VERIFIER_LIMITS.maxCertificates);
  const used = new Set<number>();
  const search = (current: X509Certificate, depth: number): TrustAnchor | null => {
    for (const anchor of anchors) if (issuedBy(current, anchor.certificate, at)) return anchor;
    if (depth >= VERIFIER_LIMITS.maxChainDepth) return null;
    for (let k = 0; k < pool.length; k += 1) {
      const candidate = pool[k];
      if (candidate === undefined || used.has(k) || !issuedBy(current, candidate, at)) continue;
      used.add(k);
      const found = search(candidate, depth + 1);
      if (found !== null) return found;
      used.delete(k);
    }
    return null;
  };
  const anchor = search(signer, 1);
  if (anchor === null) return { trusted: false, anchorRef: null, detail: 'no-path-to-anchor' };
  return { trusted: true, anchorRef: anchor.sha256, detail: 'anchor-chain' };
}
