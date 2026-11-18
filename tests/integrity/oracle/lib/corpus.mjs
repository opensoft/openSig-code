// SPDX-License-Identifier: Apache-2.0
//
// Builds the T012 oracle corpus at runtime from the structural descriptors in
// fixtures/synthetic/integrity/cases.json. No PDF, key or certificate is
// committed; everything is generated inside the caller's work directory.
// Public (T014): loadCaseManifest, prepareMaterial, buildCorpus.
// A failed build throws: the run stops, and no case is ever skipped.

import { readFileSync } from 'node:fs';
import { approvalEvidenceAttribute, spliceSignedAttribute } from './evidence-splice.mjs';
import {
  BASE_TEXT, SIGNING_DATE, appendSignatureRevision, appendUpdateRevision, buildBaseRevision,
  embedCms, naturalByteRange, rangesOf, writeByteRange,
} from './pdf-builder.mjs';
import { cmsSignDetached, cmsVerifyDetached, generateRsaKey, issueCertificate, selfSignedCertificate } from './openssl.mjs';
import { sha256, sha256Hex } from './oracle.mjs';

const MANIFEST_URL = new URL('../../../../fixtures/synthetic/integrity/cases.json', import.meta.url);

export function loadCaseManifest() {
  return JSON.parse(readFileSync(MANIFEST_URL, 'utf8'));
}

/** Synthetic approval-evidence digest: SHA-256 of a descriptor label. */
export function syntheticDigest(label) {
  return sha256(Buffer.from(`opensig-oracle synthetic approval manifest:${label}`, 'utf8'));
}

/** Runtime development signers and anchor sets (never committed). */
export function prepareMaterial(work) {
  const selfKeyPath = generateRsaKey(work, 'self-signed');
  const selfCertPath = selfSignedCertificate(work, {
    keyPath: selfKeyPath, label: 'self-signed', subject: '/O=openSig synthetic/CN=oracle self-signed development seal',
    extensions: 'oracle_self_signed', serial: '0x5E1F01',
  });
  const caKeyPath = generateRsaKey(work, 'dev-ca');
  const caCertPath = selfSignedCertificate(work, {
    keyPath: caKeyPath, label: 'dev-ca', subject: '/O=openSig synthetic/CN=oracle development CA',
    extensions: 'oracle_ca', serial: '0x0CA001',
  });
  const leafKeyPath = generateRsaKey(work, 'dev-leaf');
  const leafCertPath = issueCertificate(work, {
    keyPath: leafKeyPath, label: 'dev-leaf', subject: '/O=openSig synthetic/CN=oracle development seal',
    caCertPath, caKeyPath, serial: '0x1EAF01',
  });
  return {
    signers: {
      'self-signed': { certPath: selfCertPath, keyPath: selfKeyPath },
      'dev-ca-leaf': { certPath: leafCertPath, keyPath: leafKeyPath },
    },
    anchors: { 'dev-ca': [caCertPath], 'self-signed-cert': [selfCertPath], none: [] },
    privateKeyPaths: [selfKeyPath, caKeyPath, leafKeyPath],
  };
}

function applyByteRangeDefect([o1, l1, o2, l2], defect) {
  if (!defect) return [o1, l1, o2, l2];
  const k = defect.bytes;
  if (defect.kind === 'gap-extends-past-contents') return [o1, l1, o2 + k, l2 - k];
  if (defect.kind === 'range1-not-at-zero') return [o1 + k, l1 - k, o2, l2];
  if (defect.kind === 'range2-short-of-revision-end') return [o1, l1, o2, l2 - k];
  throw new Error(`unknown byte_range_defect ${defect.kind}`);
}

function replaceAt(bytes, index, text) {
  const out = Buffer.from(bytes);
  out.write(text, index, 'latin1');
  return out;
}

function applyMutation(signed, sigRev, der, mutation) {
  const s = signed.toString('latin1');
  const { contentsStart, contentsEnd } = sigRev.layout;
  switch (mutation.kind) {
    case 'none':
      return signed;
    case 'flip-in-range1-text': {
      const at = s.indexOf(`(${BASE_TEXT})`) + 1;
      if (at <= 0 || at >= contentsStart) throw new Error('range-1 marker not found before /Contents');
      return replaceAt(signed, at, s[at] === 'S' ? 's' : 'S');
    }
    case 'flip-in-range2-date': {
      const at = s.indexOf(`/M (${SIGNING_DATE})`) + `/M (${SIGNING_DATE}`.length - 2;
      if (at < contentsEnd) throw new Error('range-2 marker not found after /Contents');
      return replaceAt(signed, at, s[at] === '0' ? '1' : '0');
    }
    case 'append-revision':
      return appendUpdateRevision({ ...sigRev, bytes: signed }, mutation.variant).bytes;
    case 'contents-padding': {
      const at = contentsEnd - 2;
      if (at < contentsStart + 1 + der.length * 2) throw new Error('no padding left to change');
      return replaceAt(signed, at, '1');
    }
    case 'contents-der-last-byte': {
      const at = contentsStart + 1 + (der.length - 1) * 2;
      const value = (Number.parseInt(s.slice(at, at + 2), 16) ^ 0x01).toString(16).padStart(2, '0').toUpperCase();
      return replaceAt(signed, at, value);
    }
    case 'truncate-tail':
      return Buffer.from(signed.subarray(0, signed.length - mutation.bytes));
    case 'truncate-inside-contents':
      return Buffer.from(signed.subarray(0, contentsStart + 1 + mutation.keep_hex_digits));
    default:
      throw new Error(`unknown mutation ${mutation.kind}`);
  }
}

/** Build one corpus entry. originalDigest is the signed file before mutation. */
export function buildCase(work, material, d) {
  const signer = material.signers[d.signer];
  if (!signer) throw new Error(`${d.id}: unknown signer ${d.signer}`);
  const base = buildBaseRevision({ seed: d.id, xref: d.base?.xref ?? 'table', defects: d.base?.defect ?? {} });
  const sigRev = appendSignatureRevision(base, { defects: d.structure_defect ?? {} });
  const byteRange = applyByteRangeDefect(naturalByteRange(sigRev.bytes, sigRev.layout), d.byte_range_defect);
  const prepared = writeByteRange(sigRev.bytes, sigRev.layout, byteRange);
  const ranges = rangesOf(prepared, byteRange);
  let der = cmsSignDetached(work, signer, ranges);
  let controls = null;
  if (d.signing?.approval_evidence) {
    const ev = d.signing.approval_evidence;
    const spliced = spliceSignedAttribute(work, signer, der, approvalEvidenceAttribute(syntheticDigest(ev.label), ev.shape));
    // OpenSSL, not the splice, is the judge of both results (request #39).
    controls = {
      splicedVerifies: cmsVerifyDetached(work, spliced.der, ranges).ok,
      oldSignatureRejected: !cmsVerifyDetached(work, spliced.derWithOldSignature, ranges).ok,
    };
    if (!controls.splicedVerifies) throw new Error(`${d.id}: spliced SignedData does not verify under openssl; run stopped`);
    if (!controls.oldSignatureRejected) throw new Error(`${d.id}: negative control verified with the old signature; run stopped`);
    der = spliced.der;
  }
  const signed = embedCms(prepared, sigRev.layout, der);
  return {
    descriptor: d,
    bytes: applyMutation(signed, sigRev, der, d.mutation),
    originalDigest: sha256Hex(signed),
    der,
    ranges,
    controls,
  };
}

/** The whole corpus, in descriptor order; throws (stops the run) on any failed build. */
export function buildCorpus(work, material, manifest = loadCaseManifest()) {
  return manifest.cases.map((d) => buildCase(work, material, d));
}
