// SPDX-License-Identifier: Apache-2.0
//
// OC-09 corpus support (admitted by A-010, request #39, Part E Q2).
// `openssl cms -sign` cannot add an arbitrary signed attribute, so this
// module takes an openssl-made SignedData, inserts the
// opensig-approval-evidence-digest attribute (own DER code) in SET OF order,
// re-signs the new signedAttrs SET with `openssl dgst -sha256 -sign` (RSA
// PKCS#1 v1.5) and re-wraps the structure. corpus.mjs keeps the result only if
// `openssl cms -verify` passes on it AND fails on the old-signature control.

import { OID } from './cms-reader.mjs';
import { DerError, children, compareSetMembers, encodeOid, rawOf, readTlv, tlv } from './der.mjs';
import { dgstSign } from './openssl.mjs';

/** shape: 'single-32' | 'truncated-31' | 'two-values' (malformed variants). */
export function approvalEvidenceAttribute(digest, shape = 'single-32') {
  if (digest.length !== 32) throw new Error('approval-evidence digest must be 32 bytes');
  let values;
  if (shape === 'single-32') values = [tlv(0x04, digest)];
  else if (shape === 'truncated-31') values = [tlv(0x04, digest.subarray(0, 31))];
  else if (shape === 'two-values') values = [tlv(0x04, digest), tlv(0x04, Buffer.alloc(32, 0x5a))].sort(compareSetMembers);
  else throw new Error(`unknown attribute shape ${shape}`);
  return tlv(0x30, encodeOid(OID.approvalEvidenceDigest), tlv(0x31, ...values));
}

const copy = (der, node) => Buffer.from(rawOf(der, node));

export function spliceSignedAttribute(work, signer, der, attribute) {
  const top = readTlv(der, 0);
  if (top.tag !== 0x30 || top.end !== der.length) throw new DerError('splice-contentinfo');
  const [contentType, wrapped] = children(der, top);
  const [signedData] = children(der, wrapped);
  const sdFields = children(der, signedData);
  const signerInfos = sdFields[sdFields.length - 1];
  if (signerInfos.tag !== 0x31) throw new DerError('splice-signer-infos');
  const infos = children(der, signerInfos);
  if (infos.length !== 1) throw new DerError('splice-signer-count');
  const fields = children(der, infos[0]);
  const attrsIndex = fields.findIndex((f) => f.tag === 0xa0);
  const sigIndex = fields.findIndex((f) => f.tag === 0x04);
  if (attrsIndex < 0 || sigIndex !== attrsIndex + 2) throw new DerError('splice-signerinfo-shape');
  const members = children(der, fields[attrsIndex]).map((a) => copy(der, a));
  members.push(attribute);
  members.sort(compareSetMembers);
  const rebuild = (signatureField) => {
    const newFields = fields.map((f, i) => {
      if (i === attrsIndex) return tlv(0xa0, ...members);
      if (i === sigIndex) return signatureField;
      return copy(der, f);
    });
    const newSignedData = tlv(0x30, ...sdFields.slice(0, -1).map((f) => copy(der, f)), tlv(0x31, tlv(0x30, ...newFields)));
    return tlv(0x30, copy(der, contentType), tlv(0xa0, newSignedData));
  };
  // RFC 5652 5.4: the signature covers the DER of the attributes as a SET OF.
  const signature = dgstSign(work, signer, tlv(0x31, ...members));
  return {
    der: rebuild(tlv(0x04, signature)),
    // Negative control (request #39): new attributes, OLD signature; must fail.
    derWithOldSignature: rebuild(copy(der, fields[sigIndex])),
  };
}
