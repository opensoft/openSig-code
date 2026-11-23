// SPDX-License-Identifier: Apache-2.0
//
// T004 DV-02: every fixture document carries the structure its manifest declares, checked
// with an independent reader (tests/dev/pdf-structure.mjs), and the fixtures are synthetic
// only: reserved domains, no keys or credentials, no images and no embedded fonts.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { generateDocument, MAX_DOCUMENT_BYTES, MAX_DOCUMENT_PAGES } from '../../scripts/gen-fixtures.mjs';
import { isSecretName } from '../../scripts/no-secrets.mjs';
import { int, name, numbers, objectText, readPages, readStartxref, readXref, ref, refs, text } from './pdf-structure.mjs';

const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const FIXTURES = join(REPO, 'fixtures', 'synthetic');
const manifest = JSON.parse(readFileSync(join(FIXTURES, 'documents', 'manifest.json'), 'utf8'));
const identities = JSON.parse(readFileSync(join(FIXTURES, 'identities', 'identities.json'), 'utf8'));

function documentBytes(doc) {
  return doc.committed ? readFileSync(join(FIXTURES, 'documents', doc.file)) : generateDocument(doc.file);
}

const byFile = new Map(manifest.documents.map((doc) => [doc.file, doc]));
const well = (doc) => doc.kind !== 'malformed';

/** Byte positions where two equal-length buffers differ. */
function diffPositions(a, b) {
  assert.equal(a.length, b.length, 'patch variants keep the base length');
  const positions = [];
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) positions.push(i);
  return positions;
}

test('[DV-02] the fixture set covers every structural variant the task requires', () => {
  const kinds = new Set(manifest.documents.map((doc) => doc.kind));
  for (const kind of ['multi-page', 'rotated', 'malformed', 'encrypted-flag', 'already-signed', 'oversized', 'page-limit']) {
    assert.ok(kinds.has(kind), `kind ${kind} is present`);
  }
  assert.ok(manifest.documents.some((doc) => doc.kind === 'multi-page' && doc.pages.length >= 2));
  assert.ok(manifest.documents.some((doc) => doc.kind === 'rotated' && doc.pages.some((page) => page.rotate !== 0)));
  assert.ok(manifest.documents.some((doc) => doc.kind === 'page-limit' && doc.pages.length === MAX_DOCUMENT_PAGES + 1 && doc.expect.outcome === 'reject'));
  assert.ok(manifest.documents.some((doc) => doc.kind === 'page-limit' && doc.pages.length === MAX_DOCUMENT_PAGES && doc.expect.outcome === 'accept'));
  assert.equal(byFile.get('oversized.pdf').bytes, MAX_DOCUMENT_BYTES + 1);
  assert.equal(byFile.get('size-at-limit.pdf').bytes, MAX_DOCUMENT_BYTES);
  assert.deepEqual(manifest.limits, { max_bytes: 10 * 1024 * 1024, max_pages: 50 });
  for (const doc of manifest.documents) {
    assert.ok(['accept', 'reject'].includes(doc.expect.outcome), `${doc.file} outcome`);
    assert.equal(doc.expect.outcome === 'accept', doc.expect.reason === null, `${doc.file} reason`);
  }
});

test('[DV-02] well-formed documents parse independently with the declared page geometry', () => {
  for (const doc of manifest.documents.filter(well)) {
    const bytes = documentBytes(doc);
    const source = text(bytes);
    assert.ok(source.startsWith('%PDF-1.7\n'), `${doc.file} header`);
    assert.ok(source.endsWith('%%EOF\n'), `${doc.file} trailer end`);
    const { xref, pages } = readPages(bytes);
    assert.equal(xref.sections, 1, `${doc.file} has one revision`);
    assert.equal(source.startsWith('xref', readStartxref(bytes)), doc.xref === 'table', `${doc.file} xref form`);
    for (const num of xref.entries.keys()) objectText(bytes, xref, num);
    assert.deepEqual(
      pages.map(({ object, ...page }) => page),
      doc.pages,
      `${doc.file} page geometry`,
    );
    for (const page of pages) {
      assert.ok([0, 90, 180, 270].includes(page.rotate));
      assert.ok(page.width > 0 && page.height > 0);
    }
  }

  // Rotation inheritance: the rotated fixture mixes inherited, overridden and negative /Rotate.
  const rotated = readPages(documentBytes(byFile.get('rotated-pages.pdf')));
  assert.deepEqual(rotated.pages.map((page) => page.rotate), [90, 270, 180, 0, 270]);
  const ownRotate = rotated.pages.map((page) => int(objectText(documentBytes(byFile.get('rotated-pages.pdf')), rotated.xref, page.object), 'Rotate'));
  assert.deepEqual(ownRotate, [null, null, 180, 0, -90], 'pages 1 and 2 inherit /Rotate from ancestors');

  // The xref-stream agreement packs dictionaries into an object stream.
  const streamed = readXref(documentBytes(byFile.get('agreement-xref-stream.pdf')));
  assert.ok([...streamed.entries.values()].some((entry) => entry.type === 2), 'objects live in an object stream');

  // Size boundaries are byte-exact.
  assert.equal(documentBytes(byFile.get('size-at-limit.pdf')).length, MAX_DOCUMENT_BYTES);
  assert.equal(documentBytes(byFile.get('oversized.pdf')).length, MAX_DOCUMENT_BYTES + 1);
});

test('[DV-02] encrypted-flag and already-signed documents carry their markers', () => {
  const encryptedBytes = documentBytes(byFile.get('encrypted-flag.pdf'));
  const encrypted = readXref(encryptedBytes);
  const encryptNum = ref(encrypted.trailer, 'Encrypt');
  assert.ok(encryptNum !== null, 'trailer names /Encrypt');
  const encryptDict = objectText(encryptedBytes, encrypted, encryptNum);
  assert.equal(name(encryptDict, 'Filter'), 'Standard');
  assert.match(encrypted.trailer, /\/ID\s*\[/);

  const signedBytes = documentBytes(byFile.get('already-signed.pdf'));
  const source = text(signedBytes);
  const { xref, catalog, pages } = readPages(signedBytes);
  assert.match(catalog, /\/SigFlags 3/);
  const [fieldNum] = refs(catalog, 'Fields');
  const field = objectText(signedBytes, xref, fieldNum);
  assert.equal(name(field, 'FT'), 'Sig');
  assert.deepEqual(refs(objectText(signedBytes, xref, pages[0].object), 'Annots'), [fieldNum]);
  const signature = objectText(signedBytes, xref, ref(field, 'V'));
  assert.equal(name(signature, 'Type'), 'Sig');
  assert.equal(name(signature, 'SubFilter'), 'ETSI.CAdES.detached');
  const [start, firstLength, secondStart, secondLength] = numbers(signature, 'ByteRange');
  assert.equal(start, 0);
  assert.equal(source[firstLength], '<', 'first range ends at the /Contents string');
  assert.equal(source[secondStart - 1], '>', 'second range starts after the /Contents string');
  assert.equal(secondStart + secondLength, signedBytes.length, 'second range runs to the end of the file');
  assert.match(source.slice(firstLength + 1, secondStart - 1), /^0+$/, 'the signature value is zero-filled');
});

test('[DV-02] each malformed variant carries exactly its declared defect', () => {
  const malformed = manifest.documents.filter((doc) => doc.kind === 'malformed');
  const checked = new Set();
  const base = documentBytes(byFile.get('single-page.pdf'));
  const checks = {
    'missing-header': (bytes) => {
      assert.notEqual(text(bytes.subarray(0, 5)), '%PDF-');
      assert.deepEqual(diffPositions(base, bytes).every((i) => i < 8), true);
    },
    truncated: (bytes) => {
      assert.ok(bytes.length < base.length);
      assert.ok(base.subarray(0, bytes.length).equals(bytes), 'a prefix of the base');
      assert.equal(text(bytes).includes('startxref'), false);
      assert.equal(text(bytes).includes('%%EOF'), false);
    },
    'startxref-out-of-range': (bytes) => {
      assert.ok(readStartxref(bytes) >= bytes.length);
      assert.throws(() => readXref(bytes), /beyond the end of the file/);
    },
    'xref-offset-mismatch': (bytes) => {
      const xref = readXref(bytes);
      const broken = [...xref.entries.keys()].filter((num) => {
        try {
          objectText(bytes, xref, num);
          return false;
        } catch (error) {
          return /does not point at/.test(error.message);
        }
      });
      assert.equal(broken.length, 1, 'exactly one entry is wrong');
      const positions = diffPositions(base, bytes);
      assert.ok(positions.every((i) => i > readStartxref(base)), 'only the cross-reference table changed');
      assert.throws(() => readPages(bytes), /does not point at/);
    },
    'unterminated-dictionary': (bytes) => {
      const positions = diffPositions(base, bytes);
      assert.equal(positions.length, 2);
      const xref = readXref(bytes);
      const page = [...xref.entries.keys()].map((num) => objectText(bytes, xref, num)).find((body) => /\/Type \/Page /.test(body));
      assert.ok(page.split('<<').length > page.split('>>').length, 'the page dictionary is not closed');
    },
    'stream-length-overrun': (bytes) => {
      assert.equal(diffPositions(base, bytes).length > 0, true);
      const source = text(bytes);
      const match = /\/Length (\d+) >>\nstream\n/.exec(source);
      const dataStart = match.index + match[0].length;
      const declaredEnd = dataStart + Number(match[1]);
      const actualEnd = source.indexOf('\nendstream', dataStart);
      assert.ok(declaredEnd > actualEnd, 'the declared length runs past endstream');
    },
    'xref-prev-cycle': (bytes) => {
      assert.ok(bytes.subarray(0, base.length).equals(base), 'an update appended to the base');
      const trailers = text(bytes).match(/trailer\n<<[^]*?>>\nstartxref\n\d+/g);
      const last = trailers.at(-1);
      assert.equal(int(last, 'Prev'), readStartxref(bytes), '/Prev names its own section');
      assert.throws(() => readXref(bytes), /\/Prev cycle/);
    },
    'page-tree-cycle': (bytes) => {
      readXref(bytes);
      assert.throws(() => readPages(bytes), /page tree revisits/);
    },
  };
  for (const doc of malformed) {
    assert.equal(doc.expect.reason, 'malformed');
    assert.equal(doc.pages, null);
    const check = checks[doc.defect];
    assert.ok(check, `a check exists for defect ${doc.defect}`);
    if (doc.derived_from !== null) assert.equal(doc.derived_from, 'single-page.pdf');
    check(documentBytes(doc));
    checked.add(doc.defect);
  }
  assert.deepEqual([...checked].sort(), Object.keys(checks).sort(), 'every defect check ran');
});

test('[DV-02] fixtures are synthetic only: reserved domains, no keys, images or embedded fonts', () => {
  const forbidden = [
    /-----BEGIN/,
    /\/Subtype\s*\/Image/,
    /\/XObject/,
    /\/FontFile/,
    /\/EmbeddedFile/,
    /\/JavaScript/,
    /\/JS\b/,
    /\/Launch/,
    /\/RichMedia/,
    /\/URI\b/,
  ];
  for (const doc of manifest.documents) {
    const source = text(documentBytes(doc));
    for (const pattern of forbidden) assert.doesNotMatch(source, pattern, `${doc.file} must not contain ${pattern}`);
    for (const [, font] of source.matchAll(/\/BaseFont\s*\/([A-Za-z0-9-]+)/g)) assert.equal(font, 'Helvetica', `${doc.file} font`);
    for (const [, domain] of source.matchAll(/[A-Za-z0-9._-]+@([A-Za-z0-9.-]+)/g)) {
      assert.ok(domain.endsWith('.test') || domain === 'example.com', `${doc.file} mentions a non-reserved domain`);
    }
  }

  assert.equal(identities.synthetic, true);
  const keys = [];
  const strings = [];
  const walk = (value) => {
    if (Array.isArray(value)) value.forEach(walk);
    else if (value && typeof value === 'object') {
      for (const [key, inner] of Object.entries(value)) {
        keys.push(key);
        walk(inner);
      }
    } else if (typeof value === 'string') strings.push(value);
  };
  walk(identities);
  for (const key of keys) {
    assert.equal(isSecretName(key), false, `identities key ${key} looks like a secret name`);
    assert.doesNotMatch(key, /jwk|token|private|certificate|credential/i, `identities key ${key}`);
  }
  for (const value of strings) {
    for (const [, domain] of value.matchAll(/@([A-Za-z0-9.-]+)$/g)) assert.ok(domain.endsWith('.test') || domain === 'example.com', 'email domain');
    for (const [, host] of value.matchAll(/^https?:\/\/([^/:]+)/g)) assert.ok(host.endsWith('.test'), 'URL host');
    assert.doesNotMatch(value, /-----BEGIN|eyJ[A-Za-z0-9_-]{10,}\./, 'no PEM blocks or JWT-shaped values');
  }

  const idPattern = /^[A-Za-z0-9_-]{16,64}$/;
  assert.equal(identities.tenants.length, 2, 'two tenants for cross-tenant cases');
  const ids = new Set();
  for (const tenant of identities.tenants) {
    for (const id of [tenant.id, ...tenant.operators.map((op) => op.id), ...tenant.recipients.map((r) => r.id)]) {
      assert.match(id, idPattern);
      assert.equal(ids.has(id), false, `identifier ${id} is unique`);
      ids.add(id);
    }
    const roles = tenant.operators.flatMap((op) => op.roles.map((role) => `${op.kind}:${role}`));
    for (const needed of ['human-operator:sender', 'human-operator:tenant_admin', 'service:service']) assert.ok(roles.includes(needed), `${tenant.id} has ${needed}`);
    for (const op of tenant.operators) {
      if (op.kind === 'service') assert.deepEqual(op.roles, ['service'], 'a service principal never holds sender or tenant_admin');
      else assert.equal(op.roles.includes('service'), false);
    }
    assert.deepEqual(tenant.recipients.map((r) => r.ordinal), [1, 2]);
  }
});
