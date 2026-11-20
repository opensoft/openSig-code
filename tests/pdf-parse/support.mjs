// SPDX-License-Identifier: Apache-2.0
//
// Shared access to the T004 synthetic fixtures for the parser-limits tests (T033).

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateDocument } from '../../scripts/gen-fixtures.mjs';

export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
export const DOCUMENTS = join(REPO, 'fixtures', 'synthetic', 'documents');
export const manifest = JSON.parse(readFileSync(join(DOCUMENTS, 'manifest.json'), 'utf8'));

export function fixtureRecord(file) {
  const record = manifest.documents.find((doc) => doc.file === file);
  if (!record) throw new Error(`no fixture ${file}`);
  return record;
}

/** Fixture bytes: committed files from disk, on-demand documents from the generator. */
export function fixtureBytes(file) {
  const record = fixtureRecord(file);
  return record.committed ? readFileSync(join(DOCUMENTS, file)) : generateDocument(file);
}

export const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

/** Page geometry in the T004 manifest shape. */
export const geometry = (pages) => pages.map(({ number, width, height, rotate, media_box }) => ({ number, width, height, rotate, media_box }));
