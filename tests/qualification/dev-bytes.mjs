// SPDX-License-Identifier: Apache-2.0
//
// "Dev bytes not in distributable" check (T027, QL-03): no byte content of a
// package outside the production closure may appear in dist/.
//
// Two findings are reported:
//   - asset-copy: a dist/ file byte-identical to a file of a non-production
//     package (taken from scripts/license-inventory.mjs, which classifies such
//     an owner as shipped by asset copy);
//   - embedded-bytes: a dist/ file that contains, as a substring, the complete
//     content of a file of at least MIN_EMBEDDED_BYTES bytes from a
//     non-production package (for example a bundler inlining a dev tool).

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { buildInventory } from '../../scripts/license-inventory.mjs';

export const MIN_EMBEDDED_BYTES = 64;

function walk(dir, rel, out, { skipNodeModules }) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const path = rel === '' ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) {
      if (!(skipNodeModules && entry.name === 'node_modules')) walk(join(dir, entry.name), path, out, { skipNodeModules });
    } else if (entry.isFile()) {
      out.push(path);
    }
  }
}

/** Return [{ rule, package, file, dist }] for dev-package bytes found in root/dist. */
export function findDevBytesInDist(root) {
  const distFiles = [];
  walk(join(root, 'dist'), '', distFiles, { skipNodeModules: false });
  if (distFiles.length === 0) return [];

  const inventory = buildInventory(root);
  const findings = [];
  const devRecords = inventory.records.filter((record) => record.installed && !record.reasons.includes('production-closure'));

  for (const record of devRecords) {
    for (const reason of record.reasons) {
      if (reason.startsWith('asset copied into ')) {
        findings.push({ rule: 'asset-copy', package: `${record.name}@${record.version}`, file: null, dist: reason.slice('asset copied into '.length) });
      }
    }
  }

  const dist = distFiles.map((file) => ({ file: `dist/${file}`, bytes: readFileSync(join(root, 'dist', file)) }));
  const largest = Math.max(...dist.map((entry) => entry.bytes.length));
  for (const record of devRecords) {
    const files = [];
    walk(join(root, record.path), '', files, { skipNodeModules: true });
    for (const file of files) {
      const abs = join(root, record.path, file);
      const size = statSync(abs).size;
      if (size < MIN_EMBEDDED_BYTES || size > largest) continue;
      const needle = readFileSync(abs);
      for (const entry of dist) {
        if (entry.bytes.length > needle.length && entry.bytes.indexOf(needle) !== -1) {
          findings.push({ rule: 'embedded-bytes', package: `${record.name}@${record.version}`, file, dist: entry.file });
        }
      }
    }
  }
  return findings;
}
