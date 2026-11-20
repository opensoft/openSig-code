// SPDX-License-Identifier: Apache-2.0
//
// The ONLY module through which T014's tests reach the T012 oracle: its seven
// public exports, as the T012 line lists them. src/verifier/ never imports the
// oracle (VB-01), and the VB-01 test checks that no other T014 test file names
// tests/integrity/oracle/. A change to these exports is a T012 change.

export { ORACLE, checkPdf } from '../../oracle/lib/oracle.mjs';
export { buildCorpus, loadCaseManifest, prepareMaterial } from '../../oracle/lib/corpus.mjs';
export { createWorkDir, removeWorkDir } from '../../oracle/lib/openssl.mjs';
