// SPDX-License-Identifier: Apache-2.0
//
// Fault entry (T037, WK-03). Launched by testing.ts sealRequestForTests in place
// of the real child, through the same launch. It reads the request header and
// picks its fault from the first byte of the approval-evidence digest
// (request offset 40):
//   1 crash        write half a reply header, then SIGKILL itself
//   2 exit-3       write a complete, well-formed refusal, then exit 3
//   3 hang         never reply (a timer keeps it alive; no busy loop)
//   4 flood        write one byte more than a sealed reply may hold, then wait
//   5 outside      a well-formed sealed reply with consistent digests whose
//                  bytes differ from the request outside the placeholder
//   6 short        a truncated sealed reply, then exit 0
//   7 wrong-digest a well-formed sealed reply whose finalPdfDigest is wrong
//   8 unfilled     the placeholder left all zeros, with a correct digest
// It imports node: built-ins only (its read grant covers this file alone).

import { createHash } from 'node:crypto';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const request = Buffer.concat(chunks);
const mode = request[40];
const documentLength = request.readUInt32BE(8);
const certificateLength = request.readUInt32BE(12);
const offset = request.readUInt32BE(32);
const hexLength = request.readUInt32BE(36);
const document = Buffer.from(request.subarray(72 + certificateLength));
const MAGIC = Buffer.from('OSSEALR1', 'latin1');
const sha256 = (data) => createHash('sha256').update(data).digest();
const keepAlive = () => setInterval(() => {}, 60_000);

function sealedReply(sealed, { badDigest = false } = {}) {
  const header = Buffer.alloc(45);
  MAGIC.copy(header, 0);
  header.writeUInt8(0, 8);
  header.writeUInt32BE(sealed.length, 9);
  const final = sha256(sealed);
  if (badDigest) final[0] ^= 0xff;
  header.set(final, 13);
  return Buffer.concat([header, sealed]);
}

/** The document with lowercase hex that starts like a DER SEQUENCE written over the placeholder. */
function filled() {
  const sealed = Buffer.from(document);
  sealed.write(`30${'ab'.repeat(hexLength / 2 - 1)}`, offset, 'latin1');
  return sealed;
}

switch (mode) {
  case 1:
    process.stdout.write(MAGIC.subarray(0, 4), () => process.kill(process.pid, 'SIGKILL'));
    keepAlive();
    break;
  case 2:
    process.stdout.write(Buffer.concat([MAGIC, Buffer.from([1, 19]), Buffer.from('placeholder-invalid', 'latin1')]));
    process.exitCode = 3;
    break;
  case 3:
    keepAlive();
    break;
  case 4:
    process.stdout.write(Buffer.alloc(45 + documentLength + 1, 0x78));
    keepAlive();
    break;
  case 5: {
    const sealed = filled();
    sealed[0] ^= 0x01;
    process.stdout.write(sealedReply(sealed));
    break;
  }
  case 6:
    process.stdout.write(sealedReply(filled()).subarray(0, 100));
    break;
  case 7:
    process.stdout.write(sealedReply(filled(), { badDigest: true }));
    break;
  case 8:
    process.stdout.write(sealedReply(Buffer.from(document)));
    break;
  default:
    process.exitCode = 9;
}
