// SPDX-License-Identifier: Apache-2.0
//
// Isolated parse child (T033). Started only by src/pdf/service.ts as
//
//   node --max-old-space-size=<MiB> --permission --allow-fs-read=<src/pdf/>
//        --disallow-code-generation-from-strings src/pdf/worker.ts '<parser limits JSON>'
//
// under an RLIMIT_CPU backstop, with an empty environment. It reads the PDF bytes from
// stdin (bounded by maxBytes), parses them and writes exactly one JSON line to stdout.
// It refuses to parse unless the Node permission model is active with no fs-write,
// child-process or worker grant.

import { Buffer } from 'node:buffer';

import { resolveParserLimits } from './limits.ts';
import { parseDocument } from './parser.ts';

export const ISOLATION_EXIT = 70;

function reply(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function main(): Promise<void> {
  const permission = process.permission;
  const isolation = {
    permission_model: permission !== undefined,
    fs_write: permission?.has('fs.write') ?? true,
    child_process: permission?.has('child') ?? true,
    worker: permission?.has('worker') ?? true,
    environment: Object.keys(process.env).sort(),
  };
  if (!isolation.permission_model || isolation.fs_write || isolation.child_process || isolation.worker) {
    reply({ ok: false, reason: 'isolation', detail: 'the permission model with no fs-write, child-process or worker grant is required' });
    process.exitCode = ISOLATION_EXIT;
    return;
  }

  let limits;
  try {
    limits = resolveParserLimits(JSON.parse(process.argv[2] ?? '{}'));
  } catch {
    reply({ ok: false, reason: 'isolation', detail: 'invalid parser limits argument' });
    process.exitCode = ISOLATION_EXIT;
    return;
  }

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > limits.maxBytes) {
      reply({ ok: false, reason: 'size-limit', detail: `more than ${limits.maxBytes} bytes`, detections: [] });
      process.exitCode = 0;
      return;
    }
    chunks.push(buffer);
  }

  const result = parseDocument(Buffer.concat(chunks, total), limits);
  if (result.ok) reply({ ok: true, report: { ...result.report, isolation } });
  else reply(result);
  process.exitCode = 0;
}

await main();
