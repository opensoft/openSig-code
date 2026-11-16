// SPDX-License-Identifier: Apache-2.0
//
// Streaming request bodies with limits (T031): JSON at most 256 KiB, PDF at most 10 MiB.
// - A declared Content-Length over the limit is a 413 before any byte is read.
// - Otherwise bytes are counted as they arrive, and the first chunk past the limit is a
//   413: reading stops (the request is paused) and nothing past the limit is buffered or
//   parsed. The error response closes the connection after a bounded lingering discard
//   (src/server/app.ts), so the client can read the 413 before the socket closes.
// - The media type must match (415 unsupported_media_type); JSON must be valid UTF-8 and
//   valid JSON (400 invalid_request).
// - Timing (A-010 LBR4-1, SEC-10): while a reader waits for body bytes a per-request timer
//   runs. It fires after `idleMs` without new bytes, or once the time spent waiting passes
//   `graceMs` and the body has arrived at less than `minBytesPerSecond` on average over that
//   time. Either is a 408 (HttpError with `connection: close`), reported through
//   state.onTimeout at once, so the server answers even if a handler is still running. Time
//   the server itself spends not reading is not counted against the client.
// Chunks are pulled in paused mode, so an early stop never destroys the socket before the
// error response is written.

import type { IncomingMessage } from 'node:http';
import { performance } from 'node:perf_hooks';

import { BODY_IDLE_TIMEOUT_MS, BODY_MIN_BYTES_PER_SECOND, BODY_RATE_GRACE_MS } from './config.ts';
import { HttpError } from './types.ts';

export interface BodyTiming {
  readonly idleMs: number;
  readonly graceMs: number;
  readonly minBytesPerSecond: number;
}

export const DEFAULT_BODY_TIMING: BodyTiming = Object.freeze({
  idleMs: BODY_IDLE_TIMEOUT_MS,
  graceMs: BODY_RATE_GRACE_MS,
  minBytesPerSecond: BODY_MIN_BYTES_PER_SECOND,
});

export interface BodyState {
  /** Bytes read from the request so far. */
  bytesRead: number;
  /** True once the body was read to its end. */
  consumed: boolean;
  /** True once a body reader was started. */
  started: boolean;
  /** Milliseconds spent waiting for body bytes (the time the minimum rate applies to). */
  waitedMs: number;
  /** True once the idle or minimum-rate timer fired. */
  timedOut: boolean;
  /** Called once, when the idle or minimum-rate timer fires. */
  onTimeout: ((error: HttpError) => void) | null;
}

export function createBodyState(): BodyState {
  return { bytesRead: 0, consumed: false, started: false, waitedMs: 0, timedOut: false, onTimeout: null };
}

function bodyTimeout(): HttpError {
  return new HttpError(408, 'invalid_request', { headers: { connection: 'close' } });
}

function mediaType(req: IncomingMessage): string {
  return String(req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase() ?? '';
}

function declaredLength(req: IncomingMessage): number | null {
  const header = req.headers['content-length'];
  if (header === undefined) return null;
  if (!/^\d{1,15}$/.test(header)) throw new HttpError(400, 'invalid_request');
  return Number(header);
}

/** Throw 413 when the declared length already exceeds `limit`. */
export function checkDeclaredLength(req: IncomingMessage, limit: number): void {
  const declared = declaredLength(req);
  if (declared !== null && declared > limit) throw new HttpError(413, 'payload_too_large');
}

function nextChunk(req: IncomingMessage, state: BodyState, timing: BodyTiming): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    if (state.timedOut) {
      reject(bodyTimeout());
      return;
    }
    if (req.readableEnded) {
      resolve(null);
      return;
    }
    let timer: NodeJS.Timeout | null = null;
    let waitingSince = 0;
    const cleanup = (): void => {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
        state.waitedMs += performance.now() - waitingSince;
      }
      req.off('readable', attempt);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('aborted', onAborted);
    };
    function attempt(): boolean {
      const chunk = req.read() as Buffer | null;
      if (chunk !== null) {
        cleanup();
        resolve(chunk);
        return true;
      }
      return false;
    }
    const onEnd = (): void => {
      cleanup();
      resolve(null);
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onAborted = (): void => {
      cleanup();
      reject(new HttpError(400, 'invalid_request'));
    };
    req.on('readable', attempt);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('aborted', onAborted);
    if (attempt()) return;
    if (req.readableEnded) {
      cleanup();
      resolve(null);
      return;
    }
    // Nothing buffered: wait, under the idle and minimum-rate deadlines.
    const rateDeadline = Math.max(timing.graceMs, (state.bytesRead / timing.minBytesPerSecond) * 1000);
    const delay = Math.max(0, Math.min(timing.idleMs, rateDeadline - state.waitedMs));
    waitingSince = performance.now();
    timer = setTimeout(() => {
      cleanup();
      state.timedOut = true;
      req.pause();
      const error = bodyTimeout();
      state.onTimeout?.(error);
      reject(error);
    }, delay);
  });
}

/** The request body as chunks, bounded by `limit`. */
export async function* boundedChunks(req: IncomingMessage, limit: number, state: BodyState, timing: BodyTiming = DEFAULT_BODY_TIMING): AsyncGenerator<Buffer> {
  state.started = true;
  checkDeclaredLength(req, limit);
  for (;;) {
    const chunk = await nextChunk(req, state, timing);
    if (chunk === null) {
      state.consumed = true;
      return;
    }
    state.bytesRead += chunk.length;
    if (state.bytesRead > limit) {
      req.pause();
      throw new HttpError(413, 'payload_too_large');
    }
    yield chunk;
  }
}

export async function readJsonBody(req: IncomingMessage, limit: number, state: BodyState, timing: BodyTiming = DEFAULT_BODY_TIMING): Promise<unknown> {
  if (mediaType(req) !== 'application/json') throw new HttpError(415, 'unsupported_media_type');
  const chunks: Buffer[] = [];
  for await (const chunk of boundedChunks(req, limit, state, timing)) chunks.push(chunk);
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    throw new HttpError(400, 'invalid_request');
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HttpError(400, 'invalid_request');
  }
}

export function pdfBody(req: IncomingMessage, limit: number, state: BodyState, timing: BodyTiming = DEFAULT_BODY_TIMING): AsyncIterable<Uint8Array> {
  if (mediaType(req) !== 'application/pdf') throw new HttpError(415, 'unsupported_media_type');
  return boundedChunks(req, limit, state, timing);
}
