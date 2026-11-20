// SPDX-License-Identifier: Apache-2.0
//
// The transport seam (T032). A transport only delivers: it has no read, list or lookup
// operation, so nothing that holds a notifier can read mail back.

export interface OutboundMessage {
  /** Envelope sender (a validated addr-spec). */
  readonly from: string;
  /** Envelope recipient (a validated addr-spec). */
  readonly to: string;
  /** The rendered RFC 5322 message: 7-bit ASCII, CRLF line endings. */
  readonly data: Buffer;
  /** Random identifier (hex); carries no capability value. */
  readonly messageId: string;
  readonly date: Date;
}

export interface Transport {
  readonly name: 'spool' | 'smtp';
  deliver(message: OutboundMessage): Promise<void>;
}
