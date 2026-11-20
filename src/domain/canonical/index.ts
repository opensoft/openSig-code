// SPDX-License-Identifier: Apache-2.0
//
// The project's single RFC 8785 canonical JSON module (T029). Import it for
// every digest over canonical JSON; never write another canonicalizer.

export {
  CanonicalJsonError,
  canonicalBytes,
  canonicalDigest,
  canonicalize,
  MAX_DEPTH,
  serializeNumber,
  serializeString,
  type JsonValue,
} from './canonicalize.ts';
export { parseJson } from './parse.ts';
