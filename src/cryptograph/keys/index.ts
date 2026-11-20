// SPDX-License-Identifier: Apache-2.0
//
// Seal key custody (T013). Development only: the file-backed adapter. A
// managed custodian (a release gate) would implement the same SealSigner.

export {
  loadDevelopmentSealKey,
  MAX_KEY_FILE_BYTES,
  MIN_KEY_FILE_BYTES,
  refuseKeyMaterialInProcess,
  SEAL_KEY_MODULUS_BITS,
  SEAL_KEY_PUBLIC_EXPONENT,
  SealKeyError,
  type SealKeyErrorCode,
  type SealKeySource,
  type SealSigner,
} from './development-key.ts';
