// SPDX-License-Identifier: Apache-2.0
//
// Public surface of the operator envelope handlers (T034). Typical wiring (T031's US1
// composition slot, row WIRE-US1, does this in src/server/main.ts):
//
//   const ceremony = new RecipientCeremony({ db, blobs, notifier, clock, challengeKey });
//   app.locals.set(RECIPIENT_CEREMONY, ceremony);
//   app.locals.set(ENVELOPE_API, new EnvelopeApi({ db, blobs, ceremony, clock }));
//   createApp({ routes: withEnvelopeHandlers(withRecipientHandlers(ROUTES)), ... });
//
// The route handlers are installed by src/api/routes.ts (withEnvelopeHandlers).

export { ENVELOPE_API, EnvelopeApi, RESEND_ROUTE, type EnvelopeApiOptions, type UploadRequest } from './api.ts';
export { ENVELOPE_HANDLERS, envelopeApiOf } from './handlers.ts';
export { ID_PATTERN, IF_MATCH_PATTERN } from './request.ts';
export { UPLOADS_PER_TENANT, acquireUploadSlot, uploadCapacity, uploadsInFlight, type UploadSlot } from './uploads.ts';
