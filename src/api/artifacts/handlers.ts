// SPDX-License-Identifier: Apache-2.0
//
// Route handlers of the artifact operations (T016). The server (src/server/app.ts, T031) has
// already applied its shared policy: routing (path parameters match ^[A-Za-z0-9_-]{16,64}$,
// others are 404), the Origin allowlist, operator authentication and the role-by-operation
// matrix (401/403). Each handler reads its path parameter and hands it, with the principal,
// to the app's ArtifactApi (api.ts).
//
//   readVerification  GET /v1/envelopes/{envelope_id}/verification  200 VerificationReport, ETag
//   downloadFinalPdf  GET /v1/envelopes/{envelope_id}/final-pdf     200 application/pdf, ETag
//   downloadPackage   GET /v1/envelopes/{envelope_id}/package       200 application/zip, ETag
//
// None takes a body or an Idempotency-Key. The ArtifactApi is app-scoped: the server keeps
// one under ARTIFACT_API in its locals, and a request that finds none gets a 500 (fail
// closed). withArtifactHandlers() (src/api/routes.ts) installs ARTIFACT_HANDLERS into a
// route registry. The production wiring, which puts an ArtifactApi into the server's locals
// and the map into ROUTES, belongs to the T031 US2 composition slot (row ARTIFACT-ROUTES;
// see routes.ts).

import type { OperationId } from '../auth/matrix.ts';
import { HttpError, type HandlerResult, type RequestContext, type RouteHandler } from '../../server/types.ts';
import { pathId, principalOf } from '../envelopes/request.ts';
import { ARTIFACT_API, ArtifactApi, ArtifactInvariantError, type ArtifactOperation } from './api.ts';

/** The app's ArtifactApi, or a 500 when the server was started without one. */
export function artifactApiOf(ctx: RequestContext): ArtifactApi {
  const api = ctx.locals.get(ARTIFACT_API);
  if (!(api instanceof ArtifactApi)) throw new HttpError(500, 'internal');
  return api;
}

/**
 * Run one read. A broken invariant is logged with its fixed code and the correlation ID, and
 * answers 500 internal, never 409 (request #46 (5)). The server logs a thrown HttpError only
 * in its request line, so the invariant is logged here.
 */
function serve(operation: ArtifactOperation, read: (api: ArtifactApi, ctx: RequestContext) => HandlerResult): RouteHandler {
  return async (ctx) => {
    const api = artifactApiOf(ctx);
    try {
      return read(api, ctx);
    } catch (error) {
      if (!(error instanceof ArtifactInvariantError)) throw error;
      ctx.logger.error('artifact_invariant', { correlation_id: ctx.correlationId, operation, invariant: error.code });
      throw new HttpError(500, 'internal');
    }
  };
}

export const readVerification: RouteHandler = serve('readVerification', (api, ctx) => api.readVerification(principalOf(ctx), pathId(ctx, 'envelope_id')));

export const downloadFinalPdf: RouteHandler = serve('downloadFinalPdf', (api, ctx) => api.downloadFinalPdf(principalOf(ctx), pathId(ctx, 'envelope_id')));

export const downloadPackage: RouteHandler = serve('downloadPackage', (api, ctx) => api.downloadPackage(principalOf(ctx), pathId(ctx, 'envelope_id')));

/** The T016 operations and their handlers. */
export const ARTIFACT_HANDLERS: Readonly<Partial<Record<OperationId, RouteHandler>>> = Object.freeze({
  readVerification,
  downloadFinalPdf,
  downloadPackage,
});
