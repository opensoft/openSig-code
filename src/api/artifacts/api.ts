// SPDX-License-Identifier: Apache-2.0
//
// Artifact retrieval (T016): readVerification, downloadFinalPdf and downloadPackage. When a
// request reaches this module, the server (src/server/app.ts, T031) has already routed it,
// checked the Origin, authenticated the operator and applied the role-by-operation matrix:
// sender, tenant_admin and service, each with artifacts:read, else 401 or 403 before any
// handler. Contract: contracts/http-api.json; data-model.md § FinalArtifact; FR-008; the
// T016 line's request #46 rulings.
//
// The order in every operation:
// 1. The envelope, through the principal's tenant store (T003). Another tenant's envelope is
//    exactly as absent as one that never existed: 404 not_found, with the same body and
//    headers (SC002-09). This comes first, so a refusal never reveals another tenant's
//    state.
// 2. An envelope that is not `completed` is 409 not_completed, whatever its state, and
//    nothing about any artifact is revealed. A FinalArtifact row does not change that.
// 3. The FinalArtifact row, through the same tenant store. Once published the row is
//    immutable.
// 4. The bytes, each served exactly as stored:
//    - final.pdf and the package come from the blob store by their recorded refs (T028
//      readRef verifies the digest and treats another tenant's ref as absent), checked
//      again against the row's digest;
//    - the report is the verification_reports row of the artifact's digest, its
//      report_bytes: the bytes T038 serialized once at publish from T014's report, which
//      the package carries as verification.json (requests #59 (9) and #74). They are
//      parsed only to check the row, never serialized again, and not claimed to be
//      RFC 8785.
// 5. The access audit event, in its own transaction, through the T029 writer: type
//    artifact.accessed, the principal as actor, the envelope, the served digest as
//    subject_digest, and metadata {operation, artifact_id}. If it cannot be written, nothing
//    is served. Only successful reads are audited; a refused read goes to the request log
//    only, so a caller who may not read cannot add events to an envelope (request #46 (6)).
// 6. The response: the exact bytes, with ETag set to the quoted SHA-256 of those bytes. That
//    is artifact_digest for final.pdf and package_digest for the package. For the report it
//    equals package-index.json's verification.json entry (request #46 (4)). The contract
//    declares no ETag header for readVerification; that is noted for the next contract
//    bump, with no schema change.
//
// Broken invariants throw ArtifactInvariantError, with a fixed code and nothing from the
// row. Examples: a completed envelope without a FinalArtifact row; an artifact with no
// recorded package (publish writes both in one transaction; request #46 (5)); no report
// row; a missing or corrupt blob; bytes that differ from the recorded digest. The handler
// logs the code and answers 500 internal, never 409. The reads open no transaction
// (data-model.md § Global rules, request #30); only the audit append takes the write lock.
// No byte, digest, blob ref or principal reference is logged.

import { createHash } from 'node:crypto';

import { parseJson, type JsonValue } from '../../domain/canonical/index.ts';
import { HttpError, type HandlerResult } from '../../server/types.ts';
import { AuditWriter } from '../../storage/audit/index.ts';
import { BlobIntegrityError, BlobNotFoundError, type BlobStore } from '../../storage/blobs/index.ts';
import { StorageUsageError, type Database, type Row, type TenantStore } from '../../storage/db/index.ts';
import { getEnvelope } from '../../storage/repositories/envelopes.ts';
import { REPORT_SCHEMA } from '../../verifier/index.ts';
import type { OperatorPrincipal } from '../auth/operator.ts';

/** The server locals key of the app's ArtifactApi. */
export const ARTIFACT_API = 'opensig.artifact-api';

/** The audit event type of a successful read. */
export const ACCESS_EVENT_TYPE = 'artifact.accessed';

export type ArtifactOperation = 'readVerification' | 'downloadFinalPdf' | 'downloadPackage';

export const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';
export const PDF_CONTENT_TYPE = 'application/pdf';
export const ZIP_CONTENT_TYPE = 'application/zip';

export type ArtifactInvariant =
  | 'artifact-missing'
  | 'artifact-invalid'
  | 'package-missing'
  | 'report-missing'
  | 'report-invalid'
  | 'blob-unreadable'
  | 'digest-mismatch';

/** A broken stored invariant. Its message is the fixed code only; the handler logs it and answers 500. */
export class ArtifactInvariantError extends Error {
  readonly code: ArtifactInvariant;

  constructor(code: ArtifactInvariant) {
    super(`artifact invariant broken: ${code}`);
    this.name = 'ArtifactInvariantError';
    this.code = code;
  }
}

export interface ArtifactApiOptions {
  readonly db: Database;
  /** The tenant-namespaced, content-addressed blob store holding final.pdf and the package (T028). */
  readonly blobs: BlobStore;
  /** Injected clock for the access events' unsigned server time. */
  readonly clock: () => Date;
  /** The audit-chain writer (T029); by default one on `db` with `clock`. */
  readonly audit?: AuditWriter;
}

interface Served {
  readonly digest: string;
  readonly body: Uint8Array;
  readonly contentType: string;
}

const DIGEST = /^[0-9a-f]{64}$/;

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function column(row: Row, name: string): string {
  const value = row[name];
  if (typeof value !== 'string') throw new ArtifactInvariantError('artifact-invalid');
  return value;
}

function digestColumn(row: Row, name: string): string {
  const value = column(row, name);
  if (!DIGEST.test(value)) throw new ArtifactInvariantError('artifact-invalid');
  return value;
}

export class ArtifactApi {
  readonly #db: Database;
  readonly #blobs: BlobStore;
  readonly #audit: AuditWriter;

  constructor(options: ArtifactApiOptions) {
    if (typeof options?.clock !== 'function') throw new TypeError('the artifact API needs an injected clock');
    if (typeof options.db?.transaction !== 'function' || typeof options.db.forTenant !== 'function') throw new TypeError('the artifact API needs the database');
    if (typeof options.blobs?.readRef !== 'function') throw new TypeError('the artifact API needs the blob store');
    if (options.audit !== undefined && !(options.audit instanceof AuditWriter)) throw new TypeError('the artifact audit writer must be an AuditWriter');
    this.#db = options.db;
    this.#blobs = options.blobs;
    this.#audit = options.audit ?? new AuditWriter(options.db, { clock: options.clock });
    Object.freeze(this);
  }

  /** readVerification: the stored report bytes of the completed artifact (200 VerificationReport). */
  readVerification(principal: OperatorPrincipal, envelopeId: string): HandlerResult {
    return this.#serve(principal, envelopeId, 'readVerification', (store, row) => this.#report(store, row, envelopeId));
  }

  /** downloadFinalPdf: final.pdf's exact sealed bytes (200 application/pdf). */
  downloadFinalPdf(principal: OperatorPrincipal, envelopeId: string): HandlerResult {
    return this.#serve(principal, envelopeId, 'downloadFinalPdf', (store, row) => this.#blob(store, row, 'pdf_blob_ref', digestColumn(row, 'artifact_digest'), PDF_CONTENT_TYPE));
  }

  /** downloadPackage: the evidence package ZIP (200 application/zip). */
  downloadPackage(principal: OperatorPrincipal, envelopeId: string): HandlerResult {
    return this.#serve(principal, envelopeId, 'downloadPackage', (store, row) => {
      if (row['package_digest'] === null || row['package_blob_ref'] === null) throw new ArtifactInvariantError('package-missing');
      return this.#blob(store, row, 'package_blob_ref', digestColumn(row, 'package_digest'), ZIP_CONTENT_TYPE);
    });
  }

  /** Steps 1 to 3: the tenant's completed envelope and its FinalArtifact row. */
  #completedArtifact(store: TenantStore, envelopeId: string): Row {
    const envelope = getEnvelope(store, envelopeId);
    if (envelope === undefined) throw new HttpError(404, 'not_found');
    if (envelope.state !== 'completed') throw new HttpError(409, 'not_completed');
    const row = store.get('final_artifacts', { envelope_id: envelopeId });
    if (row === undefined) throw new ArtifactInvariantError('artifact-missing');
    return row;
  }

  #serve(principal: OperatorPrincipal, envelopeId: string, operation: ArtifactOperation, read: (store: TenantStore, row: Row) => Served): HandlerResult {
    const store = this.#db.forTenant(principal.tenant_id);
    const row = this.#completedArtifact(store, envelopeId);
    const artifactId = column(row, 'artifact_id');
    const served = read(store, row);
    // Step 5: audited before anything is served; a failed append serves nothing.
    this.#db.transaction(() => {
      this.#audit.append(principal.tenant_id, {
        type: ACCESS_EVENT_TYPE,
        actor: { kind: principal.kind, ref: principal.ref },
        envelopeId,
        subjectDigest: served.digest,
        metadata: { operation, artifact_id: artifactId },
      });
    });
    return { status: 200, body: served.body, contentType: served.contentType, headers: { etag: `"${served.digest}"` } };
  }

  /** The verification_reports row of the artifact's digest: its report_bytes, served unchanged. */
  #report(store: TenantStore, row: Row, envelopeId: string): Served {
    const artifactDigest = digestColumn(row, 'artifact_digest');
    let stored: Row | undefined;
    try {
      stored = store.get('verification_reports', { envelope_id: envelopeId, artifact_digest: artifactDigest });
    } catch (error) {
      // More than one row for one artifact breaks T038's one-row publish.
      if (error instanceof StorageUsageError) throw new ArtifactInvariantError('report-invalid');
      throw error;
    }
    if (stored === undefined) throw new ArtifactInvariantError('report-missing');
    const bytes = stored['report_bytes'];
    if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) throw new ArtifactInvariantError('report-missing');
    let report: JsonValue;
    try {
      report = parseJson(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    } catch {
      throw new ArtifactInvariantError('report-invalid');
    }
    if (report === null || typeof report !== 'object' || Array.isArray(report)) throw new ArtifactInvariantError('report-invalid');
    if (report['schema'] !== REPORT_SCHEMA || report['artifact_digest'] !== artifactDigest) throw new ArtifactInvariantError('report-invalid');
    const body = Buffer.from(bytes);
    return { digest: sha256(body), body, contentType: JSON_CONTENT_TYPE };
  }

  /** A stored blob by its recorded ref, checked again against the row's digest. */
  #blob(store: TenantStore, row: Row, refColumn: string, expected: string, contentType: string): Served {
    let body: Buffer;
    try {
      body = this.#blobs.readRef(store.tenantId, column(row, refColumn));
    } catch (error) {
      if (error instanceof BlobNotFoundError || error instanceof BlobIntegrityError) throw new ArtifactInvariantError('blob-unreadable');
      throw error;
    }
    if (sha256(body) !== expected) throw new ArtifactInvariantError('digest-mismatch');
    return { digest: expected, body, contentType };
  }
}
