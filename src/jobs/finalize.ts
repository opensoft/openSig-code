// SPDX-License-Identifier: Apache-2.0
//
// The finalization runner (T038; data-model.md § Transitions and races,
// items 2 and 3; A-008 S1; A-010 S4 and requests #39, #43, #44, #59, #61, #62).
//
// One attempt, in phase order (T015's eight phases, request #61):
// - reserve: the lease grant (attempt_count + 1 becomes the fencing token).
// - compose: the seal anchor, written once by the first attempt to begin
//   composing and reused by every retry, with its time as sealTime; then
//   T036's composeSealRevision over the frozen document, field manifest and
//   approvals; the composed blob is recorded, then stored.
// - seal: the pre-seal approval manifest and its approval_evidence_digest
//   (FEN-07), then T037's sealComposedPdf with the key file opened for this
//   attempt (O_NOFOLLOW, O_NONBLOCK) and closed afterwards, and the lease
//   keeper's signal.
// - verify: T014 off the event loop (request #62 (2)).
// - store PDF: the sealed PDF recorded, then stored.
// - store evidence: approval-manifest.json (with final_pdf_digest) recorded,
//   then stored; then the completion checkpoint, written once and reused, the
//   envelope's events up to the head it records, T016's package (its
//   buildPackage, which rechecks the verdict and every cross-link), recorded,
//   then stored.
// - publish and outbox: the one publish transaction (publish.ts).
// T015's fault hook is T015's own code, after T038 lands (the T015 line). Its
// positions (request #61 (2)) are marked below as "hook:" comments: right
// after the grant commits; before each phase's first durable write, or at the
// phase's start when it has none; inside the publish transaction before
// COMMIT; and right after the publish commits.
//
// Lease loss: every write is fenced. A lost attempt (LeaseLost, a fenced step
// returning null or false, or a publish refused on the fence, state, version
// or checkpoint) writes nothing more: no failure record, no publication. Its
// recorded blobs stay collectable.
// Failure: classifyFailure (failure.ts) decides retryable or not, and
// failAttempt records it under the lease; a move into `failed` emits
// `envelope.finalization_failed` once (request #59 (8)).
// Reclaim: runOnce first reclaims strictly expired leases (reclaimLease), so a
// crashed attempt's job becomes retryable, or `failed` at the limit with its
// one announcement (request #61 (5)).
//
// Settings: the T031 US2 composition slot reads and validates
// OPENSIG_SEAL_KEY_FILE, OPENSIG_SEAL_CERT_FILE and OPENSIG_TRUST_ANCHORS_FILE
// at startup and constructs this runner with the key file's path, the
// certificate's DER and the anchors' PEM certificates (T014's
// splitPemCertificates). The clock enters only through these options, the
// runner's test entry (request #61 (8)).

import { createHash, randomBytes } from 'node:crypto';
import { closeSync, constants as fsConstants, openSync } from 'node:fs';

import { buildPackage as buildEvidencePackage, type BuiltPackage, type PackageInput } from '../artifacts/package.ts';
import { withinSealedBound } from '../cryptograph/compose/bounds.ts';
import { composeSealRevision, type ComposedRevision, type ComposeRequest } from '../cryptograph/compose/index.ts';
import { sealComposedPdf, type SealedPdf, type SealInput, type SealOptions } from '../cryptograph/worker/index.ts';
import { canonicalBytes } from '../domain/canonical/index.ts';
import { PublishRefused } from '../domain/finalization/errors.ts';
import { classifyFailure, StepFailure, type FailureStage } from '../domain/finalization/failure.ts';
import { LeaseKeeper, LeaseLost, type LeaseTimers } from '../domain/finalization/lease.ts';
import { buildPreSealManifest, readSealRecords } from '../domain/finalization/manifest.ts';
import { publishFinalization, type Publication } from '../domain/finalization/publish.ts';
import { failAttempt, reclaimLease, recordBlob, writeCompletionCheckpoint, writeSealAnchor, type StepContext } from '../domain/finalization/transitions.ts';
import { runVerification, type VerifyOptions } from '../domain/finalization/verify.ts';
import type { VerifyJob } from '../domain/finalization/verify-worker.ts';
import { eventFromRow, type AuditEvent, type AuditWriter } from '../storage/audit/index.ts';
import { blobRef, type BlobStore } from '../storage/blobs/index.ts';
import type { Database, TenantStore } from '../storage/db/index.ts';
import { DEFAULT_LEASE_MS, grantLease, listClaimableJobs, listExpiredLeases, renewLease, type AttemptBlobRole, type LeaseHolder } from '../storage/repositories/jobs.ts';

export const DEFAULT_RUN_INTERVAL_MS = 15_000;
export const DEFAULT_CLAIMS_PER_TENANT = 10;

/**
 * T016's pure, deterministic package builder (src/artifacts/package.ts; the
 * T016 line, A-010 S4 and request #46): the default. The seam is for tests.
 */
export type PackageBuilder = (input: PackageInput) => BuiltPackage;

/** Seams for tests; production uses the landed T036, T037 and T014 entries and the key file. */
export interface FinalizationPorts {
  readonly compose?: (request: ComposeRequest) => Promise<ComposedRevision>;
  readonly sealPdf?: (input: SealInput, options?: SealOptions) => Promise<SealedPdf>;
  readonly verify?: (job: VerifyJob, options: VerifyOptions) => Promise<Uint8Array>;
  readonly openKey?: (path: string) => number;
}

export interface FinalizationRunnerOptions {
  readonly db: Database;
  readonly audit: AuditWriter;
  readonly blobs: BlobStore;
  readonly clock: () => Date;
  /** This process's lease owner identity (1..100 of [A-Za-z0-9_.:-]). */
  readonly owner: string;
  readonly leaseMs?: number;
  readonly seal: { readonly keyFile: string; readonly certificateDer: Uint8Array; readonly developmentCertificate: boolean };
  /** PEM certificates of OPENSIG_TRUST_ANCHORS_FILE; none without the setting. */
  readonly anchors: readonly string[];
  /** Default: T016's buildPackage. */
  readonly buildPackage?: PackageBuilder;
  readonly ports?: FinalizationPorts;
  readonly timers?: LeaseTimers;
  readonly newId?: (prefix: string) => string;
  readonly newEventId?: () => string;
  readonly claimsPerTenant?: number;
}

export type AttemptOutcome =
  | { readonly kind: 'not-claimed' }
  | { readonly kind: 'lost' }
  | { readonly kind: 'published'; readonly publication: Publication }
  | { readonly kind: 'retryable' | 'failed'; readonly errorCode: string };

export interface RunReport {
  readonly reclaimed: number;
  readonly attempts: readonly { readonly tenantId: string; readonly envelopeId: string; readonly outcome: AttemptOutcome['kind'] }[];
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function defaultId(prefix: string): string {
  return `${prefix}-${randomBytes(16).toString('base64url')}`;
}

/** Open the seal key without following a final symbolic link and without blocking (request #39, Part F). */
export function openSealKey(path: string): number {
  return openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
}

function lost(): never {
  throw new LeaseLost('fenced');
}

function eventsUpTo(store: TenantStore, envelopeId: string, seq: number): { readonly event: AuditEvent; readonly eventDigest: string }[] {
  const events: { readonly event: AuditEvent; readonly eventDigest: string }[] = [];
  for (const row of store.iterate('audit_events', { envelope_id: envelopeId, seq: { op: '<=', value: seq } }, { orderBy: [['seq', 'asc']] })) {
    events.push({ event: eventFromRow(row), eventDigest: String(row['event_digest']) });
  }
  return events;
}

export class FinalizationRunner {
  readonly #o: FinalizationRunnerOptions;
  readonly #leaseMs: number;
  #timer: ReturnType<typeof setTimeout> | undefined = undefined;
  #running = false;

  constructor(options: FinalizationRunnerOptions) {
    if (typeof options?.clock !== 'function') throw new TypeError('the finalization runner needs an injected clock');
    if (options.buildPackage !== undefined && typeof options.buildPackage !== 'function') throw new TypeError('the package builder must be a function');
    if (!(options.seal?.certificateDer instanceof Uint8Array) || typeof options.seal.keyFile !== 'string') throw new TypeError('the finalization runner needs the seal settings');
    this.#o = options;
    this.#leaseMs = options.leaseMs ?? DEFAULT_LEASE_MS;
  }

  /** One attempt on one envelope's job, if it is claimable now (the runner's test entry). */
  async runAttempt(tenantId: string, envelopeId: string): Promise<AttemptOutcome> {
    const o = this.#o;
    const store = o.db.forTenant(tenantId);
    const grant = o.db.transaction(() => grantLease(store, envelopeId, { owner: o.owner, now: o.clock(), leaseMs: this.#leaseMs }));
    if (grant === null) return { kind: 'not-claimed' };
    // hook: reserve, right after the grant commits.
    const holder: LeaseHolder = { envelopeId, fencingToken: grant.fencingToken, leaseOwner: grant.leaseOwner };
    const context: StepContext = { db: o.db, audit: o.audit, tenantId, clock: o.clock, newEventId: o.newEventId };
    const keeper = new LeaseKeeper({
      renew: () => o.db.transaction(() => renewLease(store, holder, { now: o.clock(), leaseMs: this.#leaseMs })),
      leaseExpiresAt: grant.leaseExpiresAt,
      leaseMs: this.#leaseMs,
      clock: o.clock,
      timers: o.timers,
    });
    keeper.start();
    let stage: FailureStage = 'manifest';
    try {
      return { kind: 'published', publication: await this.#attempt(store, context, holder, grant.reservedVersion, keeper, (next) => (stage = next)) };
    } catch (error) {
      if (keeper.lossCause !== null || error instanceof LeaseLost) return { kind: 'lost' };
      if (error instanceof PublishRefused && error.reason !== 'blob') return { kind: 'lost' };
      const failure = error instanceof PublishRefused ? new StepFailure('publish_refused', 'blob-missing', true) : error;
      const verdict = classifyFailure(stage, failure);
      const outcome = failAttempt(context, holder, verdict);
      return outcome === 'lease-lost' ? { kind: 'lost' } : { kind: outcome, errorCode: verdict.errorCode };
    } finally {
      keeper.stop();
    }
  }

  async #attempt(
    store: TenantStore,
    context: StepContext,
    holder: LeaseHolder,
    reservedVersion: number,
    keeper: LeaseKeeper,
    enter: (stage: FailureStage) => void,
  ): Promise<Publication> {
    const o = this.#o;
    const ports = o.ports ?? {};
    const newId = o.newId ?? defaultId;
    const storeBlob = (role: AttemptBlobRole, bytes: Uint8Array): string => {
      const digest = sha256(bytes);
      // hook: before this phase's first durable write (the record).
      if (!recordBlob(context, holder, blobRef(context.tenantId, digest), role)) lost();
      o.blobs.put(context.tenantId, bytes, { expectedDigest: digest });
      return digest;
    };

    keeper.checkHeld();
    const records = readSealRecords(store, holder.envelopeId);

    enter('anchor');
    // hook: compose, before the anchor (its first durable write, when this attempt writes it).
    const anchor = writeSealAnchor(context, holder) ?? lost();
    enter('compose');
    keeper.checkHeld();
    const document = o.blobs.readRef(context.tenantId, records.document.blobRef);
    const composed = await (ports.compose ?? composeSealRevision)({
      document,
      fieldManifest: records.fieldManifest as unknown as ComposeRequest['fieldManifest'],
      approvals: records.approvals as unknown as ComposeRequest['approvals'],
      sealTime: anchor.sealTime,
      certificateDer: o.seal.certificateDer,
    });
    keeper.checkHeld();
    storeBlob('composed', composed.bytes);

    enter('manifest');
    const preSeal = buildPreSealManifest(records, {
      envelopeId: holder.envelopeId,
      anchor,
      approvedCompositionDigest: composed.digest,
      seal: { signerCertificateSha256: sha256(o.seal.certificateDer), developmentCertificate: o.seal.developmentCertificate },
    });

    enter('seal');
    // hook: seal, at the phase's start.
    keeper.checkHeld();
    const keyFd = (ports.openKey ?? openSealKey)(o.seal.keyFile);
    let sealed: SealedPdf;
    try {
      sealed = await (ports.sealPdf ?? sealComposedPdf)(
        { composed, certificateDer: o.seal.certificateDer, approvalEvidenceDigest: Buffer.from(preSeal.approvalEvidenceDigest, 'hex'), keyFd },
        { signal: keeper.signal },
      );
    } finally {
      closeSync(keyFd);
    }
    // Row SIZE-BOUND: T036's one product bound (MAX_SEALED_PDF_BYTES). T037 already refuses
    // above it, so a breach here is a broken invariant, not retryable.
    if (!withinSealedBound(sealed.bytes.length)) throw new StepFailure('sealed_too_large', 'bound', false);

    enter('verify');
    // hook: verify, at the phase's start.
    keeper.checkHeld();
    const reportBytes = await (ports.verify ?? runVerification)(
      {
        bytes: sealed.bytes,
        anchors: o.anchors,
        expectedArtifactDigest: sealed.finalPdfDigest,
        expectedApprovalEvidenceDigest: preSeal.approvalEvidenceDigest,
        validationTime: o.clock().toISOString(),
      },
      { signal: keeper.signal },
    );

    enter('store');
    keeper.checkHeld();
    storeBlob('sealed', sealed.bytes);
    const approvalManifest = { ...preSeal.manifest, final_pdf_digest: sealed.finalPdfDigest };
    const evidenceBytes = canonicalBytes(approvalManifest);
    const evidenceDigest = storeBlob('evidence', evidenceBytes);

    enter('package');
    const checkpoint = writeCompletionCheckpoint(context, holder) ?? lost();
    // The package index names the artifact, so its id is fixed before the build.
    const artifactId = newId('art');
    const built = (o.buildPackage ?? buildEvidencePackage)({
      tenantId: context.tenantId,
      envelopeId: holder.envelopeId,
      artifactId,
      finalPdf: sealed.bytes,
      approvalManifest,
      events: eventsUpTo(store, holder.envelopeId, checkpoint.seq),
      // At the checkpoint the chain head is the checkpoint's event (T029).
      chainHead: { seq: checkpoint.seq, digest: checkpoint.digest },
      checkpoint,
      verification: reportBytes,
    });
    const packageDigest = storeBlob('package', built.bytes);

    enter('publish');
    keeper.checkHeld();
    // hook: publish, inside the publish transaction before COMMIT (T015's own code).
    const publication = publishFinalization(
      o.db,
      {
        tenantId: context.tenantId,
        holder,
        expectedEnvelopeVersion: reservedVersion,
        receiptHead: { seq: checkpoint.seq, digest: checkpoint.digest },
        verificationReportId: newId('vrep'),
        reportBytes,
        artifact: {
          artifactId,
          artifactDigest: sealed.finalPdfDigest,
          packageDigest,
          approvedCompositionDigest: composed.digest,
          evidenceDigest,
          approvalEvidenceDigest: preSeal.approvalEvidenceDigest,
          developmentCertificate: o.seal.developmentCertificate,
        },
      },
      { clock: o.clock, audit: o.audit, blobs: o.blobs, newEventId: o.newEventId },
    );
    // hook: outbox, right after the publish commits.
    return publication;
  }

  /** Reclaim strictly expired leases, then run the claimable jobs, one attempt at a time. */
  async runOnce(): Promise<RunReport> {
    const o = this.#o;
    const limit = o.claimsPerTenant ?? DEFAULT_CLAIMS_PER_TENANT;
    let reclaimed = 0;
    const attempts: { tenantId: string; envelopeId: string; outcome: AttemptOutcome['kind'] }[] = [];
    for (const tenantId of o.db.listTenantIds()) {
      const store = o.db.forTenant(tenantId);
      const context: StepContext = { db: o.db, audit: o.audit, tenantId, clock: o.clock, newEventId: o.newEventId };
      for (const envelopeId of listExpiredLeases(store, o.clock(), limit)) {
        if (reclaimLease(context, envelopeId) !== 'not-expired') reclaimed += 1;
      }
      for (const envelopeId of listClaimableJobs(store, o.clock(), limit)) {
        const outcome = await this.runAttempt(tenantId, envelopeId);
        attempts.push({ tenantId, envelopeId, outcome: outcome.kind });
      }
    }
    return { reclaimed, attempts };
  }

  /** Run on an interval, never two runs at once. The T031 US2 composition slot starts it. */
  start(intervalMs = DEFAULT_RUN_INTERVAL_MS): void {
    if (this.#timer !== undefined) return;
    const tick = (): void => {
      this.#timer = setTimeout(() => {
        if (this.#running) return tick();
        this.#running = true;
        this.runOnce()
          .catch(() => undefined)
          .finally(() => {
            this.#running = false;
            if (this.#timer !== undefined) tick();
          });
      }, intervalMs);
      this.#timer.unref();
    };
    tick();
  }

  stop(): void {
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
  }
}
