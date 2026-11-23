// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';

import contract from '../../../contracts/http-api.json' with { type: 'json' };
import { buildFieldManifest, recipientsDigest } from '../../domain/envelopes/manifest.ts';
import { canonicalDigest } from '../../domain/canonical/index.ts';
import { ToolError } from './api-client.mjs';

const MAX_PDF_BYTES = 10 * 1024 * 1024;
const MAX_PDF_BASE64 = Math.ceil(MAX_PDF_BYTES / 3) * 4;
const schemas = contract.components.schemas;
const idPattern = /^[A-Za-z0-9_-]{16,64}$/;
const digestPattern = /^[0-9a-f]{64}$/;

const objectSchema = (properties) => ({
  type: 'object', properties, required: Object.keys(properties), additionalProperties: false,
});
const identifier = { type: 'string', pattern: idPattern.source };
const envelope = { envelope_id: identifier };
const fieldSchema = {
  ...schemas.FieldInput,
  properties: { ...schemas.FieldInput.properties, rect: schemas.Rect },
};

export const tools = [
  {
    name: 'prepare_envelope',
    description: 'Create a draft from a base64 PDF, freeze the fields, and return the recipient preview for human confirmation.',
    inputSchema: objectSchema({
      source: schemas.Source,
      pdf: { type: 'string', contentEncoding: 'base64', minLength: 4, maxLength: MAX_PDF_BASE64 },
      recipients: { ...schemas.EnvelopeCreate.properties.recipients, items: schemas.RecipientInput },
      fields: { ...schemas.Prepare.properties.fields, items: fieldSchema },
    }),
  },
  {
    name: 'request_signatures',
    description: 'Send invitations by mail using the human operator’s confirmation for this exact version.',
    inputSchema: objectSchema({
      ...envelope,
      expected_version: schemas.Send.properties.expected_version,
      authorization_reference: identifier,
    }),
  },
  {
    name: 'get_status',
    description: 'Read envelope status, recipient progress, finalization and the artifact summary.',
    inputSchema: objectSchema(envelope),
  },
  {
    name: 'retrieve_completed_package',
    description: 'Retrieve the completed evidence ZIP as base64 and its verification report.',
    inputSchema: objectSchema(envelope),
  },
];

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isId = (value) => typeof value === 'string' && idPattern.test(value);
const isDigest = (value) => typeof value === 'string' && digestPattern.test(value);
const isVersion = (value) => Number.isSafeInteger(value) && value >= 1;
function project(value, keys) {
  const values = keys.map((key) => [key, value[key]]);
  return Object.fromEntries(values.filter(([, field]) =>
    field === null || ['string', 'boolean', 'number'].includes(typeof field)));
}

function boundedList(value, max) {
  return Array.isArray(value) && value.length > 0 && value.length <= max && value.every(isObject);
}

function plain(value, keys) {
  return isObject(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function pdfBytes(pdf) {
  if (typeof pdf !== 'string' || pdf.length > MAX_PDF_BASE64 || pdf.length % 4 !== 0) {
    throw new ToolError('Expected a base64 PDF of at most 10 MiB.');
  }
  const bytes = Buffer.from(pdf, 'base64');
  if (bytes.length === 0 || bytes.length > MAX_PDF_BYTES || bytes.toString('base64') !== pdf) {
    throw new ToolError('Expected a base64 PDF of at most 10 MiB.');
  }
  return bytes;
}

function checkedEnvelope(value, id) {
  if (!isObject(value) || !isId(value.id) || (id !== undefined && value.id !== id) ||
      !isVersion(value.version) || !schemas.Envelope.properties.state.enum.includes(value.state)) {
    throw new ToolError('Unexpected openSig envelope response.');
  }
  return value;
}

const statusFields = ['id', 'version', 'state', 'approvals_complete'];
const recipientFields = ['id', 'ordinal', 'role', 'email', 'status', 'invited_at', 'approved_at', 'approval_digest'];
const artifactFields = Object.keys(schemas.ArtifactSummary.properties);
const finalizationFields = Object.keys(schemas.FinalizationStatus.properties);

function statusSummary(value) {
  return {
    ...project(value, [...statusFields, 'anchor_status']),
    recipients: value.recipients.map((row) => project(row, ['id', 'ordinal', 'status', 'invited_at', 'approved_at'])),
    finalization: value.finalization === null ? null : project(value.finalization, finalizationFields),
    artifact: value.artifact === null ? null : project(value.artifact, artifactFields),
  };
}

function previewSummary(value) {
  return {
    ...project(value, ['envelope_id', 'version', 'state', 'manifest_digest', 'recipients_digest', 'requires_human_confirmation']),
    created_by: project(value.created_by, ['kind', 'ref']),
    source: project(value.source, ['app', 'record', 'version']),
    document: {
      ...project(value.document, ['digest', 'bytes']),
      pages: value.document.pages.map((row) => project(row, ['number', 'width', 'height', 'rotate'])),
    },
    fields: value.fields.map((row) => ({
      ...project(row, ['key', 'recipient_id', 'recipient_ordinal', 'page', 'type']),
      rect: project(row.rect, ['x', 'y', 'width', 'height']),
    })),
    recipients: value.recipients.map((row) => project(row, recipientFields)),
  };
}

function verificationSummary(value) {
  if (!isObject(value) || value.schema !== 'opensig.verification/1' ||
      !isDigest(value.artifact_digest) || !Array.isArray(value.checks)) {
    throw new ToolError('Unexpected openSig verification report.');
  }
  return {
    ...project(value, Object.keys(schemas.VerificationReport.properties)),
    verifier: project(value.verifier, ['name', 'version']),
    checks: value.checks.map((check) => project(check, ['id', 'result', 'detail_code'])),
  };
}

async function prepareEnvelope(api, { source, pdf, recipients, fields }) {
  if (!isObject(source) || !boundedList(recipients, 2) || !boundedList(fields, 20)) {
    throw new ToolError('Expected a source, recipients and fields.');
  }
  const bytes = pdfBytes(pdf);
  const documentDigest = sha256(bytes);
  const requestedRecipients = recipientsDigest(recipients);
  const draft = checkedEnvelope(await api('POST', '/v1/envelopes', { body: { source, recipients }, expected: 201 }));
  const root = '/v1/envelopes/' + draft.id;
  const uploaded = checkedEnvelope(await api('PUT', root + '/document', { body: bytes, version: draft.version }), draft.id);
  if (uploaded.document?.digest !== documentDigest) throw new ToolError('The uploaded PDF digest differs.');
  const prepared = checkedEnvelope(await api('POST', root + '/prepare', {
    body: { expected_version: uploaded.version, fields },
  }), draft.id);
  const raw = await api('GET', root + '/preview');
  const preview = previewSummary(raw);
  const frozen = buildFieldManifest(draft.id, documentDigest, preview.fields);
  const requestedFields = fields.map((field) => ({
    ...field,
    recipient_id: preview.recipients.find(({ ordinal }) => ordinal === field.recipient_ordinal)?.id,
  }));
  if (prepared.state !== 'prepared' || preview.state !== 'prepared' ||
      preview.envelope_id !== draft.id || preview.version !== prepared.version ||
      preview.created_by.kind !== 'service' || preview.requires_human_confirmation !== true ||
      canonicalDigest(preview.source) !== canonicalDigest(source) ||
      preview.document.digest !== documentDigest || prepared.document?.digest !== documentDigest ||
      preview.manifest_digest !== frozen.digest || prepared.manifest_digest !== frozen.digest ||
      buildFieldManifest(draft.id, documentDigest, requestedFields).digest !== frozen.digest ||
      preview.recipients_digest !== requestedRecipients ||
      recipientsDigest(preview.recipients) !== requestedRecipients) {
    throw new ToolError('The recipient preview does not match the prepared envelope.');
  }
  return {
    envelope_id: draft.id,
    version: preview.version,
    document_digest: documentDigest,
    manifest_digest: preview.manifest_digest,
    recipients_digest: preview.recipients_digest,
    preview,
  };
}

export async function callTool(api, name, args) {
  const definition = tools.find((tool) => tool.name === name);
  if (!definition) throw new ToolError('Unknown openSig tool.');
  if (!plain(args, definition.inputSchema.required)) throw new ToolError('Invalid tool arguments.');
  if (name === 'prepare_envelope') return prepareEnvelope(api, args);
  if (!isId(args.envelope_id)) throw new ToolError('Invalid envelope identifier.');
  const root = '/v1/envelopes/' + args.envelope_id;

  switch (name) {
    case 'request_signatures': {
      const { expected_version, authorization_reference } = args;
      if (!isVersion(expected_version) || !isId(authorization_reference)) {
        throw new ToolError('A valid expected version and human authorization reference are required.');
      }
      const body = { expected_version, authorization_reference };
      return project(checkedEnvelope(await api('POST', root + '/send', { body }), args.envelope_id), statusFields);
    }
    case 'get_status':
      return statusSummary(checkedEnvelope(await api('GET', root), args.envelope_id));
    case 'retrieve_completed_package': {
      const bytes = await api('GET', root + '/package', { zip: true });
      const verification = verificationSummary(await api('GET', root + '/verification'));
      return { package_base64: bytes.toString('base64'), package_digest: sha256(bytes), verification };
    }
  }
}
