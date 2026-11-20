// SPDX-License-Identifier: Apache-2.0
//
// Outbound mail policy (T032; contracts/sessions-events-adapters.md § Outbound mail guard).
//
// - Addresses: a strict ASCII addr-spec subset (dot-atom local part, host-name domain, no
//   quoted strings, comments, IP literals, CR or LF), at most 254 characters.
// - Recipient domains: only the reserved test domains (.test, example.com, example.org and
//   their subdomains) unless the owner supplies an explicit pilot configuration that names
//   each additional domain exactly (no wildcards, no implied subdomains).
// - SMTP relay: a loopback IP literal only (127.0.0.0/8 or ::1). Host names, including
//   "localhost", are refused because their resolution is outside this policy. The pilot
//   configuration does not widen the relay rule in the MVP: a pilot relays through a
//   loopback MTA.

import { lstatSync, readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { isAbsolute } from 'node:path';

import { NotificationError } from './errors.ts';

/** The reserved recipient domains (contract: `.test`, `example.com`, `example.org`). */
export const RESERVED_RECIPIENT_DOMAINS: readonly string[] = Object.freeze(['.test', 'example.com', 'example.org']);

export const PILOT_SCHEMA = 'opensig.mail-pilot.v1';
const PILOT_MEMBERS = new Set(['schema', 'reference', 'recipient_domains']);
const PILOT_MAX_BYTES = 64 * 1024;
const PILOT_MAX_DOMAINS = 100;

const LOCAL_PART = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const LABEL = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;
const TOP_LABEL = /^(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$/;
const REFERENCE = /^[\x20-\x7e]{1,200}$/;

export interface ParsedAddress {
  /** The address with its domain lowercased. */
  readonly address: string;
  readonly local: string;
  /** Lowercase domain. */
  readonly domain: string;
}

/** True for a multi-label ASCII host name whose top label is alphabetic (or an A-label). */
export function isHostName(value: string): boolean {
  if (value.length === 0 || value.length > 253) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  if (!labels.every((label) => LABEL.test(label))) return false;
  return TOP_LABEL.test(labels[labels.length - 1] ?? '');
}

/** Parse a mail address; throws invalid_notification naming `field`, never the value. */
export function parseAddress(value: unknown, field: string): ParsedAddress {
  const invalid = () => new NotificationError('invalid_notification', `${field} is not a supported mail address`, { field });
  if (typeof value !== 'string' || value.length === 0 || value.length > 254) throw invalid();
  const at = value.indexOf('@');
  if (at <= 0 || at !== value.lastIndexOf('@')) throw invalid();
  const local = value.slice(0, at);
  const domain = value.slice(at + 1).toLowerCase();
  if (local.length > 64 || !LOCAL_PART.test(local) || !isHostName(domain)) throw invalid();
  return Object.freeze({ address: `${local}@${domain}`, local, domain });
}

/** True for `.test` names and for example.com / example.org and their subdomains. */
export function isReservedDomain(domain: string): boolean {
  const name = domain.toLowerCase();
  if (name.endsWith('.test')) return name.length > '.test'.length;
  return ['example.com', 'example.org'].some((reserved) => name === reserved || name.endsWith(`.${reserved}`));
}

export interface PilotPolicy {
  /** The owner's reference for the authorization (recorded, never interpreted). */
  readonly reference: string;
  /** Exact lowercase domains admitted in addition to the reserved test domains. */
  readonly recipientDomains: ReadonlySet<string>;
}

function pilotError(message: string): NotificationError {
  return new NotificationError('config_invalid', `pilot configuration: ${message}`);
}

/** Validate an owner pilot configuration object: {schema, reference, recipient_domains}. */
export function parsePilotPolicy(input: unknown): PilotPolicy {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw pilotError('must be a JSON object');
  const record = input as Record<string, unknown>;
  for (const key of Object.keys(record)) if (!PILOT_MEMBERS.has(key)) throw pilotError(`unknown member ${JSON.stringify(key.slice(0, 40))}`);
  if (record.schema !== PILOT_SCHEMA) throw pilotError(`schema must be ${PILOT_SCHEMA}`);
  if (typeof record.reference !== 'string' || !REFERENCE.test(record.reference)) {
    throw pilotError('reference must be 1 to 200 printable ASCII characters');
  }
  const list = record.recipient_domains;
  if (!Array.isArray(list) || list.length === 0 || list.length > PILOT_MAX_DOMAINS) {
    throw pilotError(`recipient_domains must list 1 to ${PILOT_MAX_DOMAINS} domains`);
  }
  const domains = new Set<string>();
  for (const [index, entry] of list.entries()) {
    if (typeof entry !== 'string' || entry !== entry.toLowerCase() || !isHostName(entry)) {
      throw pilotError(`recipient_domains[${index}] must be an exact lowercase domain name (no wildcard)`);
    }
    if (domains.has(entry)) throw pilotError(`recipient_domains[${index}] is a duplicate`);
    domains.add(entry);
  }
  return Object.freeze({ reference: record.reference, recipientDomains: domains });
}

/**
 * Load the owner pilot configuration file. It must be an absolute path to a regular file
 * (not a symlink) of at most 64 KiB that group and others cannot write.
 */
export function loadPilotPolicy(path: string): PilotPolicy {
  if (!isAbsolute(path)) throw pilotError('the file path must be absolute');
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    throw pilotError('the file is unreadable');
  }
  if (!stat.isFile()) throw pilotError('the path must name a regular file, not a symlink or directory');
  if ((stat.mode & 0o022) !== 0) throw pilotError('the file must not be writable by group or others');
  if (stat.size > PILOT_MAX_BYTES) throw pilotError('the file exceeds 64 KiB');
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw pilotError('the file is not valid JSON');
  }
  return parsePilotPolicy(parsed);
}

/** True when mail may be addressed to `domain` under the reserved list and `pilot`. */
export function recipientDomainAllowed(domain: string, pilot: PilotPolicy | null): boolean {
  const name = domain.toLowerCase();
  return isReservedDomain(name) || (pilot !== null && pilot.recipientDomains.has(name));
}

/** Throws recipient_domain_refused unless the address's domain is allowed. */
export function assertRecipientAllowed(address: ParsedAddress, pilot: PilotPolicy | null): void {
  if (!recipientDomainAllowed(address.domain, pilot)) {
    throw new NotificationError(
      'recipient_domain_refused',
      'the recipient domain is outside the reserved test domains and no owner pilot configuration admits it',
      { field: 'to' },
    );
  }
}

/** True for an IPv4 literal in 127.0.0.0/8 (strict dotted decimal) or the IPv6 literal ::1. */
export function isLoopbackAddress(host: string): boolean {
  const kind = isIP(host);
  if (kind === 4) {
    const octets = host.split('.');
    return octets.length === 4 && octets.every((octet) => /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255) && octets[0] === '127';
  }
  if (kind === 6) {
    try {
      return new URL(`http://[${host}]/`).hostname === '[::1]';
    } catch {
      return false;
    }
  }
  return false;
}

/** Throws relay_refused unless `host` is a loopback IP literal. The host is never echoed. */
export function assertLoopbackRelay(host: unknown): void {
  if (typeof host !== 'string' || !isLoopbackAddress(host)) {
    throw new NotificationError('relay_refused', 'the SMTP relay must be a loopback IP literal (127.0.0.0/8 or ::1); other relays are refused');
  }
}
