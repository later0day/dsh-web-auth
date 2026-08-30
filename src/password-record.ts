/**
 * The password credential record: its key derivation and the versioned grant
 * payload with strict parsing. A username maps to a record key
 * `dsh-web-auth/u<sha256-hex>` so any username (including ones with characters
 * a credential-key id segment forbids) yields a valid lowercase-hex id. The
 * payload holds an scrypt salt and hash plus the exact cost parameters used to
 * derive them, so verification re-derives with the stored parameters rather
 * than assuming current constants. Parsing throws on any unexpected shape
 * rather than treating a malformed record as an absent user.
 * @module @deepseek-ai/dsh-web-auth/password-record
 */

import { createHash } from 'node:crypto'
import { credentialKey } from '@deepseek-ai/dsh-credentials'
import type { CredentialKey, CredentialRecord } from '@deepseek-ai/dsh-credentials'

/** The credential-record scope this plugin owns. */
const RECORD_SCOPE = 'dsh-web-auth'
/** Current payload format version. */
export const PASSWORD_PAYLOAD_VERSION = 1

/**
 * One stored password verifier: an scrypt hash over a per-record salt, with
 * the cost parameters used to produce it. All fields are base64 strings or
 * finite integers so the record survives a JSON round trip.
 */
export interface PasswordGrantPayload {
  readonly version: typeof PASSWORD_PAYLOAD_VERSION
  /** Base64 salt fed to scrypt. */
  readonly salt: string
  /** Base64 scrypt output. */
  readonly hash: string
  /** scrypt CPU/memory cost (N). */
  readonly N: number
  /** scrypt block size (r). */
  readonly r: number
  /** scrypt parallelization (p). */
  readonly p: number
  /** Derived key length in bytes. */
  readonly keylen: number
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}

/**
 * Derive the credential-record key for one username.
 * @param username - the login name, verbatim.
 * @returns the `dsh-web-auth/u<sha256-hex>` record key.
 */
export function recordKeyFor(username: string): CredentialKey {
  const id = 'u' + createHash('sha256').update(username, 'utf8').digest('hex')
  return credentialKey(RECORD_SCOPE, id)
}

/**
 * Parse a stored credential record into a password payload.
 * @param record - the record read from the credentials service, or undefined.
 * @returns the parsed payload, or undefined when no record exists for the user.
 * @throws when a record exists but does not carry a supported password payload.
 */
export function parsePasswordGrant(
  record: CredentialRecord | undefined,
): PasswordGrantPayload | undefined {
  if (record === undefined) return undefined
  if (record.kind !== 'grant' || !isRecord(record.payload)) {
    throw new Error('dsh-web-auth: password credential record has an unsupported format')
  }
  const p = record.payload
  if (p.version !== PASSWORD_PAYLOAD_VERSION
    || typeof p.salt !== 'string' || p.salt.length === 0
    || typeof p.hash !== 'string' || p.hash.length === 0
    || !isPositiveInteger(p.N) || !isPositiveInteger(p.r)
    || !isPositiveInteger(p.p) || !isPositiveInteger(p.keylen)) {
    throw new Error('dsh-web-auth: password credential record has an invalid payload')
  }
  return {
    version: PASSWORD_PAYLOAD_VERSION,
    salt: p.salt,
    hash: p.hash,
    N: p.N,
    r: p.r,
    p: p.p,
    keylen: p.keylen,
  }
}
