/**
 * Password verification against a stored scrypt verifier. Verification reads
 * the user's credential record, re-derives the scrypt hash with the record's
 * own stored parameters, and compares in constant time with a length guard
 * (mirroring the browser-session token compare in dsh-client-connection). An
 * unknown user runs a dummy derivation with fixed default parameters so a
 * missing account and a wrong password take indistinguishable time.
 * @module @deepseek-ai/dsh-web-auth/verify
 */

import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto'
import type { ScryptOptions } from 'node:crypto'
import type { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import { parsePasswordGrant, recordKeyFor } from './password-record.ts'
import type { PasswordGrantPayload } from './password-record.ts'

/** Promise wrapper over the options-carrying scrypt overload. */
function scrypt(password: string, salt: Buffer, keylen: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (err, derivedKey) => {
      if (err !== null) reject(err)
      else resolve(derivedKey)
    })
  })
}

/**
 * Fixed scrypt cost parameters used to hash new passwords and to run the
 * unknown-user dummy derivation. Verification of an existing user uses that
 * user's stored parameters instead. These are security constants, not
 * deployment tunables.
 */
export const SCRYPT_DEFAULTS = { N: 32768, r: 8, p: 1, keylen: 32 } as const

/** scrypt memory ceiling; N*r*128 stays well under this for the defaults. */
const SCRYPT_MAXMEM = 256 * 1024 * 1024

/** A throwaway salt for the unknown-user dummy derivation. */
const DUMMY_SALT = randomBytes(16)

async function derive(password: string, salt: Buffer, params: {
  N: number
  r: number
  p: number
  keylen: number
}): Promise<Buffer> {
  return scrypt(password, salt, params.keylen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT_MAXMEM,
  })
}

/** Constant-time compare with a length guard: timingSafeEqual throws on unequal lengths. */
function bytesMatch(actual: Buffer, expected: Buffer): boolean {
  return actual.byteLength === expected.byteLength && timingSafeEqual(actual, expected)
}

/**
 * Verify a submitted password for one username.
 * @param credentials - the credential provider holding the password records.
 * @param username - the submitted login name.
 * @param password - the submitted password.
 * @returns true only when the user exists and the password matches its stored scrypt verifier.
 */
export async function verifyPassword(
  credentials: CredentialProvider,
  username: string,
  password: string,
): Promise<boolean> {
  let payload: PasswordGrantPayload | undefined
  try {
    payload = parsePasswordGrant(await credentials.readRecord(recordKeyFor(username)))
  } catch {
    // A malformed record is not a usable account; equalize timing and reject.
    payload = undefined
  }
  if (payload === undefined) {
    // Unknown or unusable user: derive against a dummy salt so the response
    // time does not reveal whether the account exists, then reject.
    await derive(password, DUMMY_SALT, SCRYPT_DEFAULTS)
    return false
  }
  const salt = Buffer.from(payload.salt, 'base64')
  const expected = Buffer.from(payload.hash, 'base64')
  const actual = await derive(password, salt, {
    N: payload.N,
    r: payload.r,
    p: payload.p,
    keylen: payload.keylen,
  })
  return bytesMatch(actual, expected)
}
