import { createHash, randomBytes, scryptSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { CredentialKey, CredentialProvider, CredentialRecord } from '@deepseek-ai/dsh-credentials'
import { verifyPassword } from '../src/verify.ts'
import { PASSWORD_PAYLOAD_VERSION } from '../src/password-record.ts'

const PARAMS = { N: 32768, r: 8, p: 1, keylen: 32 } as const

/** Build the stored grant record a username/password would produce offline. */
function grantFor(password: string): CredentialRecord {
  const salt = randomBytes(16)
  const hash = scryptSync(password, salt, PARAMS.keylen, {
    N: PARAMS.N,
    r: PARAMS.r,
    p: PARAMS.p,
    maxmem: 256 * 1024 * 1024,
  })
  return {
    kind: 'grant',
    payload: {
      version: PASSWORD_PAYLOAD_VERSION,
      salt: salt.toString('base64'),
      hash: hash.toString('base64'),
      ...PARAMS,
    },
  }
}

/** A credential provider whose readRecord serves a fixed username→record map. */
function fakeCredentials(records: Map<string, CredentialRecord>): CredentialProvider {
  return {
    readRecord: (key: CredentialKey): Promise<CredentialRecord | undefined> =>
      Promise.resolve(records.get(key as string)),
  } as unknown as CredentialProvider
}

/** The record key verify.ts derives for a username. */
function keyFor(username: string): string {
  return `dsh-web-auth/u${createHash('sha256').update(username, 'utf8').digest('hex')}`
}

describe('verifyPassword', () => {
  it('accepts the correct password for a stored user', async () => {
    const creds = fakeCredentials(new Map([[keyFor('alice'), grantFor('s3cret')]]))
    expect(await verifyPassword(creds, 'alice', 's3cret')).toBe(true)
  })

  it('rejects a wrong password for a stored user', async () => {
    const creds = fakeCredentials(new Map([[keyFor('alice'), grantFor('s3cret')]]))
    expect(await verifyPassword(creds, 'alice', 'wrong')).toBe(false)
  })

  it('rejects an unknown user', async () => {
    const creds = fakeCredentials(new Map())
    expect(await verifyPassword(creds, 'nobody', 'whatever')).toBe(false)
  })

  it('rejects a malformed record rather than treating it as a match', async () => {
    const creds = fakeCredentials(new Map([
      [keyFor('mallory'), { kind: 'grant', payload: { version: 1, salt: 'x' } } as CredentialRecord],
    ]))
    expect(await verifyPassword(creds, 'mallory', 'anything')).toBe(false)
  })
})
