/**
 * The plugin's session cookie: an HMAC-SHA256-signed, authority-bound value
 * minted on password success and verified by the authentication provider on
 * every later request. The signing secret is a persistent `grant` record in
 * the credentials service (mirroring host-authentication-token's
 * browser-session secret), so sessions survive a server restart. 0.2.2-rc.3
 * removed `connection.authenticatedUrl` and the token→cookie bridge, so the
 * plugin now mints its own cookie instead of redirecting through the harness
 * token exchange.
 * @module @deepseek-ai/dsh-web-auth/session
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { credentialKey } from '@deepseek-ai/dsh-credentials'
import type { CredentialProvider, CredentialRecord } from '@deepseek-ai/dsh-credentials'
import type { ConnectionTrustRequest } from '@deepseek-ai/dsh-client-connection'

/** Credential record key holding the cookie signing secret. */
const SECRET_RECORD_KEY = credentialKey('dsh-web-auth', 'session-secret')
/** Cookie name; the value is `v1.<base64url body>.<base64url hmac>`. */
export const SESSION_COOKIE = 'dsh-web-auth-session'
/** Cookie payload version this activation mints and accepts. */
const PAYLOAD_VERSION = 1
/** Signing key length in bytes. */
const SECRET_BYTES = 32
/** Absolute cookie lifetime in days (a login-gate convenience bound). */
const SESSION_MAX_AGE_DAYS = 30
const DAY_MS = 24 * 60 * 60 * 1000
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/

interface StoredSecretPayload {
  readonly version: 1
  readonly secret: string
}

interface SessionPayload {
  readonly version: 1
  /** Authority (host[:port], or origin under TLS) the cookie was minted for. */
  readonly authority: string
  readonly issuedAt: number
  readonly expiresAt: number
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '')
}

function decodeBase64Url(value: string): Buffer | undefined {
  if (!BASE64URL_PATTERN.test(value) || value.length % 4 === 1) return undefined
  const padding = '='.repeat((4 - value.length % 4) % 4)
  const decoded = Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + padding, 'base64')
  return encodeBase64Url(decoded) === value ? decoded : undefined
}

function header(
  headers: ConnectionTrustRequest['headers'],
  name: string,
): string | undefined {
  if (headers instanceof Headers) return headers.get(name) ?? undefined
  const value = headers[name]
  return typeof value === 'string' ? value : undefined
}

/** Cookie audience: origin under TLS (secret carries Secure), host otherwise. */
function requestAudience(headers: ConnectionTrustRequest['headers'], secure: boolean): string | undefined {
  const host = header(headers, 'host')
  if (host === undefined) return undefined
  try {
    const url = new URL(`${secure ? 'https:' : 'http:'}//${host}`)
    return secure ? url.origin : url.host
  } catch {
    return undefined
  }
}

/** Read the exact session cookie without a general cookie parser. */
export function readSessionCookie(cookieHeader: string | undefined): string | undefined {
  if (cookieHeader === undefined) return undefined
  for (const segment of cookieHeader.split(';')) {
    const at = segment.indexOf('=')
    if (at === -1 || segment.slice(0, at).trim() !== SESSION_COOKIE) continue
    return segment.slice(at + 1).trim()
  }
  return undefined
}

function canonicalSecret(value: unknown): Buffer | undefined {
  if (typeof value !== 'string') return undefined
  const decoded = decodeBase64Url(value)
  if (decoded === undefined || decoded.byteLength !== SECRET_BYTES) return undefined
  return decoded
}

function storedSecret(record: CredentialRecord | undefined): Buffer | undefined {
  if (record === undefined) return undefined
  if (record.kind !== 'grant' || !isRecord(record.payload) || record.payload.version !== 1) {
    throw new Error('dsh-web-auth: session-secret credential record has an unsupported format')
  }
  const secret = canonicalSecret(record.payload.secret)
  if (secret === undefined) {
    throw new Error('dsh-web-auth: session-secret credential record has an invalid secret')
  }
  return secret
}

async function initializeSecret(credentials: CredentialProvider): Promise<Buffer> {
  const generated: StoredSecretPayload = { version: 1, secret: encodeBase64Url(randomBytes(SECRET_BYTES)) }
  const record = await credentials.modifyRecord(SECRET_RECORD_KEY, (current) => {
    if (current !== undefined) {
      storedSecret(current)
      return Promise.resolve(undefined)
    }
    return Promise.resolve({ kind: 'grant', payload: generated })
  })
  const secret = storedSecret(record)
  if (secret === undefined) {
    throw new Error('dsh-web-auth: session-secret credential record was not created')
  }
  return secret
}

/** Mints and verifies the signed, authority-bound session cookie. */
export class SessionAuth {
  private readonly maxAgeMs: number

  private constructor(private readonly secret: Buffer, maxAgeDays: number) {
    this.maxAgeMs = maxAgeDays * DAY_MS
  }

  /**
   * Create the persistent signing secret if the home has none.
   * @param credentials - persistent credential provider for the Web profile.
   * @param maxAgeDays - absolute cookie lifetime in days; defaults to 30.
   */
  static async create(credentials: CredentialProvider, maxAgeDays = SESSION_MAX_AGE_DAYS): Promise<SessionAuth> {
    return new SessionAuth(await initializeSecret(credentials), maxAgeDays)
  }

  /**
   * Serialize the Set-Cookie value for a freshly verified login.
   * @param headers - the login request's headers; Host names the audience.
   * @param secure - whether the receiving listener serves TLS.
   * @returns the Set-Cookie header value.
   */
  cookieFor(headers: ConnectionTrustRequest['headers'], secure: boolean): string {
    // The login POST has passed the authorize fence, so Host is present; a
    // missing Host falls back to the empty audience rather than failing the
    // verified login.
    const authority = requestAudience(headers, secure) ?? ''
    const issuedAt = Date.now()
    const expiresAt = issuedAt + this.maxAgeMs
    const body = encodeBase64Url(Buffer.from(JSON.stringify({
      version: PAYLOAD_VERSION, authority, issuedAt, expiresAt,
    } satisfies SessionPayload), 'utf8'))
    const value = `v${PAYLOAD_VERSION}.${body}.${encodeBase64Url(this.signature(body))}`
    const attributes = `${SESSION_COOKIE}=${value}; Max-Age=${String(Math.floor(this.maxAgeMs / 1000))}; Path=/; Expires=${new Date(expiresAt).toUTCString()}; HttpOnly; SameSite=Strict`
    return secure ? `${attributes}; Secure` : attributes
  }

  /**
   * Verify the session cookie on a later request.
   * @param request - request headers carrying Host and Cookie.
   * @param secure - whether the receiving listener serves TLS.
   * @returns true only for an unexpired cookie signed by the stored secret for this authority.
   */
  verify(request: ConnectionTrustRequest, secure: boolean): boolean {
    const authority = requestAudience(request.headers, secure)
    if (authority === undefined) return false
    const value = readSessionCookie(header(request.headers, 'cookie'))
    if (value === undefined) return false
    const parts = value.split('.')
    const [version, body, encodedSignature] = parts
    if (parts.length !== 3 || version !== `v${PAYLOAD_VERSION}`
      || body === undefined || encodedSignature === undefined) return false
    const actual = decodeBase64Url(encodedSignature)
    const expected = actual === undefined ? undefined : this.signature(body)
    if (actual === undefined || expected === undefined
      || actual.byteLength !== expected.byteLength || !timingSafeEqual(actual, expected)) return false
    const bodyBytes = decodeBase64Url(body)
    if (bodyBytes === undefined) return false
    let decoded: unknown
    try { decoded = JSON.parse(bodyBytes.toString('utf8')) } catch { return false }
    if (!isRecord(decoded) || decoded.version !== PAYLOAD_VERSION
      || typeof decoded.authority !== 'string' || decoded.authority !== authority
      || typeof decoded.issuedAt !== 'number' || !Number.isSafeInteger(decoded.issuedAt)
      || typeof decoded.expiresAt !== 'number' || !Number.isSafeInteger(decoded.expiresAt)) return false
    const now = Date.now()
    return decoded.issuedAt <= now && decoded.expiresAt > now
      && decoded.expiresAt - decoded.issuedAt <= this.maxAgeMs
  }

  private signature(body: string): Buffer {
    return createHmac('sha256', this.secret).update(body).digest()
  }
}
