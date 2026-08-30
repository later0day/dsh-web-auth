/**
 * CSRF nonce for the login form. GET /login mints a random nonce, holds it in
 * a short-lived server-side set, and returns it both as a `SameSite=Strict`
 * cookie and as a hidden form field. POST /auth/login requires the cookie and
 * field to match a held, unexpired nonce, then consumes it (single use). This
 * defends the password POST against cross-site submission on top of the
 * Host/Origin fence the connection service already applies. Nonces are
 * process-local and expire; the set is swept on each mint.
 * @module @deepseek-ai/dsh-web-auth/nonce
 */

import { randomBytes, timingSafeEqual } from 'node:crypto'

/** The nonce cookie name; scoped and Strict so it never rides a cross-site request. */
export const NONCE_COOKIE = 'dsh-web-auth-nonce'
/** The hidden form field carrying the same nonce. */
export const NONCE_FIELD = 'nonce'

const NONCE_BYTES = 32
const BASE64URL = /^[A-Za-z0-9_-]+$/

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  return ab.byteLength === bb.byteLength && timingSafeEqual(ab, bb)
}

/** Mints, holds, and consumes single-use login nonces with a fixed lifetime. */
export class NonceStore {
  /** value -> expiry epoch ms */
  private readonly live = new Map<string, number>()

  /**
   * @param ttlMs - nonce lifetime in milliseconds.
   * @param now - clock source (injectable for tests); defaults to Date.now.
   */
  constructor(
    private readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  private sweep(): void {
    const t = this.now()
    for (const [value, expiry] of this.live) {
      if (expiry <= t) this.live.delete(value)
    }
  }

  /**
   * Mint a fresh nonce and hold it until it expires.
   * @returns the base64url nonce value.
   */
  issue(): string {
    this.sweep()
    const value = randomBytes(NONCE_BYTES).toString('base64url')
    this.live.set(value, this.now() + this.ttlMs)
    return value
  }

  /**
   * Verify that a cookie/field pair names one held, unexpired nonce, and
   * consume it so it cannot be replayed.
   * @param cookieValue - the nonce from the request cookie.
   * @param fieldValue - the nonce from the submitted form field.
   * @returns true only when both match the same live nonce.
   */
  consume(cookieValue: string | undefined, fieldValue: string | undefined): boolean {
    if (cookieValue === undefined || fieldValue === undefined) return false
    if (!BASE64URL.test(cookieValue) || !BASE64URL.test(fieldValue)) return false
    if (!constantTimeEqual(cookieValue, fieldValue)) return false
    const expiry = this.live.get(cookieValue)
    if (expiry === undefined) return false
    this.live.delete(cookieValue)
    return expiry > this.now()
  }
}

/**
 * Read one cookie value from a Cookie header without a general cookie parser.
 * @param cookieHeader - the raw Cookie header, or undefined.
 * @param name - the cookie name to read.
 * @returns the cookie value, or undefined when absent.
 */
export function readCookie(cookieHeader: string | undefined, name: string): string | undefined {
  if (cookieHeader === undefined) return undefined
  for (const segment of cookieHeader.split(';')) {
    const at = segment.indexOf('=')
    if (at === -1 || segment.slice(0, at).trim() !== name) continue
    return segment.slice(at + 1).trim()
  }
  return undefined
}

/**
 * Serialize the nonce Set-Cookie value. Scoped to `Path=/` so the cookie set
 * by `GET /login` is also sent to `POST /auth/login`, whose only shared path
 * prefix is the root; `SameSite=Strict` and `HttpOnly` remain the cross-site
 * and script-access defenses.
 * @param value - the nonce.
 * @param maxAgeSeconds - cookie lifetime in seconds.
 * @returns the Set-Cookie header value.
 */
export function nonceCookieHeader(value: string, maxAgeSeconds: number): string {
  return `${NONCE_COOKIE}=${value}; Max-Age=${String(maxAgeSeconds)}; Path=/; HttpOnly; SameSite=Strict`
}
