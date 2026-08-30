import { describe, expect, it } from 'vitest'
import {
  NONCE_COOKIE,
  NonceStore,
  nonceCookieHeader,
  readCookie,
} from '../src/nonce.ts'

describe('NonceStore', () => {
  it('consumes a matching cookie/field pair exactly once', () => {
    const store = new NonceStore(1000, () => 0)
    const nonce = store.issue()
    expect(store.consume(nonce, nonce)).toBe(true)
    // Single use: a replay of the same value fails.
    expect(store.consume(nonce, nonce)).toBe(false)
  })

  it('rejects a mismatched cookie and field', () => {
    const store = new NonceStore(1000, () => 0)
    const a = store.issue()
    const b = store.issue()
    expect(store.consume(a, b)).toBe(false)
  })

  it('rejects a nonce that was never issued', () => {
    const store = new NonceStore(1000, () => 0)
    expect(store.consume('AAAA', 'AAAA')).toBe(false)
  })

  it('rejects an expired nonce', () => {
    let now = 0
    const store = new NonceStore(1000, () => now)
    const nonce = store.issue()
    now = 1000
    expect(store.consume(nonce, nonce)).toBe(false)
  })

  it('rejects a non-base64url value without a store lookup', () => {
    const store = new NonceStore(1000, () => 0)
    expect(store.consume('has space', 'has space')).toBe(false)
  })

  it('rejects when either side is absent', () => {
    const store = new NonceStore(1000, () => 0)
    const nonce = store.issue()
    expect(store.consume(undefined, nonce)).toBe(false)
    expect(store.consume(nonce, undefined)).toBe(false)
  })
})

describe('readCookie', () => {
  it('reads one named cookie from a Cookie header', () => {
    expect(readCookie('a=1; dsh-web-auth-nonce=xyz; b=2', NONCE_COOKIE)).toBe('xyz')
  })

  it('returns undefined when the cookie is absent', () => {
    expect(readCookie('a=1; b=2', NONCE_COOKIE)).toBeUndefined()
  })

  it('returns undefined for no header', () => {
    expect(readCookie(undefined, NONCE_COOKIE)).toBeUndefined()
  })
})

describe('nonceCookieHeader', () => {
  it('scopes the cookie to /, HttpOnly, SameSite=Strict', () => {
    const header = nonceCookieHeader('abc', 300)
    expect(header).toContain(`${NONCE_COOKIE}=abc`)
    expect(header).toContain('Max-Age=300')
    expect(header).toContain('Path=/')
    expect(header).toContain('HttpOnly')
    expect(header).toContain('SameSite=Strict')
  })
})
