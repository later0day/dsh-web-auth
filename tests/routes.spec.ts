import { Readable } from 'node:stream'
import { createHash, randomBytes, scryptSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import type { Context } from '@deepseek-ai/cordis'
import type { CredentialKey, CredentialProvider, CredentialRecord } from '@deepseek-ai/dsh-credentials'
import type { ConnectionRequestRejection, HostConnectionHandle } from '@deepseek-ai/dsh-client-connection'
import type { WebRoute, WebServer } from '@deepseek-ai/dsh-host-webserver'
import { applyRoutes } from '../src/routes.ts'
import { NONCE_COOKIE } from '../src/nonce.ts'
import { PASSWORD_PAYLOAD_VERSION } from '../src/password-record.ts'

const PARAMS = { N: 32768, r: 8, p: 1, keylen: 32 } as const
const HOST = '192.168.1.10:3080'

function grantFor(password: string): CredentialRecord {
  const salt = randomBytes(16)
  const hash = scryptSync(password, salt, PARAMS.keylen, {
    N: PARAMS.N, r: PARAMS.r, p: PARAMS.p, maxmem: 256 * 1024 * 1024,
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

function keyFor(username: string): string {
  return `dsh-web-auth/u${createHash('sha256').update(username, 'utf8').digest('hex')}`
}

/** A captured response: status, headers, and body written by a handler. */
interface Captured {
  status: number
  headers: Record<string, string | string[]>
  body: string
}

/** A node:http-shaped response that records what a handler writes. */
function fakeRes(): { res: import('node:http').ServerResponse; captured: Captured } {
  const captured: Captured = { status: 0, headers: {}, body: '' }
  const res = {
    writeHead(status: number, headers?: Record<string, string | string[]>) {
      captured.status = status
      if (headers !== undefined) Object.assign(captured.headers, headers)
      return this
    },
    end(body?: string) {
      if (body !== undefined) captured.body = body
      return this
    },
  }
  return { res: res as unknown as import('node:http').ServerResponse, captured }
}

/** A node:http-shaped POST request streaming a urlencoded body. */
function fakePost(headers: Record<string, string>, body: string): import('node:http').IncomingMessage {
  const req = Readable.from(body.length > 0 ? [Buffer.from(body, 'utf8')] : []) as unknown as
    import('node:http').IncomingMessage
  Object.assign(req, {
    method: 'POST',
    url: '/auth/login',
    headers: { host: HOST, 'sec-fetch-site': 'same-origin', ...headers },
  })
  return req
}

function fakeGet(headers: Record<string, string> = {}): import('node:http').IncomingMessage {
  return { method: 'GET', url: '/login', headers: { host: HOST, ...headers } } as unknown as import('node:http').IncomingMessage
}

/** Harness under test: capture both route handlers over fakes. */
function boot(options: {
  rejection: () => ConnectionRequestRejection
  records?: Map<string, CredentialRecord>
  users?: Set<string>
  maxAttempts?: number
}): { get: WebRoute['handler']; post: WebRoute['handler']; authenticatedUrlCalls: string[] } {
  const routes = new Map<string, WebRoute['handler']>()
  const webServer = {
    register(route: WebRoute) {
      routes.set(route.path, route.handler)
      return () => routes.delete(route.path)
    },
  } as unknown as WebServer

  const authenticatedUrlCalls: string[] = []
  const connection = {
    requestRejection: () => options.rejection(),
    authenticatedUrl: (base: string) => {
      authenticatedUrlCalls.push(base)
      return `${base}/?token=LAUNCH`
    },
  } as unknown as HostConnectionHandle

  const records = options.records ?? new Map<string, CredentialRecord>()
  const credentials = {
    readRecord: (key: CredentialKey) => Promise.resolve(records.get(key as string)),
  } as unknown as CredentialProvider

  const ctx = { effect: (setup: () => unknown) => { setup() } } as unknown as Context

  applyRoutes(ctx, {
    webServer,
    connection,
    credentials,
    users: options.users ?? new Set(['alice']),
    maxAttempts: options.maxAttempts ?? 5,
    lockoutSeconds: 300,
    nonceTtlSeconds: 300,
  })

  return {
    get: routes.get('/login')!,
    post: routes.get('/auth/login')!,
    authenticatedUrlCalls,
  }
}

/** Render the login form once and pull the nonce out of its hidden field. */
async function mintNonce(get: WebRoute['handler']): Promise<{ nonce: string; cookie: string }> {
  const { res, captured } = fakeRes()
  await get(fakeGet(), res)
  const nonce = /name="nonce" value="([^"]+)"/.exec(captured.body)![1]
  const setCookie = captured.headers['set-cookie'] as string
  const cookie = setCookie.split(';')[0]
  return { nonce, cookie }
}

describe('login routes', () => {
  it('GET /login on a cross-site or untrusted-Host request answers 403', async () => {
    const { get } = boot({ rejection: () => 403 })
    const { res, captured } = fakeRes()
    await get(fakeGet(), res)
    expect(captured.status).toBe(403)
  })

  it('GET /login when already authenticated redirects to /', async () => {
    const { get } = boot({ rejection: () => undefined })
    const { res, captured } = fakeRes()
    await get(fakeGet(), res)
    expect(captured.status).toBe(302)
    expect(captured.headers.location).toBe('/')
  })

  it('GET /login renders the form with no-store and a Strict nonce cookie', async () => {
    const { get } = boot({ rejection: () => 401 })
    const { res, captured } = fakeRes()
    await get(fakeGet(), res)
    expect(captured.status).toBe(200)
    expect(captured.headers['cache-control']).toBe('no-store')
    // same-origin (not no-referrer): under no-referrer the browser sends the
    // login form's own same-origin POST with Origin: null, which Connection's
    // request fence refuses — see http.ts. same-origin keeps the real Origin on
    // the submit while still stripping Referer on cross-site navigations.
    expect(captured.headers['referrer-policy']).toBe('same-origin')
    expect(captured.headers['content-security-policy']).toContain("default-src 'none'")
    expect(String(captured.headers['set-cookie'])).toContain('SameSite=Strict')
    // The cookie must be scoped to a path the POST route (/auth/login) sends
    // it to; a /login-only scope would never reach the submit handler.
    expect(String(captured.headers['set-cookie'])).toContain('Path=/;')
  })

  it('POST rejects a non-POST method with 405', async () => {
    const { post } = boot({ rejection: () => 401 })
    const { res, captured } = fakeRes()
    const req = fakeGet()
    await post(req, res)
    expect(captured.status).toBe(405)
  })

  it('POST with a missing nonce is forbidden before any credential work', async () => {
    const { post } = boot({ rejection: () => 401 })
    const { res, captured } = fakeRes()
    await post(fakePost({ 'content-type': 'application/x-www-form-urlencoded' }, 'username=alice&password=s3cret'), res)
    expect(captured.status).toBe(403)
  })

  it('POST with a cookie/field nonce mismatch is forbidden', async () => {
    const { get, post } = boot({ rejection: () => 401 })
    const { nonce } = await mintNonce(get)
    const { res, captured } = fakeRes()
    await post(fakePost(
      { 'content-type': 'application/x-www-form-urlencoded', cookie: `${NONCE_COOKIE}=different` },
      `username=alice&password=s3cret&nonce=${nonce}`,
    ), res)
    expect(captured.status).toBe(403)
  })

  it('POST with a valid nonce but wrong password re-renders 401', async () => {
    const records = new Map([[keyFor('alice'), grantFor('s3cret')]])
    const { get, post } = boot({ rejection: () => 401, records })
    const { nonce, cookie } = await mintNonce(get)
    const { res, captured } = fakeRes()
    await post(fakePost(
      { 'content-type': 'application/x-www-form-urlencoded', cookie },
      `username=alice&password=wrong&nonce=${nonce}`,
    ), res)
    expect(captured.status).toBe(401)
    expect(captured.body).toContain('role="alert"')
  })

  it('POST with the correct password bridges to authenticatedUrl via 303', async () => {
    const records = new Map([[keyFor('alice'), grantFor('s3cret')]])
    const { get, post, authenticatedUrlCalls } = boot({ rejection: () => 401, records })
    const { nonce, cookie } = await mintNonce(get)
    const { res, captured } = fakeRes()
    await post(fakePost(
      { 'content-type': 'application/x-www-form-urlencoded', cookie },
      `username=alice&password=s3cret&nonce=${nonce}`,
    ), res)
    expect(captured.status).toBe(303)
    expect(captured.headers.location).toBe(`http://${HOST}/?token=LAUNCH`)
    expect(authenticatedUrlCalls).toEqual([`http://${HOST}`])
    // The token appears only in the redirect Location, never in a page body.
    expect(captured.body).toBe('')
  })

  it('honors x-forwarded-proto:https so the redirect stays on https behind a TLS proxy', async () => {
    const records = new Map([[keyFor('alice'), grantFor('s3cret')]])
    const { get, post, authenticatedUrlCalls } = boot({ rejection: () => 401, records })
    const { nonce, cookie } = await mintNonce(get)
    const { res, captured } = fakeRes()
    await post(fakePost(
      { 'content-type': 'application/x-www-form-urlencoded', cookie, 'x-forwarded-proto': 'https' },
      `username=alice&password=s3cret&nonce=${nonce}`,
    ), res)
    expect(captured.status).toBe(303)
    expect(captured.headers.location).toBe(`https://${HOST}/?token=LAUNCH`)
    expect(authenticatedUrlCalls).toEqual([`https://${HOST}`])
  })

  it('locks a username after the attempt limit and answers 429 before scrypt', async () => {
    const records = new Map([[keyFor('alice'), grantFor('s3cret')]])
    const { get, post } = boot({ rejection: () => 401, records, maxAttempts: 2 })
    for (let i = 0; i < 2; i += 1) {
      const { nonce, cookie } = await mintNonce(get)
      const { res } = fakeRes()
      await post(fakePost(
        { 'content-type': 'application/x-www-form-urlencoded', cookie },
        `username=alice&password=wrong&nonce=${nonce}`,
      ), res)
    }
    const { nonce, cookie } = await mintNonce(get)
    const { res, captured } = fakeRes()
    await post(fakePost(
      { 'content-type': 'application/x-www-form-urlencoded', cookie },
      `username=alice&password=s3cret&nonce=${nonce}`,
    ), res)
    expect(captured.status).toBe(429)
    expect(captured.headers['retry-after']).toBeDefined()
  })

  it('POST when already authenticated redirects to / with 303', async () => {
    const { post } = boot({ rejection: () => undefined })
    const { res, captured } = fakeRes()
    await post(fakePost({ 'content-type': 'application/x-www-form-urlencoded' }, ''), res)
    expect(captured.status).toBe(303)
    expect(captured.headers.location).toBe('/')
  })
})
