/**
 * The two login routes and the authentication provider. Both routes are
 * registered as exact routes on the web server with `auth: 'anonymous'` (the
 * 0.2.2-rc.3 default is 'required', which would 503 the login form itself),
 * so the dispatcher matches them by their verbatim pathname before any prefix
 * route or the fallback; neither can capture a `/` or `/api` request (see
 * README, "No path bypass"). Every route request still passes the WebServer's
 * authorize step — Connection's `webserver/authorize` listener applies the
 * Host/Origin fence for anonymous routes too, so a cross-site or
 * untrusted-Host request is refused with 403 before the handler runs.
 *
 * A password success mints this plugin's own signed session cookie (see
 * session.ts); the authentication provider registered on
 * `connection.authentication` returns the plugin's owner Peer for a request
 * carrying a valid cookie, which admits every harness surface that would
 * otherwise require the (removed) token→cookie bridge. An unauthenticated
 * page navigation is redirected to `/login` via the 401 response rewriter, so
 * the browser lands on the form instead of a bare 401 body.
 * @module @deepseek-ai/dsh-web-auth/routes
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import type { ConnectionTrustRequest, HostConnectionHandle, PeerScope } from '@deepseek-ai/dsh-client-connection'
import type { WebServer } from '@deepseek-ai/dsh-host-webserver'
import { header, readFormBody, reply } from './http.ts'
import { renderLoginPage } from './login-page.ts'
import {
  NONCE_COOKIE,
  NONCE_FIELD,
  NonceStore,
  nonceCookieHeader,
  readCookie,
} from './nonce.ts'
import { SessionAuth } from './session.ts'
import { Throttle } from './throttle.ts'
import { verifyPassword } from './verify.ts'

/** The login page path; GET renders the form. */
const LOGIN_PATH = '/login'
/** The credential-submission path; POST verifies and mints the session cookie. */
const SUBMIT_PATH = '/auth/login'

/**
 * The Content-Security-Policy for the login page: no external anything, inline
 * style only (the page's own `<style>`), and forms may target only this origin.
 */
const LOGIN_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

/** Services the routes hold for the life of the registration. */
export interface RouteDeps {
  readonly webServer: WebServer
  readonly connection: HostConnectionHandle
  readonly credentials: CredentialProvider
  /** Usernames permitted to log in, resolved from config at load. */
  readonly users: ReadonlySet<string>
  readonly maxAttempts: number
  readonly lockoutSeconds: number
  readonly nonceTtlSeconds: number
}

/**
 * Derive the request authority for the throttle source key. The request has
 * already passed the authorize fence, so its Host header names a configured
 * trusted authority. A TLS-terminating reverse proxy forwards
 * `x-forwarded-proto: https` while talking to this server over plain HTTP, so
 * the scheme is read from that header when present. Only `http` and `https`
 * are honored; any other forwarded value falls back to http.
 * @param req - the fenced login request.
 * @returns a `<scheme>://<authority>` base URL, or undefined when the Host header is absent.
 */
function baseUrlFor(req: IncomingMessage): string | undefined {
  const host = header(req, 'host')
  if (host === undefined || host.length === 0) return undefined
  const forwarded = header(req, 'x-forwarded-proto')?.split(',')[0]?.trim()
  const scheme = forwarded === 'https' ? 'https' : 'http'
  return `${scheme}://${host}`
}

/** Header facts the provider and cookie minting share. */
function trustRequest(req: IncomingMessage): ConnectionTrustRequest {
  return { headers: req.headers, method: req.method, url: req.url, socket: { destroyed: req.socket?.destroyed ?? false } }
}

/**
 * Register the login routes and authentication provider for the life of the
 * given context, wiring the nonce store, throttle, session cookies, and
 * credential verification.
 * @param ctx - the plugin context whose disposal removes the registrations.
 * @param deps - the services and resolved configuration the routes use.
 */
export async function applyRoutes(ctx: Context, deps: RouteDeps): Promise<void> {
  const { webServer, connection, credentials, users } = deps
  const sessions = await SessionAuth.create(credentials)
  const nonces = new NonceStore(deps.nonceTtlSeconds * 1000)
  const throttle = new Throttle(deps.maxAttempts, deps.lockoutSeconds * 1000)
  // One owner Peer backs every cookie-authenticated request; the harness's
  // own token plugin does the same for its cookie audience.
  const peer: PeerScope = connection.createPeer({ principal: { kind: 'owner' } })

  const isSecure = (): boolean => ctx.get('webServer')?.protocol === 'https:'

  connection.authentication.register({
    authenticate(request) {
      return sessions.verify(request, isSecure()) ? peer : undefined
    },
  })

  // Route the unauthenticated browser to the form: a plain 401 body leaves the
  // user at an opaque error page. Only browser navigations redirect; the
  // SPA's own API calls must see a real 401 to trigger their reconnect flow.
  ctx.on('webserver/request', async (request, response, next) => {
    const facts: ConnectionTrustRequest = request
    if (facts.socket?.destroyed || response.destroyed || facts.signal?.aborted) return
    const url = new URL(request.url ?? '/', 'http://dsh.invalid')
    const isNavigation = (request.headers['sec-fetch-mode'] ?? '') === 'navigate'
    if (url.pathname === LOGIN_PATH || url.pathname === SUBMIT_PATH || !isNavigation) {
      await next()
      return
    }
    // Observe the harness 401 before it is written: run the dispatch chain,
    // and when it ended answering 401 without writing headers yet, redirect.
    let sawDeny = false
    const originalWriteHead = response.writeHead.bind(response)
    const instrumented = response.writeHead as unknown as { __dshWebAuthHook?: boolean }
    if (instrumented.__dshWebAuthHook !== true) {
      instrumented.__dshWebAuthHook = true
      response.writeHead = ((status: number, headers?: object) => {
        if (status === 401) sawDeny = true
        return originalWriteHead(status as never, headers as never)
      }) as typeof response.writeHead
    }
    try {
      await next()
    } finally {
      response.writeHead = originalWriteHead
      instrumented.__dshWebAuthHook = false
    }
    if (sawDeny && !response.headersSent) {
      response.writeHead(302, { 'cache-control': 'no-store', location: LOGIN_PATH })
      response.end()
    }
  })

  const renderForm = (res: ServerResponse, status: number, error?: string): void => {
    const nonce = nonces.issue()
    reply(res, status, {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': LOGIN_CSP,
      'set-cookie': nonceCookieHeader(nonce, deps.nonceTtlSeconds),
    }, renderLoginPage(nonce, error))
  }

  const handleGet = (req: IncomingMessage, res: ServerResponse, peerArg?: PeerScope): void => {
    if (peerArg !== undefined) {
      // Already authenticated (the provider accepted this request): no form.
      reply(res, 302, { location: '/' })
      return
    }
    renderForm(res, 200)
  }

  const handlePost = async (req: IncomingMessage, res: ServerResponse, peerArg?: PeerScope): Promise<void> => {
    if (req.method !== 'POST') {
      reply(res, 405, { allow: 'POST' }, 'method not allowed')
      return
    }
    if (peerArg !== undefined) {
      reply(res, 303, { location: '/' })
      return
    }

    const form = await readFormBody(req)
    // A single-use nonce that matches its Strict cookie is required before any
    // credential work, so a cross-site POST cannot drive verification or CPU.
    const nonceOk = nonces.consume(
      readCookie(header(req, 'cookie'), NONCE_COOKIE),
      form?.get(NONCE_FIELD) ?? undefined,
    )
    if (form === undefined || !nonceOk) {
      reply(res, 403, {}, 'forbidden')
      return
    }

    const username = form.get('username') ?? ''
    const password = form.get('password') ?? ''
    // Throttle per submitted username and per source authority; a locked key is
    // refused before scrypt runs, so a locked attacker cannot spend CPU.
    const source = baseUrlFor(req) ?? 'unknown'
    const keys = [`u:${username}`, `s:${source}`]
    const lockedFor = Math.max(...keys.map(key => throttle.retryAfterSeconds(key)))
    if (lockedFor > 0) {
      reply(res, 429, { 'retry-after': String(lockedFor) }, 'too many attempts')
      return
    }

    const known = users.has(username)
    const ok = known && await verifyPassword(credentials, username, password)
    if (!ok) {
      for (const key of keys) throttle.recordFailure(key)
      renderForm(res, 401, 'Incorrect username or password.')
      return
    }

    for (const key of keys) throttle.reset(key)
    // Mint this plugin's own session cookie; the redirect target is the clean
    // root, and the provider accepts the cookie on the next request.
    reply(res, 303, { location: '/', 'set-cookie': sessions.cookieFor(req.headers, isSecure()) })
  }

  ctx.effect(() => webServer.register({
    kind: 'exact',
    path: LOGIN_PATH,
    auth: 'anonymous',
    handler: handleGet,
  }), 'dsh-web-auth: GET /login')

  ctx.effect(() => webServer.register({
    kind: 'exact',
    path: SUBMIT_PATH,
    auth: 'anonymous',
    handler: handlePost,
  }), 'dsh-web-auth: POST /auth/login')
}
