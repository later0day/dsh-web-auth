/**
 * The two login routes and their shared request flow. Both are registered as
 * exact routes on the web server, so the dispatcher matches them by their
 * verbatim pathname before any prefix route or the fallback; neither can
 * capture a `/` or `/api` request (see README, "No path bypass"). Every
 * request first passes `connection.requestRejection`, reusing Connection's own
 * Host/Origin fence and browser-authentication state rather than reimplementing
 * either: 403 stops a cross-site or untrusted-Host request, an already
 * authenticated request is sent to `/`, and only a fenced-but-unauthenticated
 * request reaches the password flow. A password success bridges back through
 * `connection.authenticatedUrl`, the sole path that mints the harness cookie.
 * @module @deepseek-ai/dsh-web-auth/routes
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Context } from '@deepseek-ai/cordis'
import type { CredentialProvider } from '@deepseek-ai/dsh-credentials'
import type { HostConnectionHandle } from '@deepseek-ai/dsh-client-connection'
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
import { Throttle } from './throttle.ts'
import { verifyPassword } from './verify.ts'

/** The login page path; GET renders the form. */
const LOGIN_PATH = '/login'
/** The credential-submission path; POST verifies and bridges to the harness token. */
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
 * Derive the request authority for the post-login redirect base URL. The
 * request has already passed `requestRejection`, so its Host header names a
 * configured trusted authority; `authenticatedUrl` normalizes path and query.
 * A TLS-terminating reverse proxy forwards `x-forwarded-proto: https` while
 * talking to this server over plain HTTP, so the scheme is read from that
 * header when present — otherwise a browser on https would be redirected to an
 * http URL the proxy does not serve. Only `http` and `https` are honored; any
 * other forwarded value falls back to http.
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

/**
 * Register the login routes on the web server for the life of the given
 * context, wiring the nonce store, throttle, and credential verification.
 * @param ctx - the plugin context whose disposal removes the routes.
 * @param deps - the services and resolved configuration the routes use.
 */
export function applyRoutes(ctx: Context, deps: RouteDeps): void {
  const { webServer, connection, credentials, users } = deps
  const nonces = new NonceStore(deps.nonceTtlSeconds * 1000)
  const throttle = new Throttle(deps.maxAttempts, deps.lockoutSeconds * 1000)

  const renderForm = (res: ServerResponse, status: number, error?: string): void => {
    const nonce = nonces.issue()
    reply(res, status, {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': LOGIN_CSP,
      'set-cookie': nonceCookieHeader(nonce, deps.nonceTtlSeconds),
    }, renderLoginPage(nonce, error))
  }

  const handleGet = (req: IncomingMessage, res: ServerResponse): void => {
    const rejection = connection.requestRejection({ headers: req.headers })
    if (rejection === 403) {
      reply(res, 403, {}, 'forbidden')
      return
    }
    if (rejection === undefined) {
      // Already authenticated: no reason to show the form.
      reply(res, 302, { location: '/' })
      return
    }
    renderForm(res, 200)
  }

  const handlePost = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== 'POST') {
      reply(res, 405, { allow: 'POST' }, 'method not allowed')
      return
    }
    const rejection = connection.requestRejection({ headers: req.headers })
    if (rejection === 403) {
      reply(res, 403, {}, 'forbidden')
      return
    }
    if (rejection === undefined) {
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
    const base = baseUrlFor(req)
    if (base === undefined) {
      reply(res, 400, {}, 'bad request')
      return
    }
    // Bridge to the harness token exchange: the browser follows this redirect
    // to `/?token=`, and Connection's authorizeIndex mints the harness cookie
    // and strips the token. The token appears only in this one Location header.
    reply(res, 303, { location: connection.authenticatedUrl(base) })
  }

  ctx.effect(() => webServer.register({
    kind: 'exact',
    path: LOGIN_PATH,
    handler: handleGet,
  }), 'dsh-web-auth: GET /login')

  ctx.effect(() => webServer.register({
    kind: 'exact',
    path: SUBMIT_PATH,
    handler: handlePost,
  }), 'dsh-web-auth: POST /auth/login')
}
