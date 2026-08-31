/**
 * node:http helpers shared by the login routes: case-insensitive header
 * reads, a byte-bounded urlencoded form-body reader, and a reply helper that
 * forces `no-store` and `same-origin` referrer on every auth response so
 * credentials and the bridged token never enter a cache or a cross-site
 * Referer. `same-origin` (not `no-referrer`) is required: under `no-referrer`
 * a browser downgrades the Origin header of the login form's own same-origin
 * POST to the opaque literal "null", which Connection's request fence refuses
 * as cross-site (api-request-trust.ts), so every real-browser login 403s.
 * `same-origin` keeps the real Origin on the same-origin submit while still
 * stripping Referer entirely on any cross-site navigation.
 * @module @deepseek-ai/dsh-web-auth/http
 */

import type { IncomingMessage, ServerResponse } from 'node:http'

/** Cap on a login POST body; a form of one nonce plus credentials is tiny. */
const MAX_FORM_BODY_BYTES = 16 * 1024

/**
 * Read one request header as a single string.
 * @param req - the incoming request.
 * @param name - lower-case header name.
 * @returns the header value, or undefined when absent or multi-valued.
 */
export function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return typeof value === 'string' ? value : undefined
}

/**
 * Read and parse an `application/x-www-form-urlencoded` body under a fixed
 * byte cap. A body exceeding the cap rejects rather than buffering unbounded
 * input from a network client.
 * @param req - the incoming POST request.
 * @returns decoded form fields, or undefined when the body exceeds the cap or the stream errors.
 */
export async function readFormBody(
  req: IncomingMessage,
): Promise<URLSearchParams | undefined> {
  const chunks: Buffer[] = []
  let total = 0
  try {
    for await (const chunk of req) {
      const buf = chunk as Buffer
      total += buf.byteLength
      if (total > MAX_FORM_BODY_BYTES) return undefined
      chunks.push(buf)
    }
  } catch {
    return undefined
  }
  return new URLSearchParams(Buffer.concat(chunks).toString('utf8'))
}

/** Security headers forced on every auth response. */
type ReplyHeaders = Record<string, string>

/**
 * Write one complete response with cache and referrer suppression applied.
 * @param res - the response to write.
 * @param status - HTTP status code.
 * @param headers - additional response headers (merged over the forced ones).
 * @param body - optional text body.
 */
export function reply(
  res: ServerResponse,
  status: number,
  headers: ReplyHeaders = {},
  body?: string,
): void {
  res.writeHead(status, {
    'cache-control': 'no-store',
    'referrer-policy': 'same-origin',
    ...headers,
  })
  res.end(body)
}
