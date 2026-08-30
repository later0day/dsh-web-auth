# dsh-web-auth

A username/password login gate for the DSH Web profile. It adds a login page and a credential-submission route in front of the existing homepage, so the Web GUI can be reached over a LAN without handing every visitor the process launch token printed on the operator's console.

It **adds two routes only** — `GET /login` and `POST /auth/login` — and never touches the harness's existing `/` and `/api` guards. On a correct password it does not mint its own session; it redirects the browser back into the harness's own token→cookie exchange (`connection.authenticatedUrl`), so the cookie a logged-in user carries is the ordinary harness browser-session cookie. The plugin therefore gates access without owning or weakening the request fence.

## Why this exists

`dsh --profile web` binds `127.0.0.1` by default, and the `--host 0.0.0.0` CLI flag is deliberately blocked: exposing the RCE-capable API to the network with only a console-printed token is not a login. The harness homepage *is* already gated — `frontend-static` calls `connection.authorizeIndex` before serving `index.html`, and `/api` is guarded by `connection.requestRejection` — but its "login" is a launch token an operator would have to forward as a whole `?token=` URL, which is a shared bearer secret, not per-person sign-in. This plugin fills that gap with a password form and bridges a success back to the harness token exchange.

## Config

| Field | Default | Meaning |
|---|---|---|
| `users` | — | Accounts permitted to log in; at least one is required. Each is `{ username }` — passwords are **not** configured here (see [Enrolling a password](#enrolling-a-password)). |
| `maxAttempts` | `5` | Failed attempts allowed per username and per source before a lockout. |
| `lockoutSeconds` | `300` | Lockout window after the attempt limit is reached. |
| `nonceTtlSeconds` | `300` | Login-form CSRF nonce lifetime. |

There is deliberately **no session-TTL field**: the logged-in session is the harness browser cookie, whose lifetime is owned by `client-connection`'s `cookieMaxAgeDays`. This plugin reuses that cookie and cannot shorten it; its own time knobs govern only nonce freshness and the throttle window.

`resolveUsers` validates the list at load — an empty list, an empty username, or a duplicate username fails loudly at boot rather than serving a login page no one can pass.

## No path bypass

The user's foremost requirement was that adding routes must not open a path-traversal hole around the existing guards. It cannot, by construction:

The web server dispatcher normalizes the request path exactly once — `new URL(req.url, 'http://x').pathname` — **before** matching, then matches the exact table, then the longest prefix, then the single fallback. The plugin registers `/login` and `/auth/login` as *exact* routes, so:

| Request | Normalized path | Lands on |
|---|---|---|
| `/api/../login` | `/login` | the login page (public by design) |
| `/login/../api/run` | `/api/run` | the `/api` prefix — **still guarded** by the harness |
| `/api/..%2flogin` | `/api/..%2flogin` (`%2f` is not decoded) | the `/api` prefix — guarded |
| `/api/%2e%2e/` | `/` | the fallback homepage — guarded by `authorizeIndex` |

Three properties hold: normalization happens once and before matching (no "normalized to A, dispatched to B" window); `%2f` is not decoded, so an encoded slash cannot forge a path segment; and there is no overlapping fallback the plugin's routes can steal `/` or `/api` traffic into. The added routes sort ahead of the fallback but can never capture a `/` or `/api` request.

Every plugin route additionally calls `connection.requestRejection` first, **reusing** the harness's own Host/Origin fence and browser-authentication state rather than reimplementing either. Its three outcomes drive the flow: `403` (untrusted Host or cross-site) is refused, `undefined` (already authenticated) is sent to `/`, and only `401` (fenced but unauthenticated) reaches the password flow.

## Login flow

**`GET /login`** — `403` → 403; already authenticated → 302 `/`; otherwise render the form with a fresh single-use CSRF nonce (delivered as a `SameSite=Strict; HttpOnly; Path=/` cookie and a hidden field), `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and a strict `Content-Security-Policy` (`default-src 'none'`; inline style only; `form-action 'self'`). The page is self-contained — no external asset URLs.

**`POST /auth/login`** — non-POST → 405; `403` → 403; already authenticated → 303 `/`. Otherwise: read the bounded form body → require the single-use nonce to match its Strict cookie (mismatch → 403, before any credential work) → throttle check per username **and** per source, refusing a locked key with 429 *before* scrypt runs so a locked attacker spends no CPU → `verifyPassword` in constant time. On failure, record the attempt and re-render the form with 401. On success, reset the throttle and 303-redirect to `connection.authenticatedUrl('http://<request-Host>')`.

The browser then follows that redirect to `/?token=…`; `frontend-static` and `authorizeIndex` mint the harness cookie and strip the token with their own no-referrer 303. **The token appears only in that one success redirect's `Location` header — never in a page body and never in a log.**

## Password verification

A password is stored as an scrypt verifier in a `grant` credential record, keyed `dsh-web-auth/u<sha256-hex-of-username>` (the `u` prefix keeps the id a valid lowercase-hex identifier for any username). The payload carries the salt, hash, and the exact cost parameters used, so verification re-derives with the record's own parameters. An unknown or malformed record still runs a dummy scrypt against a throwaway salt, so a missing account and a wrong password take indistinguishable time. The compare guards byte length before `timingSafeEqual`.

Fixed cost parameters (security constants, not tunables): `N=32768, r=8, p=1, keylen=32`, 16-byte salt, `maxmem=256 MiB`.

## Enrolling a password

The harness ships no interactive bin, so passwords are hashed offline and pasted into the credentials document. This one-liner reads the plaintext from an environment variable (never argv, so it does not appear in the process list):

```sh
WEBAUTH_PW='the-password' node --input-type=module -e '
import {scryptSync,randomBytes,createHash} from "node:crypto";
const pw=process.env.WEBAUTH_PW, user=process.argv[1];
const salt=randomBytes(16), N=32768,r=8,p=1,keylen=32;
const hash=scryptSync(pw,salt,keylen,{N,r,p,maxmem:256*1024*1024});
const id="u"+createHash("sha256").update(user).digest("hex");
console.log(`  dsh-web-auth/${id}:\n    kind: grant\n    payload:\n      version: 1\n`+
  `      salt: ${salt.toString("base64")}\n      hash: ${hash.toString("base64")}\n`+
  `      N: ${N}\n      r: ${r}\n      p: ${p}\n      keylen: ${keylen}` );
' <username>
```

Paste the printed block under `records:` in `$DSH_HOME/.credentials.yaml` (mode `0600`), and add `{ username: <username> }` to the plugin's `users`. The plaintext is never stored or logged.

## Wiring

Enable the plugin through a user overlay — a profile's `cordis.patch.yml` under `$DSH_HOME`, or a `--patch` file — not the shipped defaults:

```yaml
- id: '@deepseek-ai/dsh-web-auth'
  config:
    users:
      - username: alice
```

`inject: ['webServer', 'connection', 'credentials']` orders mounting correctly regardless of the entry's position in the file.

### Binding to a LAN (optional, with tradeoffs)

To actually reach the GUI from another machine, override the web server bind host in the same overlay. This bypasses the `--host` CLI block (which lives only in the startup argument parser):

```yaml
- id: webserver
  config:
    host: 0.0.0.0
    port: !!js ctx.webStartup.port ?? 3080   # config replaces wholesale — restate port/compression
- id: connection
  config:
    trustedHosts: [ '192.168.x.x:3080' ]      # MUST exactly match the authority users type, or /api → 403
```

Tradeoffs to accept before doing this: `0.0.0.0` exposes the port to the LAN, with the login page and throttle as the barrier; `trustedHosts` must exactly match the authority in the address users visit (this is the DNS-rebinding defense — a mismatch turns every `/api` call into 403); and the connection is plain HTTP unless you terminate TLS in front of it.

## Model Experience

None. This plugin adds HTTP routes for browser login and contributes nothing to any model request, tool schema, prompt, or session log. It emits no model-visible text and has no KV-cache effect.

## Known Limitations and Deferred Work

- **Coarse revocation only** — deleting a user's credential record blocks *future* logins, but an already-issued harness cookie stays valid up to `cookieMaxAgeDays` (minimum 1 day). There is no per-user immediate kick; the only emergency "log everyone out" is rotating the `client-connection` browser-session HMAC secret, which signs out the operator too.
- **No per-user identity above the gate** — the minted cookie is the shared authority-bound harness cookie, not a per-user session; there are no roles and no audit trail of who logged in.
- **In-memory throttle** — attempt counts are per process and reset on restart; the `GET /login` render path is not rate-limited.
- **Offline password enrollment only** — no interactive set-password command; see [Enrolling a password](#enrolling-a-password).
- **Plain HTTP over a LAN** unless external TLS termination is added.
- **Cross-site defense inherits the harness threat model** — it relies on the browser's Fetch-Metadata/Origin signals through `connection.requestRejection`; this plugin does not change that model.
