/**
 * The self-contained login page. One inline-CSS HTML document with a
 * username/password form and a hidden nonce field; it references no external
 * assets, so it needs no additional public routes and renders under the same
 * strict Content-Security-Policy the route sets. The nonce is emitted into a
 * hidden field and an optional error banner is shown; both interpolated values
 * are HTML-escaped.
 * @module @deepseek-ai/dsh-web-auth/login-page
 */

import { NONCE_FIELD } from './nonce.ts'

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

/**
 * Render the login page.
 * @param nonce - the CSRF nonce for this render.
 * @param error - optional error message shown above the form.
 * @returns the complete HTML document.
 */
export function renderLoginPage(nonce: string, error?: string): string {
  const banner = error === undefined
    ? ''
    : `<p class="error" role="alert">${escapeHtml(error)}</p>`
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
    font: 15px/1.5 system-ui, sans-serif; background: #f5f5f7; color: #1d1d1f; }
  @media (prefers-color-scheme: dark) { body { background: #1d1d1f; color: #f5f5f7; } }
  form { width: min(92vw, 22rem); padding: 2rem; border-radius: 12px;
    background: color-mix(in srgb, Canvas 85%, transparent);
    box-shadow: 0 1px 3px rgba(0,0,0,.15); display: grid; gap: 1rem; }
  h1 { margin: 0 0 .5rem; font-size: 1.25rem; }
  label { display: grid; gap: .35rem; font-weight: 600; }
  input { padding: .6rem .7rem; font-size: 1rem; border: 1px solid #8884;
    border-radius: 8px; background: Field; color: FieldText; }
  button { padding: .65rem; font-size: 1rem; font-weight: 600; border: 0;
    border-radius: 8px; background: #0071e3; color: #fff; cursor: pointer; }
  button:hover { background: #0077ed; }
  .error { margin: 0; padding: .6rem .7rem; border-radius: 8px;
    background: #ff3b3022; color: #c9271e; font-weight: 600; }
</style>
</head>
<body>
<form method="post" action="/auth/login" autocomplete="off">
  <h1>Sign in</h1>
  ${banner}
  <label>Username
    <input name="username" autocomplete="username" autofocus required>
  </label>
  <label>Password
    <input name="password" type="password" autocomplete="current-password" required>
  </label>
  <input type="hidden" name="${NONCE_FIELD}" value="${escapeHtml(nonce)}">
  <button type="submit">Sign in</button>
</form>
</body>
</html>
`
}
