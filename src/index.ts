/**
 * @deepseek-ai/dsh-web-auth — a username/password login gate for the Web
 * profile. It adds two routes only (`GET /login`, `POST /auth/login`) with
 * `auth: 'anonymous'` and never weakens the existing `/` and `/api` guards:
 * a password success mints this plugin's own signed session cookie, and the
 * authentication provider registered on `connection.authentication` returns
 * an owner Peer for requests carrying it, bridging the login into the
 * harness's 0.2.2-rc.3 ConnectionAuthentication model. Browser navigations
 * that would otherwise see a bare 401 are redirected to the login form.
 * This is a function plugin — named `name`/`inject`/`Config`/`apply`, no
 * default export.
 * @module @deepseek-ai/dsh-web-auth
 */

import type { Context } from '@deepseek-ai/cordis'
import { Config, resolveConfig, resolveUsers } from './config.ts'
import { applyRoutes } from './routes.ts'

export { Config } from './config.ts'
export type { UserConfig } from './config.ts'

/** Loader plugin name. */
export const name = '@deepseek-ai/dsh-web-auth'

/** Services required before the login routes and provider can register. */
export const inject = ['webServer', 'connection', 'connection.authentication', 'credentials']

/**
 * Register the login routes and authentication provider. `resolveUsers`
 * validates the configured user list at load, so an empty or duplicated list
 * fails loudly here rather than serving a login page no one can pass.
 * @param ctx - the plugin context carrying the injected services.
 * @param config - the validated plugin configuration.
 */
export async function apply(ctx: Context, config: Config): Promise<void> {
  const users = resolveUsers(config.users)
  const resolved = resolveConfig(config)
  await applyRoutes(ctx, {
    webServer: ctx.webServer,
    connection: ctx.connection,
    credentials: ctx.credentials,
    users,
    maxAttempts: resolved.maxAttempts,
    lockoutSeconds: resolved.lockoutSeconds,
    nonceTtlSeconds: resolved.nonceTtlSeconds,
  })
}
