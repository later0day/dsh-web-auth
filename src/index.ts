/**
 * @deepseek-ai/dsh-web-auth — a username/password login gate for the Web
 * profile. It adds two routes only (`GET /login`, `POST /auth/login`) and never
 * touches the existing `/` and `/api` guards, so it can gate LAN access without
 * weakening the harness's request fence: a password success bridges back into
 * the harness's own token→cookie exchange through `connection.authenticatedUrl`.
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

/** Services required before the login routes can register. */
export const inject = ['webServer', 'connection', 'credentials']

/**
 * Register the login routes. `resolveUsers` validates the configured user list
 * at load, so an empty or duplicated list fails loudly here rather than serving
 * a login page no one can pass.
 * @param ctx - the plugin context carrying the injected services.
 * @param config - the validated plugin configuration.
 */
export function apply(ctx: Context, config: Config): void {
  const users = resolveUsers(config.users)
  const resolved = resolveConfig(config)
  applyRoutes(ctx, {
    webServer: ctx.webServer,
    connection: ctx.connection,
    credentials: ctx.credentials,
    users,
    maxAttempts: resolved.maxAttempts,
    lockoutSeconds: resolved.lockoutSeconds,
    nonceTtlSeconds: resolved.nonceTtlSeconds,
  })
}
