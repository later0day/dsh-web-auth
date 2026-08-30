/**
 * Package-owned invariant companion for `@deepseek-ai/dsh-web-auth`.
 * @module @deepseek-ai/dsh-web-auth/invariant
 */

/* jscpd:ignore-start */
import type { Context } from '@deepseek-ai/cordis'
import type { InvariantInstaller } from '@deepseek-ai/dsh-invariants'

const PACKAGE_NAME = '@deepseek-ai/dsh-web-auth'

/** Cordis companion plugin name. */
export const name = 'web-auth-invariant'
/** Service required before the companion can reserve package ownership. */
export const inject = ['invariants']

/**
 * No runtime invariant: login is request-scoped and owns no event stream or
 * mutable persistent relation. The harness cookie's lifecycle belongs to
 * `client-connection`, credential records belong to `dsh-credentials`, and the
 * nonce and throttle state are process-local and pinned by this package's unit
 * suite.
 */
const install: InvariantInstaller = () => {}

/**
 * Register this package's invariant companion.
 * @param ctx - Cordis context carrying the invariant service.
 * @returns the installed registration's disposer after setup succeeds.
 */
export const apply = (ctx: Context): Promise<() => void> =>
  Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install))
/* jscpd:ignore-end */
