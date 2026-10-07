/**
 * Plugin config: the login user list and the brute-force throttle bounds.
 * Passwords are never configured here — only usernames; each password's scrypt
 * verifier lives in the credentials service (see password-record.ts). The user
 * list is resolved and validated at load so an empty or duplicated list fails
 * loudly rather than yielding a login page no one can pass.
 * @module @deepseek-ai/dsh-web-auth/config
 */

import z from '@deepseek-ai/schemastery'

/** One configured login account; the password verifier lives in credentials. */
export interface UserConfig {
  /** The login name; its scrypt verifier is stored under recordKeyFor(username). */
  username: string
}

/** Plugin configuration as a cordis.yml author writes it. */
export interface Config {
  /** Accounts permitted to log in; at least one is required. */
  users: UserConfig[]
  /** Failed attempts allowed per username and per source before lockout; defaults to 5. */
  maxAttempts?: number
  /** Lockout window in seconds after the attempt limit is reached; defaults to 300. */
  lockoutSeconds?: number
  /** Login-form CSRF nonce lifetime in seconds; defaults to 300. */
  nonceTtlSeconds?: number
}

/** The throttle and nonce knobs after defaults are applied. */
export interface ResolvedConfig {
  maxAttempts: number
  lockoutSeconds: number
  nonceTtlSeconds: number
}

/** Default failures allowed before a username or source locks. */
const DEFAULT_MAX_ATTEMPTS = 5
/** Default lockout window in seconds. */
const DEFAULT_LOCKOUT_SECONDS = 300
/** Default login-form nonce lifetime in seconds. */
const DEFAULT_NONCE_TTL_SECONDS = 300

const userSchema = z.object({
  username: z.string().required(),
})

export const Config = z.object({
  users: z.array(userSchema).default([]),
  maxAttempts: z.natural().min(1).default(DEFAULT_MAX_ATTEMPTS),
  lockoutSeconds: z.natural().min(1).default(DEFAULT_LOCKOUT_SECONDS),
  nonceTtlSeconds: z.natural().min(1).default(DEFAULT_NONCE_TTL_SECONDS),
})

/**
 * Apply the throttle and nonce defaults to a parsed config. Schemastery fills
 * these at parse time; this restates the defaults so the resolved values are
 * required numbers rather than the optionally-typed parsed fields.
 * @param config - the parsed plugin config.
 * @returns the throttle and nonce knobs with defaults applied.
 */
export function resolveConfig(config: Config): ResolvedConfig {
  return {
    maxAttempts: config.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
    lockoutSeconds: config.lockoutSeconds ?? DEFAULT_LOCKOUT_SECONDS,
    nonceTtlSeconds: config.nonceTtlSeconds ?? DEFAULT_NONCE_TTL_SECONDS,
  }
}

/**
 * Validate and normalize the configured user list at load.
 * @param users - the raw user entries.
 * @returns the set of usernames permitted to log in.
 * @throws when the list is empty, or has an empty or duplicated username.
 */
export function resolveUsers(users: readonly UserConfig[]): ReadonlySet<string> {
  if (users.length === 0) {
    throw new Error('dsh-web-auth: at least one user must be configured')
  }
  const names = new Set<string>()
  for (const { username } of users) {
    if (username.length === 0) {
      throw new Error('dsh-web-auth: a configured username is empty')
    }
    if (names.has(username)) {
      throw new Error(`dsh-web-auth: duplicate configured username ${JSON.stringify(username)}`)
    }
    names.add(username)
  }
  return names
}
