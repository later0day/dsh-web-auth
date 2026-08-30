/**
 * In-memory login-attempt throttle. Each key (a username and, separately, a
 * request source) accrues failures; once failures reach the configured limit
 * the key is locked for a fixed window, and the login route rejects with 429
 * before running the password derivation so a locked key cannot drive CPU. A
 * success clears the key. State is per process and resets on restart — this is
 * a brute-force speed bump, not a durable account-lockout record.
 * @module @deepseek-ai/dsh-web-auth/throttle
 */

interface Attempt {
  failures: number
  /** Epoch ms until which the key is locked, or 0 when not locked. */
  lockedUntil: number
}

/** A throttle over string keys with a failure limit and lockout window. */
export class Throttle {
  private readonly attempts = new Map<string, Attempt>()

  /**
   * @param maxAttempts - failures allowed before a key locks.
   * @param lockoutMs - lockout duration in milliseconds.
   * @param now - clock source (injectable for tests); defaults to Date.now.
   */
  constructor(
    private readonly maxAttempts: number,
    private readonly lockoutMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /**
   * Remaining lockout for a key.
   * @param key - the throttled key.
   * @returns seconds left in the lockout, or 0 when the key may attempt.
   */
  retryAfterSeconds(key: string): number {
    const entry = this.attempts.get(key)
    if (entry === undefined || entry.lockedUntil === 0) return 0
    const remainingMs = entry.lockedUntil - this.now()
    if (remainingMs <= 0) {
      // Lock expired: clear it so the next attempt starts fresh.
      this.attempts.delete(key)
      return 0
    }
    return Math.ceil(remainingMs / 1000)
  }

  /**
   * Record one failed attempt for a key, locking it when the limit is reached.
   * @param key - the throttled key.
   */
  recordFailure(key: string): void {
    const entry = this.attempts.get(key) ?? { failures: 0, lockedUntil: 0 }
    entry.failures += 1
    if (entry.failures >= this.maxAttempts) {
      entry.lockedUntil = this.now() + this.lockoutMs
    }
    this.attempts.set(key, entry)
  }

  /**
   * Clear all state for a key after a successful login.
   * @param key - the throttled key.
   */
  reset(key: string): void {
    this.attempts.delete(key)
  }
}
