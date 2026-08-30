import { describe, expect, it } from 'vitest'
import { Config, resolveUsers } from '../src/config.ts'

describe('Config', () => {
  it('defaults the throttle and nonce knobs', () => {
    const parsed = new Config({ users: [{ username: 'alice' }] })
    expect(parsed).toEqual({
      users: [{ username: 'alice' }],
      maxAttempts: 5,
      lockoutSeconds: 300,
      nonceTtlSeconds: 300,
    })
  })

  it('keeps explicit throttle and nonce knobs', () => {
    const parsed = new Config({
      users: [{ username: 'alice' }],
      maxAttempts: 3,
      lockoutSeconds: 60,
      nonceTtlSeconds: 120,
    })
    expect(parsed.maxAttempts).toBe(3)
    expect(parsed.lockoutSeconds).toBe(60)
    expect(parsed.nonceTtlSeconds).toBe(120)
  })

  it('rejects a zero attempt limit', () => {
    expect(() => new Config({ users: [{ username: 'a' }], maxAttempts: 0 })).toThrow()
  })
})

describe('resolveUsers', () => {
  it('collects the configured usernames', () => {
    expect(resolveUsers([{ username: 'alice' }, { username: 'bob' }]))
      .toEqual(new Set(['alice', 'bob']))
  })

  it('rejects an empty user list', () => {
    expect(() => resolveUsers([])).toThrow(/at least one user/)
  })

  it('rejects an empty username', () => {
    expect(() => resolveUsers([{ username: '' }])).toThrow(/username is empty/)
  })

  it('rejects a duplicate username', () => {
    expect(() => resolveUsers([{ username: 'a' }, { username: 'a' }])).toThrow(/duplicate/)
  })
})
