import { describe, expect, it } from 'vitest'
import { Throttle } from '../src/throttle.ts'

describe('Throttle', () => {
  it('permits attempts below the limit', () => {
    const throttle = new Throttle(3, 1000, () => 0)
    throttle.recordFailure('k')
    throttle.recordFailure('k')
    expect(throttle.retryAfterSeconds('k')).toBe(0)
  })

  it('locks a key at the failure limit and reports the remaining seconds', () => {
    let now = 0
    const throttle = new Throttle(3, 5000, () => now)
    throttle.recordFailure('k')
    throttle.recordFailure('k')
    throttle.recordFailure('k')
    expect(throttle.retryAfterSeconds('k')).toBe(5)
    now = 2000
    expect(throttle.retryAfterSeconds('k')).toBe(3)
  })

  it('clears the lock once the window elapses', () => {
    let now = 0
    const throttle = new Throttle(1, 1000, () => now)
    throttle.recordFailure('k')
    expect(throttle.retryAfterSeconds('k')).toBe(1)
    now = 1000
    expect(throttle.retryAfterSeconds('k')).toBe(0)
  })

  it('reset clears accrued failures', () => {
    let now = 0
    const throttle = new Throttle(2, 1000, () => now)
    throttle.recordFailure('k')
    throttle.reset('k')
    throttle.recordFailure('k')
    expect(throttle.retryAfterSeconds('k')).toBe(0)
  })
})
