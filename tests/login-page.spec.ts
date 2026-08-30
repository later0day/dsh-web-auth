import { describe, expect, it } from 'vitest'
import { renderLoginPage } from '../src/login-page.ts'

describe('renderLoginPage', () => {
  it('embeds the nonce in a hidden field and posts to the submit path', () => {
    const html = renderLoginPage('the-nonce')
    expect(html).toContain('action="/auth/login"')
    expect(html).toContain('name="nonce"')
    expect(html).toContain('value="the-nonce"')
  })

  it('omits the error banner when no error is given', () => {
    expect(renderLoginPage('n')).not.toContain('role="alert"')
  })

  it('shows an escaped error banner when given one', () => {
    const html = renderLoginPage('n', 'Bad <x> & "y"')
    expect(html).toContain('role="alert"')
    expect(html).toContain('Bad &lt;x&gt; &amp; &quot;y&quot;')
    expect(html).not.toContain('Bad <x>')
  })

  it('escapes a hostile nonce so it cannot break out of the attribute', () => {
    const html = renderLoginPage('"><script>alert(1)</script>')
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&quot;&gt;&lt;script&gt;')
  })

  it('references no external asset URLs', () => {
    const html = renderLoginPage('n')
    expect(html).not.toMatch(/src=|href=|url\(/)
  })
})
