import { describe, it, expect } from 'vitest'
import { createHash } from 'crypto'
import { computeX509HashClientId, pemToBase64 } from '../src/functions'

/**
 * CRED-392 / HAIP: client_id for the `x509_hash` Client Identifier Prefix is the
 * base64url encoding of the SHA-256 hash of the DER-encoded leaf certificate.
 */
describe('computeX509HashClientId', () => {
  function pemWrap(der: Buffer): string {
    const b64 = der.toString('base64')
    return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`
  }

  it('returns base64url(SHA-256(DER(leaf))) and strips PEM armor', () => {
    const der = Buffer.from('test-der-bytes-for-leaf-certificate')
    const expected = createHash('sha256').update(der).digest('base64url')
    expect(computeX509HashClientId(pemWrap(der))).toBe(expected)
  })

  it('produces a base64url string without padding or + /', () => {
    const der = Buffer.from([0xde, 0xad, 0xbe, 0xef])
    const value = computeX509HashClientId(pemWrap(der))
    expect(value).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('is stable for identical input and differs for different input', () => {
    const a = pemWrap(Buffer.from('cert-a'))
    const b = pemWrap(Buffer.from('cert-b'))
    expect(computeX509HashClientId(a)).toBe(computeX509HashClientId(a))
    expect(computeX509HashClientId(a)).not.toBe(computeX509HashClientId(b))
  })

  it('tolerates a real multi-line PEM with CRLF line endings and surrounding whitespace', () => {
    // Use enough bytes that the base64 body wraps onto multiple 64-char lines, so the
    // CRLF line breaks land *inside* the base64 payload (not only at the armor boundaries).
    const der = Buffer.from('multi-line-crlf-regression-test-payload'.repeat(8))
    const expected = createHash('sha256').update(der).digest('base64url')
    const b64 = der.toString('base64')
    const wrapped = (b64.match(/.{1,64}/g) ?? []).join('\r\n')
    expect(wrapped).toContain('\r\n') // sanity: the payload really is multi-line
    const pem = `  -----BEGIN CERTIFICATE-----\r\n${wrapped}\r\n-----END CERTIFICATE-----  `
    expect(computeX509HashClientId(pem)).toBe(expected)
  })
})

/**
 * The SHA-256 hash above is computed via Buffer.from(.., 'base64'), which silently ignores
 * stray `\r`, so it cannot catch the CRLF stripping bug. The actual damage is in the x5c JWT
 * header, which is the raw pemToBase64 output. These assert that output is clean base64.
 */
describe('pemToBase64', () => {
  it('strips both CR and LF from a multi-line CRLF PEM (x5c must be clean base64)', () => {
    const der = Buffer.from('x5c-crlf-regression-test-payload'.repeat(8))
    const b64 = der.toString('base64')
    const wrapped = (b64.match(/.{1,64}/g) ?? []).join('\r\n')
    expect(wrapped).toContain('\r\n') // sanity: genuinely multi-line
    const pem = `-----BEGIN CERTIFICATE-----\r\n${wrapped}\r\n-----END CERTIFICATE-----`
    const out = pemToBase64(pem)
    expect(out).not.toContain('\r')
    expect(out).not.toContain('\n')
    expect(out).toBe(b64) // round-trips to the original unwrapped base64
  })

  it('handles LF-only PEMs as well', () => {
    const der = Buffer.from('lf-only-payload'.repeat(8))
    const b64 = der.toString('base64')
    const wrapped = (b64.match(/.{1,64}/g) ?? []).join('\n')
    const pem = `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`
    expect(pemToBase64(pem)).toBe(b64)
  })
})
