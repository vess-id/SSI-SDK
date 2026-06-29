import { describe, it, expect } from 'vitest'
import { createHash } from 'crypto'
import { computeX509HashClientId } from '../src/functions'

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

  it('tolerates PEM with CRLF line endings and surrounding whitespace', () => {
    const der = Buffer.from('whitespace-test')
    const expected = createHash('sha256').update(der).digest('base64url')
    const b64 = der.toString('base64')
    const pem = `  -----BEGIN CERTIFICATE-----\r\n${b64}\r\n-----END CERTIFICATE-----  `
    expect(computeX509HashClientId(pem)).toBe(expected)
  })
})
