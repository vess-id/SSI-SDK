import { describe, it, expect } from 'vitest'
import { createHash } from 'crypto'
import { PassBy } from '@vess-id/did-auth-siop'
import { computeX509HashClientId, pemToBase64, createRPBuilder } from '../src/functions'
import type { IRPOptions, IRequiredContext } from '../src/types/ISIOPv2RP'

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

  it('is stable across separate calls and differs for different input', () => {
    const a = pemWrap(Buffer.from('cert-a'))
    const b = pemWrap(Buffer.from('cert-b'))
    // Store the results of two independent calls so the determinism assertion can actually
    // fail (comparing computeX509HashClientId(a) to itself in one expression is tautological).
    const resultA1 = computeX509HashClientId(a)
    const resultA2 = computeX509HashClientId(a)
    expect(resultA1).toBe(resultA2)
    expect(resultA1).not.toBe(computeX509HashClientId(b))
  })

  it('hashes only the leaf when a chain PEM (leaf + intermediate) is passed', () => {
    // A common mistake is to pass a concatenated chain PEM as the certificate. Stripping all
    // armor and hashing the concatenation would yield SHA-256(DER(leaf) + DER(intermediate)),
    // a silently wrong client_id. Only the first (leaf) block must be hashed.
    const leafDer = Buffer.from('leaf-certificate-der-bytes')
    const intermediateDer = Buffer.from('intermediate-certificate-der-bytes')
    const leafOnly = computeX509HashClientId(pemWrap(leafDer))
    const chainPem = `${pemWrap(leafDer)}\n${pemWrap(intermediateDer)}`
    expect(computeX509HashClientId(chainPem)).toBe(leafOnly)
  })

  it('throws when the input contains no PEM certificate block', () => {
    expect(() => computeX509HashClientId('not a pem')).toThrow(/valid PEM certificate block/)
  })

  it('strips PEM armor and multi-line wrapping (does NOT guard CRLF — see pemToBase64 suite)', () => {
    // NOTE: this only exercises armor/whitespace stripping. It is NOT a CRLF regression test:
    // computeX509HashClientId hashes via Buffer.from(.., 'base64'), which silently discards
    // stray `\r`, so the old `\n`-only pemToBase64 would also pass here. The load-bearing CRLF
    // regression guard lives in the `pemToBase64` describe block below.
    const der = Buffer.from('multi-line-armor-stripping-payload'.repeat(8))
    const expected = createHash('sha256').update(der).digest('base64url')
    const b64 = der.toString('base64')
    const wrapped = (b64.match(/.{1,64}/g) ?? []).join('\n')
    expect(wrapped).toContain('\n') // sanity: the payload really is multi-line
    const pem = `  -----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----  `
    expect(computeX509HashClientId(pem)).toBe(expected)
  })
})

/**
 * This is the documented home of the CRLF regression test. The SHA-256 hash in the suite above
 * is computed via Buffer.from(.., 'base64'), which silently ignores stray `\r`, so it cannot
 * catch the CRLF stripping bug. The actual damage is in the x5c JWT header, which is the raw
 * pemToBase64 output. These assert that output is clean base64 (and would fail on the old
 * `\n`-only implementation).
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

/**
 * Guard coverage for the x509_hash branch of createRPBuilder. These exercise the three throw
 * paths added in this PR (missing x509Opts, empty certificate, unsigned request) so a future
 * refactor that drops a guard is caught. A minimal stub context is used: supportedDIDMethods and
 * a resolveOpts.resolver are supplied so createRPBuilder skips the agent-backed DID-method and
 * resolver lookups, and identifierManagedGet is stubbed (it runs before the client_id branch).
 */
describe('createRPBuilder x509_hash guards', () => {
  const context = {
    agent: { identifierManagedGet: async () => ({ jwkThumbprint: 'test-thumb' }) },
  } as unknown as IRequiredContext

  const baseRpOpts = (overrides: Partial<IRPOptions> = {}): IRPOptions =>
    ({
      clientIdScheme: 'x509_hash',
      identifierOpts: {
        idOpts: { identifier: 'did:jwk:eyJ0ZXN0IjoxfQ', kmsKeyRef: 'test-key' },
        supportedDIDMethods: ['jwk'],
        resolveOpts: { resolver: { resolve: async () => ({}) } },
      },
      ...overrides,
    }) as unknown as IRPOptions

  const validLeafPem = '-----BEGIN CERTIFICATE-----\nZHVtbXktbGVhZg==\n-----END CERTIFICATE-----'

  it('throws when x509Opts is missing', async () => {
    await expect(createRPBuilder({ rpOpts: baseRpOpts(), context })).rejects.toThrow(/x509Opts is required/)
  })

  it('throws when certificate is an empty / whitespace string', async () => {
    const rpOpts = baseRpOpts({ x509Opts: { certificate: '   ', keyRef: 'test-key' } as IRPOptions['x509Opts'] })
    await expect(createRPBuilder({ rpOpts, context })).rejects.toThrow(/non-empty PEM string/)
  })

  it('throws when passBy is NONE (HAIP requires a signed request object)', async () => {
    const rpOpts = baseRpOpts({
      x509Opts: { certificate: validLeafPem, keyRef: 'test-key' } as IRPOptions['x509Opts'],
      clientMetadataOpts: { passBy: PassBy.NONE } as IRPOptions['clientMetadataOpts'],
    })
    await expect(createRPBuilder({ rpOpts, context })).rejects.toThrow(/signed request object/)
  })
})
