import { describe, it, expect } from 'vitest'
import { createHash } from 'crypto'
import { PassBy } from '@vess-id/did-auth-siop'
import { computeX509HashClientId, createRPBuilder, signCallback } from '../src/functions'
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

  it('strips PEM armor and multi-line wrapping (does NOT guard CRLF — see signCallback x5c suite)', () => {
    // NOTE: this only exercises armor/whitespace stripping. It is NOT a CRLF regression test:
    // computeX509HashClientId hashes via Buffer.from(.., 'base64'), which silently discards
    // stray `\r`, so a `\n`-only strip would also pass here. The load-bearing CRLF regression
    // guard is behavioural and lives in the `signCallback x5c header` describe block below.
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
 * Behavioural home of the CRLF regression test. The bug (a `\r` left in the base64) only shows
 * up in the x5c JWT header that signCallback builds — the SHA-256 hash path masks it because
 * Buffer.from(.., 'base64') silently drops `\r`. So the guard is asserted on signCallback's
 * observable output: the x5c array must be clean base64 even from a CRLF PEM. jwtCreateJwsCompactSignature
 * is stubbed to capture the protected header, so no KMS / jwt-service is required.
 */
describe('signCallback x5c header', () => {
  async function x5cFor(certificate: string, certificateChain?: string[]): Promise<string[]> {
    let capturedHeader: any
    const context = {
      agent: {
        jwtCreateJwsCompactSignature: async (args: any) => {
          capturedHeader = args.protectedHeader
          return { jwt: 'stub.header.signature' }
        },
      },
    } as unknown as IRequiredContext
    const idOpts = { method: 'did', identifier: 'did:jwk:eyJ0ZXN0IjoxfQ', kmsKeyRef: 'test-key' } as any
    const x509Opts = { certificate, certificateChain, keyRef: 'test-key', alg: 'ES256' } as IRPOptions['x509Opts']
    await signCallback(idOpts, context, x509Opts)({ method: 'did' } as any, { header: {}, payload: {} } as any, 'kid')
    return capturedHeader.x5c
  }

  const crlfWrap = (der: Buffer): string =>
    `-----BEGIN CERTIFICATE-----\r\n${(der.toString('base64').match(/.{1,64}/g) ?? []).join('\r\n')}\r\n-----END CERTIFICATE-----`

  it('builds a clean base64 x5c from a multi-line CRLF certificate PEM', async () => {
    const der = Buffer.from('x5c-crlf-regression-payload'.repeat(8))
    const pem = crlfWrap(der)
    expect(pem).toContain('\r\n') // sanity: genuinely CRLF, multi-line
    const x5c = await x5cFor(pem)
    // The load-bearing assertion: a stray `\r`/`\n` here would corrupt the x5c value on the wire.
    expect(x5c[0]).not.toContain('\r')
    expect(x5c[0]).not.toContain('\n')
    expect(x5c[0]).toBe(der.toString('base64')) // round-trips to the unwrapped base64
    expect(x5c).toHaveLength(1)
  })

  it('includes intermediate certs in x5c, each cleaned of CR/LF', async () => {
    const leafDer = Buffer.from('leaf-cert-payload'.repeat(8))
    const intermediateDer = Buffer.from('intermediate-cert-payload'.repeat(8))
    const x5c = await x5cFor(crlfWrap(leafDer), [crlfWrap(intermediateDer)])
    expect(x5c).toHaveLength(2)
    expect(x5c[0]).toBe(leafDer.toString('base64'))
    expect(x5c[1]).toBe(intermediateDer.toString('base64'))
    expect(x5c.every((c) => !/[\r\n]/.test(c))).toBe(true)
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
