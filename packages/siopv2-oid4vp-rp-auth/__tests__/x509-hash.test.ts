import { describe, it, expect } from 'vitest'
import { createHash } from 'crypto'
import { PassBy } from '@vess-id/did-auth-siop'
import { createRPBuilder, signCallback } from '../src/functions'
import type { IRPOptions, IRequiredContext } from '../src/types/ISIOPv2RP'

/**
 * CRED-392 / HAIP: the `x509_hash` client_id is `x509_hash:` + base64url(SHA-256(DER(leaf))).
 * These assert the observable output of createRPBuilder — the client_id it sets on the builder —
 * rather than the internal hash helper, so the computation stays covered behaviourally. A minimal
 * stub context lets createRPBuilder skip its agent-backed DID-method and resolver lookups.
 */
describe('createRPBuilder x509_hash client_id', () => {
  const context = {
    agent: { identifierManagedGet: async () => ({ jwkThumbprint: 'test-thumb' }) },
  } as unknown as IRequiredContext

  function pemWrap(der: Buffer): string {
    return `-----BEGIN CERTIFICATE-----\n${der.toString('base64')}\n-----END CERTIFICATE-----`
  }

  async function clientIdFor(certificate: string): Promise<string> {
    const rpOpts = {
      clientIdScheme: 'x509_hash',
      x509Opts: { certificate, keyRef: 'test-key' },
      identifierOpts: {
        idOpts: { identifier: 'did:jwk:eyJ0ZXN0IjoxfQ', kmsKeyRef: 'test-key' },
        supportedDIDMethods: ['jwk'],
        resolveOpts: { resolver: { resolve: async () => ({}) } },
      },
    } as unknown as IRPOptions
    const builder = await createRPBuilder({ rpOpts, context })
    return builder.clientId
  }

  it('sets client_id to x509_hash:base64url(SHA-256(DER(leaf)))', async () => {
    const der = Buffer.from('test-der-bytes-for-leaf-certificate')
    const expected = 'x509_hash:' + createHash('sha256').update(der).digest('base64url')
    expect(await clientIdFor(pemWrap(der))).toBe(expected)
  })

  it('produces a url-safe base64 client_id (no padding or + /)', async () => {
    expect(await clientIdFor(pemWrap(Buffer.from([0xde, 0xad, 0xbe, 0xef])))).toMatch(/^x509_hash:[A-Za-z0-9_-]+$/)
  })

  it('is deterministic and differs for different certificates', async () => {
    const a = pemWrap(Buffer.from('cert-a'))
    const idA1 = await clientIdFor(a)
    const idA2 = await clientIdFor(a)
    expect(idA1).toBe(idA2)
    expect(idA1).not.toBe(await clientIdFor(pemWrap(Buffer.from('cert-b'))))
  })

  it('hashes only the leaf when a chain PEM (leaf + intermediate) is passed', async () => {
    // Passing a concatenated chain must hash SHA-256(DER(leaf)) only, not SHA-256(leaf + intermediate).
    const leafDer = Buffer.from('leaf-certificate-der-bytes')
    const intermediateDer = Buffer.from('intermediate-certificate-der-bytes')
    const leafOnly = await clientIdFor(pemWrap(leafDer))
    expect(await clientIdFor(`${pemWrap(leafDer)}\n${pemWrap(intermediateDer)}`)).toBe(leafOnly)
  })

  it('rejects a certificate that contains no PEM block', async () => {
    await expect(clientIdFor('not a pem')).rejects.toThrow(/valid PEM certificate block/)
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
