import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { SdJwtVcPayload, SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc'
import { DisclosureFrame } from '@sd-jwt/types'
import { JwkDIDProvider } from '@sphereon/ssi-sdk-ext.did-provider-jwk'
import { getDidJwkResolver } from '@sphereon/ssi-sdk-ext.did-resolver-jwk'
import { IdentifierResolution, IIdentifierResolution } from '@sphereon/ssi-sdk-ext.identifier-resolution'
import { IJwtService, JwtService } from '@sphereon/ssi-sdk-ext.jwt-service'
import { MemoryKeyStore, MemoryPrivateKeyStore, SphereonKeyManager } from '@sphereon/ssi-sdk-ext.key-manager'
import { SphereonKeyManagementSystem } from '@sphereon/ssi-sdk-ext.kms-local'
import { ImDLMdoc } from '@vess-id/ssi-sdk.mdl-mdoc'
import { createAgent, IAgentPlugin, IDIDManager, IKeyManager, IResolver, TAgent } from '@veramo/core'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { DIDDocument, Resolver, VerificationMethod } from 'did-resolver'
import { defaultGenerateDigest, defaultGenerateSalt } from '../defaultCallbacks'
import { ISDJwtPlugin, SDJwtPlugin } from '../index'

type AgentType = IDIDManager & IKeyManager & IIdentifierResolution & IJwtService & IResolver & ISDJwtPlugin & ImDLMdoc

type X5cMockMode = 'success' | 'error-result' | 'throw'

describe('SDJwtPlugin', () => {
  let agent: TAgent<AgentType>

  let issuer: string

  let holder: string

  let issuerJwk: JsonWebKey

  let holderJwk: JsonWebKey

  let warnSpy: ReturnType<typeof vi.spyOn>

  // Behavior of the mocked x509VerifyCertificateChain, switched per test
  let x5cMockMode: X5cMockMode = 'error-result'
  // JWK returned as the leaf certificate public key when x5cMockMode === 'success'
  let x5cMockSuccessJwk: JsonWebKey | undefined

  const dummyX5c = ['LS0tZHVtbXktbGVhZi1jZXJ0LS0t', 'LS0tZHVtbXktaW50ZXJtZWRpYXRlLWNlcnQtLS0=']

  const claims = {
    sub: '',
    given_name: 'John',
    family_name: 'Deo',
  }

  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['given_name', 'family_name'],
  }

  // Minimal inline plugin that mocks x509VerifyCertificateChain (normally provided by MDLMdoc)
  const x509MockPlugin: IAgentPlugin = {
    methods: {
      x509VerifyCertificateChain: async () => {
        if (x5cMockMode === 'throw') {
          throw new Error('x509VerifyCertificateChain blew up (mock)')
        }
        if (x5cMockMode === 'error-result') {
          return {
            error: true,
            critical: true,
            message: 'Certificate chain validation failed (mock)',
            verificationTime: new Date(),
          }
        }
        return {
          error: false,
          critical: false,
          message: 'Certificate chain validated (mock)',
          verificationTime: new Date(),
          certificateChain: [{ publicKeyJWK: x5cMockSuccessJwk }],
        }
      },
    } as any,
  }

  beforeAll(async () => {
    agent = createAgent<AgentType>({
      plugins: [
        new SDJwtPlugin(),
        x509MockPlugin as any,
        new IdentifierResolution(),
        new JwtService(),
        new SphereonKeyManager({
          store: new MemoryKeyStore(),
          kms: {
            local: new SphereonKeyManagementSystem(new MemoryPrivateKeyStore()),
          },
        }),
        new DIDResolverPlugin({
          resolver: new Resolver({
            ...getDidJwkResolver(),
          }),
        }),
        new DIDManager({
          store: new MemoryDIDStore(),
          defaultProvider: 'did:jwk',
          providers: {
            'did:jwk': new JwkDIDProvider({
              defaultKms: 'local',
            }),
          },
        }),
      ],
    })
    issuer = await agent
      .didManagerCreate({
        kms: 'local',
        provider: 'did:jwk',
        alias: 'issuer',
        //we use this curve since nodejs does not support ES256k which is the default one.
        options: { keyType: 'Secp256r1' },
      })
      .then((did) => `${did.did}#0`)
    holder = await agent
      .didManagerCreate({
        kms: 'local',
        provider: 'did:jwk',
        alias: 'holder',
        //we use this curve since nodejs does not support ES256k which is the default one.
        options: { keyType: 'Secp256r1' },
      })
      .then((did) => `${did.did}#0`)
    claims.sub = holder

    const issuerDidDoc = await agent.resolveDid({ didUrl: issuer })
    issuerJwk = ((issuerDidDoc.didDocument as DIDDocument).verificationMethod as VerificationMethod[])[0].publicKeyJwk as JsonWebKey
    const holderDidDoc = await agent.resolveDid({ didUrl: holder })
    holderJwk = ((holderDidDoc.didDocument as DIDDocument).verificationMethod as VerificationMethod[])[0].publicKeyJwk as JsonWebKey
  })

  beforeEach(() => {
    x5cMockMode = 'error-result'
    x5cMockSuccessJwk = undefined
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  /**
   * Issues an SD-JWT VC signed with the issuer's did:jwk key, but with a custom JOSE header
   * (e.g. containing an x5c chain), which createSdJwtVc does not support for did-based keys.
   */
  async function createCredentialWithHeader(payload: SdJwtVcPayload, header: Record<string, unknown>): Promise<string> {
    const identifier = await agent.identifierManagedGetByDid({ identifier: issuer.split('#')[0] })
    const sdjwt = new SDJwtVcInstance({
      omitTyp: true,
      signer: async (data: string) => agent.keyManagerSign({ keyRef: identifier.kmsKeyRef, data }),
      signAlg: 'ES256',
      hasher: defaultGenerateDigest,
      saltGenerator: defaultGenerateSalt,
      hashAlg: 'sha-256',
    })
    return sdjwt.issue(payload, disclosureFrame as DisclosureFrame<SdJwtVcPayload>, { header: { typ: 'dc+sd-jwt', ...header } })
  }

  it('x5c チェーン検証がエラー結果を返した場合、kid の DID 解決にフォールバックして検証が成功すること', async () => {
    x5cMockMode = 'error-result'
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: issuer,
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { kid: issuer, x5c: dummyX5c },
    )
    const result = await agent.verifySdJwtVc({ credential })
    expect(result).toBeDefined()
    expect((result.payload as typeof claims).given_name).toBe('John')
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('x5c certificate chain validation failed, falling back'))
  })

  it('x5c チェーン検証が成功した場合、x5c 由来の JWK で検証が成功すること', async () => {
    x5cMockMode = 'success'
    x5cMockSuccessJwk = issuerJwk
    // no kid/did fallback possible: success can only come from the x5c-derived JWK
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: 'urn:example:unresolvable-issuer',
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { x5c: dummyX5c },
    )
    const result = await agent.verifySdJwtVc({ credential })
    expect(result).toBeDefined()
    expect((result.payload as typeof claims).given_name).toBe('John')
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('x5c チェーン検証失敗かつフォールバック経路がない場合、エラーを投げること', async () => {
    x5cMockMode = 'error-result'
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: 'urn:example:unresolvable-issuer',
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { x5c: dummyX5c },
    )
    await expect(agent.verifySdJwtVc({ credential })).rejects.toThrow('No valid public key found for signature verification')
  })

  it('x5c チェーン検証失敗時に header.jwk を署名検証に使用しないこと', async () => {
    x5cMockMode = 'error-result'
    // header.jwk is the real issuer key, so signature verification WOULD succeed if it were
    // (incorrectly) used as a fallback after the x5c chain validation failed
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: 'urn:example:unresolvable-issuer',
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { x5c: dummyX5c, jwk: issuerJwk },
    )
    await expect(agent.verifySdJwtVc({ credential })).rejects.toThrow('No valid public key found for signature verification')
  })

  it('x509VerifyCertificateChain が例外を投げた場合、kid の DID 解決にフォールバックして検証が成功すること', async () => {
    x5cMockMode = 'throw'
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: issuer,
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { kid: issuer, x5c: dummyX5c },
    )
    const result = await agent.verifySdJwtVc({ credential })
    expect(result).toBeDefined()
    expect((result.payload as typeof claims).given_name).toBe('John')
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('x509VerifyCertificateChain blew up (mock)'))
  })

  it('verifySdJwtPresentation 経由でも x5c チェーン検証失敗時に kid の DID 解決にフォールバックして検証が成功すること', async () => {
    x5cMockMode = 'error-result'
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: issuer,
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
        cnf: {
          jwk: holderJwk,
        },
      },
      { kid: issuer, x5c: dummyX5c },
    )
    const presentation = await agent.createSdJwtPresentation({
      presentation: credential,
      presentationFrame: { given_name: true },
      kb: {
        payload: {
          aud: '1',
          iat: 1,
          nonce: '342',
        },
      },
    })
    const result = await agent.verifySdJwtPresentation({
      presentation: presentation.presentation,
      requiredClaimKeys: ['given_name'],
      keyBindingAud: '1',
      keyBindingNonce: '342',
    })
    expect(result).toBeDefined()
    expect((result.payload as typeof claims).given_name).toBe('John')
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('x5c certificate chain validation failed, falling back'))
  })
})
