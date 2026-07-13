import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { SdJwtVcPayload, SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc'
import { DisclosureFrame } from '@sd-jwt/types'
import { JwkDIDProvider } from '@sphereon/ssi-sdk-ext.did-provider-jwk'
import { getDidJwkResolver } from '@sphereon/ssi-sdk-ext.did-resolver-jwk'
import { IdentifierResolution, IIdentifierResolution } from '@sphereon/ssi-sdk-ext.identifier-resolution'
import { IJwtService, JwtService } from '@sphereon/ssi-sdk-ext.jwt-service'
import { MemoryKeyStore, MemoryPrivateKeyStore, SphereonKeyManager } from '@sphereon/ssi-sdk-ext.key-manager'
import { SphereonKeyManagementSystem } from '@sphereon/ssi-sdk-ext.kms-local'
import { validateX509CertificateChain, type X509CertificateChainValidationOpts } from '@sphereon/ssi-sdk-ext.x509-utils'
import { ImDLMdoc } from '@vess-id/ssi-sdk.mdl-mdoc'
import { createAgent, IAgentPlugin, IDIDManager, IKeyManager, IResolver, TAgent } from '@veramo/core'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { DIDDocument, Resolver, VerificationMethod } from 'did-resolver'
import { defaultGenerateDigest, defaultGenerateSalt } from '../defaultCallbacks'
import { funkeTestCA, sphereonCA } from '../trustAnchors'
import { ISDJwtPlugin, SDJwtPlugin } from '../index'

type AgentType = IDIDManager & IKeyManager & IIdentifierResolution & IJwtService & IResolver & ISDJwtPlugin & ImDLMdoc

/**
 * x509VerifyCertificateChain モックの応答モード:
 * - 'complete-required': チェーン末尾が trustedAnchorPem のときのみ成功（trustAnchor 付き）を返す。
 *   root 除外チェーンが chain completion によってのみ検証成立する状況を再現する。
 * - 'always-success': 常に成功（trustAnchor 付き）を返す。root 入りチェーン（従来型）を再現する。
 * - 'success-no-trust-anchor': 常に error なし・certificateChain ありだが trustAnchor 無しの成功を返す。
 *   validator の単一自己署名証明書パス（allowSingleNoCAChainElement）／allowNoTrustAnchorsFound
 *   による anchor 照合なし成功を再現する。
 */
type X5cMockMode = 'complete-required' | 'always-success' | 'success-no-trust-anchor'

describe('SDJwtPlugin x5c chain completion', () => {
  // 署名鍵・DID を全 agent で共有するためのストア
  const keyStore = new MemoryKeyStore()
  const privateKeyStore = new MemoryPrivateKeyStore()
  const didStore = new MemoryDIDStore()

  let baseAgent: TAgent<AgentType>

  let issuer: string

  let issuerJwk: JsonWebKey

  let warnSpy: ReturnType<typeof vi.spyOn>

  let infoSpy: ReturnType<typeof vi.spyOn>

  // Behavior of the mocked x509VerifyCertificateChain, switched per test
  let x5cMockMode: X5cMockMode = 'complete-required'
  // JWK returned as the leaf certificate public key on mock success
  let x5cMockSuccessJwk: JsonWebKey | undefined
  // Captured arguments of every x509VerifyCertificateChain call
  let x509Calls: Array<{ chain: string[]; trustAnchors?: string[]; opts?: Record<string, unknown> }> = []

  const trustedAnchorPem = '-----BEGIN CERTIFICATE-----\nVEVTVC1UUlVTVEVELUFOQ0hPUg==\n-----END CERTIFICATE-----'
  const unrelatedAnchorPem = '-----BEGIN CERTIFICATE-----\nVEVTVC1VTlJFTEFURUQtQU5DSE9S\n-----END CERTIFICATE-----'
  const unrelatedAnchorPem2 = '-----BEGIN CERTIFICATE-----\nVEVTVC1VTlJFTEFURUQtQU5DSE9SLTI=\n-----END CERTIFICATE-----'
  // モックが「validator が throw するパス」（不正 PEM の anchor 等）を再現するための anchor
  const invalidAnchorPem = '-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----'
  const trustedAnchorSubjectDN = 'CN=Test Trust Anchor'

  const dummyX5c = ['LS0tZHVtbXktbGVhZi1jZXJ0LS0t', 'LS0tZHVtbXktaW50ZXJtZWRpYXRlLWNlcnQtLS0=']

  // ---- 実 validator（x509-utils の validateX509CertificateChain）テスト用の固定フィクスチャ ----
  // @peculiar/x509 の X509CertificateGenerator（ECDSA P-256）で事前生成した自己完結チェーン。
  // 有効期間 2020-01-01〜2055-01-01。CN=X5C Test Root CA（自己署名）が CN=X5C Test Leaf に署名。
  // CN=X5C Unrelated Trust Anchor は無関係の自己署名 CA（正規 anchor 設定の攻撃シナリオ用）。
  const realChainLeafB64 =
    'MIIBJDCBzKADAgECAgECMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMTEFg1QyBUZXN0IFJvb3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjA1NTAxMDEwMDAwMDBaMBgxFjAUBgNVBAMTDVg1QyBUZXN0IExlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATZTkFwH7siM46UApTHCjpqi5NFrEZgd75ruIpVZbX4R+USFNTMXVhO2p162m2mXXryozvl6q3lK1Tykt2SUuajowIwADAKBggqhkjOPQQDAgNHADBEAiBJCk7UQV/ziMU3w6vgGN3ErD5F8sgpwJLM1PwmrQJbCwIgdnBfmUAGQJTuMKhplI5qvJIzNOfR95Kvh77vL/qbIgk='
  const realChainRootB64 =
    'MIIBPTCB46ADAgECAgEBMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMTEFg1QyBUZXN0IFJvb3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjA1NTAxMDEwMDAwMDBaMBsxGTAXBgNVBAMTEFg1QyBUZXN0IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASVRrMxWB0O5TMulc7T6MnniSaNH/WRm5Imljxj0xotNcLGoaPEvZAdA3j/2vgbywse5VIGwBEByPP91pjEZQlHoxYwFDASBgNVHRMBAf8ECDAGAQH/AgECMAoGCCqGSM49BAMCA0kAMEYCIQDky2OvAihry2dV2ao9eZjJhlNHL7/PAOhC526vdmuUfgIhAOPFknYyYU2vadDAsBKUidsppNUjfW78emV2V0TehX+r'
  const realChainRootPem =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBPTCB46ADAgECAgEBMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMTEFg1QyBUZXN0\n' +
    'IFJvb3QgQ0EwIBcNMjAwMTAxMDAwMDAwWhgPMjA1NTAxMDEwMDAwMDBaMBsxGTAX\n' +
    'BgNVBAMTEFg1QyBUZXN0IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n' +
    'AASVRrMxWB0O5TMulc7T6MnniSaNH/WRm5Imljxj0xotNcLGoaPEvZAdA3j/2vgb\n' +
    'ywse5VIGwBEByPP91pjEZQlHoxYwFDASBgNVHRMBAf8ECDAGAQH/AgECMAoGCCqG\n' +
    'SM49BAMCA0kAMEYCIQDky2OvAihry2dV2ao9eZjJhlNHL7/PAOhC526vdmuUfgIh\n' +
    'AOPFknYyYU2vadDAsBKUidsppNUjfW78emV2V0TehX+r\n' +
    '-----END CERTIFICATE-----'
  const realUnrelatedAnchorPem =
    '-----BEGIN CERTIFICATE-----\n' +
    'MIIBUDCB96ADAgECAgEDMAoGCCqGSM49BAMCMCUxIzAhBgNVBAMTGlg1QyBVbnJl\n' +
    'bGF0ZWQgVHJ1c3QgQW5jaG9yMCAXDTIwMDEwMTAwMDAwMFoYDzIwNTUwMTAxMDAw\n' +
    'MDAwWjAlMSMwIQYDVQQDExpYNUMgVW5yZWxhdGVkIFRydXN0IEFuY2hvcjBZMBMG\n' +
    'ByqGSM49AgEGCCqGSM49AwEHA0IABAQs/tSgZpvEnwbQti8PXNKmfrxP37e5JkL4\n' +
    'd7FBDp/I53S38peKQF+yE6+sG0QPLz2tCDIqdTFhkgZk1YS3yySjFjAUMBIGA1Ud\n' +
    'EwEB/wQIMAYBAf8CAQIwCgYIKoZIzj0EAwIDSAAwRQIhAKELJ41Y96xrDX2/1KdI\n' +
    'LM3HeoOg52EngnrpiW3KeCuEAiAkFse6ltMMSNbxdSklx4gewAmSbIGvjzkwUTjp\n' +
    'Q0+JvA==\n' +
    '-----END CERTIFICATE-----'
  // realChainLeafB64 の証明書に対応する秘密鍵（P-256 の d、hex）。KMS に import して leaf 鍵での実署名に使う
  const realChainLeafPrivateKeyHex = 'd640ba7de80cb464c11f930e290107b8320c42850e78dae1335401939458281d'

  const claims = {
    sub: 'test-subject',
    given_name: 'John',
    family_name: 'Deo',
  }

  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['given_name', 'family_name'],
  }

  // Minimal inline plugin that mocks x509VerifyCertificateChain (normally provided by MDLMdoc).
  // 「渡された chain 引数の末尾に anchor が付加されているか」を検査して成功/失敗を切り替えることで、
  // ①そのまま検証→②anchor 付加リトライの呼び出しシーケンス自体を検証できるようにする。
  const x509MockPlugin: IAgentPlugin = {
    methods: {
      x509VerifyCertificateChain: async (args: { chain: string[]; trustAnchors?: string[]; opts?: Record<string, unknown> }) => {
        x509Calls.push({ chain: [...args.chain], trustAnchors: args.trustAnchors, opts: args.opts })
        // 不正 PEM の anchor が付加された completion 試行では実 validator 同様に throw する
        if (args.chain[args.chain.length - 1] === invalidAnchorPem) {
          throw new Error('Cannot parse trust anchor certificate (mock)')
        }
        const successResult = {
          error: false,
          critical: false,
          message: 'Certificate chain validated (mock)',
          verificationTime: new Date(),
          certificateChain: [{ publicKeyJWK: x5cMockSuccessJwk }],
          trustAnchor: { subject: { dn: { DN: trustedAnchorSubjectDN } } },
        }
        if (x5cMockMode === 'always-success') {
          return successResult
        }
        if (x5cMockMode === 'success-no-trust-anchor') {
          const { trustAnchor: _omitted, ...withoutTrustAnchor } = successResult
          return withoutTrustAnchor
        }
        // 'complete-required'
        if (args.chain[args.chain.length - 1] === trustedAnchorPem) {
          return successResult
        }
        return {
          error: true,
          critical: true,
          message: 'Certificate chain validation failed (mock)',
          verificationTime: new Date(),
        }
      },
    } as any,
  }

  // モックではなく workspace の x509-utils 実体（validateX509CertificateChain）へ委譲するプラグイン。
  // 呼び出し引数は x509Calls に記録し、実 validator の挙動（strict バイパス拒否等）を end-to-end で検証する。
  const x509RealPlugin: IAgentPlugin = {
    methods: {
      x509VerifyCertificateChain: async (args: { chain: string[]; trustAnchors?: string[]; opts?: X509CertificateChainValidationOpts }) => {
        x509Calls.push({ chain: [...args.chain], trustAnchors: args.trustAnchors, opts: args.opts as Record<string, unknown> })
        return validateX509CertificateChain({ chain: args.chain, trustAnchors: args.trustAnchors, opts: args.opts })
      },
    } as any,
  }

  function buildAgent(sdJwtPlugin: SDJwtPlugin, x509Plugin: IAgentPlugin = x509MockPlugin): TAgent<AgentType> {
    return createAgent<AgentType>({
      plugins: [
        sdJwtPlugin,
        x509Plugin as any,
        new IdentifierResolution(),
        new JwtService(),
        new SphereonKeyManager({
          store: keyStore,
          kms: {
            local: new SphereonKeyManagementSystem(privateKeyStore),
          },
        }),
        new DIDResolverPlugin({
          resolver: new Resolver({
            ...getDidJwkResolver(),
          }),
        }),
        new DIDManager({
          store: didStore,
          defaultProvider: 'did:jwk',
          providers: {
            'did:jwk': new JwkDIDProvider({
              defaultKms: 'local',
            }),
          },
        }),
      ],
    })
  }

  beforeAll(async () => {
    baseAgent = buildAgent(new SDJwtPlugin())
    issuer = await baseAgent
      .didManagerCreate({
        kms: 'local',
        provider: 'did:jwk',
        alias: 'issuer',
        //we use this curve since nodejs does not support ES256k which is the default one.
        options: { keyType: 'Secp256r1' },
      })
      .then((did) => `${did.did}#0`)

    const issuerDidDoc = await baseAgent.resolveDid({ didUrl: issuer })
    issuerJwk = ((issuerDidDoc.didDocument as DIDDocument).verificationMethod as VerificationMethod[])[0].publicKeyJwk as JsonWebKey
  })

  beforeEach(() => {
    x5cMockMode = 'complete-required'
    x5cMockSuccessJwk = undefined
    x509Calls = []
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
    infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
    infoSpy.mockRestore()
  })

  /**
   * Issues an SD-JWT VC signed with the issuer's did:jwk key, but with a custom JOSE header
   * (e.g. containing an x5c chain), which createSdJwtVc does not support for did-based keys.
   */
  async function createCredentialWithHeader(payload: SdJwtVcPayload, header: Record<string, unknown>): Promise<string> {
    const identifier = await baseAgent.identifierManagedGetByDid({ identifier: issuer.split('#')[0] })
    return createCredentialSignedWithKeyRef(identifier.kmsKeyRef, payload, header)
  }

  /** Same as createCredentialWithHeader, but signs with an explicit KMS keyRef (e.g. an imported x5c leaf key). */
  async function createCredentialSignedWithKeyRef(keyRef: string, payload: SdJwtVcPayload, header: Record<string, unknown>): Promise<string> {
    const sdjwt = new SDJwtVcInstance({
      omitTyp: true,
      signer: async (data: string) => baseAgent.keyManagerSign({ keyRef, data }),
      signAlg: 'ES256',
      hasher: defaultGenerateDigest,
      saltGenerator: defaultGenerateSalt,
      hashAlg: 'sha-256',
    })
    return sdjwt.issue(payload, disclosureFrame as DisclosureFrame<SdJwtVcPayload>, { header: { typ: 'dc+sd-jwt', ...header } })
  }

  it('root 除外チェーンで x5c 検証が失敗した場合、設定した trust anchor をチェーン末尾に付加して再検証し x5c 経路で検証が成功すること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [trustedAnchorPem]))
    x5cMockMode = 'complete-required'
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
    // ①そのまま検証 → ②anchor 付加リトライ の 2 回呼ばれること
    expect(x509Calls).toHaveLength(2)
    expect(x509Calls[0].chain).toEqual(dummyX5c)
    expect(x509Calls[1].chain).toEqual([...dummyX5c, trustedAnchorPem])
    // フォールバック warn が出ないこと・completion 成功の info ログ（subject DN）が出ること
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
    expect(infoSpy).toHaveBeenCalledWith(expect.stringContaining(`x5c chain completed with configured trust anchor: ${trustedAnchorSubjectDN}`))
  })

  it('無関係な trust anchor のみ設定されている場合、chain completion も失敗し warn ログの上で kid の DID 解決にフォールバックして検証が成功すること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [unrelatedAnchorPem]))
    x5cMockMode = 'complete-required'
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
    // ①そのまま検証 → ②無関係 anchor での completion（失敗）の 2 回呼ばれること
    expect(x509Calls).toHaveLength(2)
    expect(x509Calls[1].chain).toEqual([...dummyX5c, unrelatedAnchorPem])
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('x5c certificate chain validation failed, falling back'))
  })

  it('root 入りチェーンが 1 回目の検証で成功した場合、chain completion の再試行を行わないこと', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [trustedAnchorPem]))
    x5cMockMode = 'always-success'
    x5cMockSuccessJwk = issuerJwk
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
    expect(x509Calls).toHaveLength(1)
    expect(x509Calls[0].chain).toEqual(dummyX5c)
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('trust anchor 未設定の場合、デフォルト CA での従来動作（x5c 検証失敗から kid フォールバック）が変わらないこと', async () => {
    const agent = buildAgent(new SDJwtPlugin())
    x5cMockMode = 'complete-required'
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
    // ①そのまま検証 → ②デフォルト CA 2 つでの completion（いずれも失敗）の計 3 回
    expect(x509Calls).toHaveLength(3)
    expect(x509Calls[1].chain).toEqual([...dummyX5c, sphereonCA])
    expect(x509Calls[2].chain).toEqual([...dummyX5c, funkeTestCA])
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('x5c certificate chain validation failed, falling back'))
  })

  it('strict モードで正しい trust anchor が設定されている場合、chain completion で検証が成功すること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [trustedAnchorPem], { mode: 'strict' }))
    x5cMockMode = 'complete-required'
    x5cMockSuccessJwk = issuerJwk
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
    expect(x509Calls).toHaveLength(2)
    expect(x509Calls[1].chain).toEqual([...dummyX5c, trustedAnchorPem])
    // strict 時は fail-close 用の opts が渡ること
    for (const call of x509Calls) {
      expect(call.opts).toEqual({ trustRootWhenNoAnchors: false, allowNoTrustAnchorsFound: false })
    }
  })

  it('strict モードで trust anchor に到達できない場合、kid が解決可能でもフォールバックせず拒否されること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [unrelatedAnchorPem], { mode: 'strict' }))
    x5cMockMode = 'complete-required'
    // kid は解決可能な DID: 非 strict であればフォールバックで検証が成功してしまう条件
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: issuer,
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { kid: issuer, x5c: dummyX5c },
    )
    const error = await agent.verifySdJwtVc({ credential }).then(
      () => undefined,
      (e: unknown) => e as Error,
    )
    expect(error?.message).toContain('invalid_issuer: x5c certificate chain validation failed (strict mode)')
    // completion 試行も失敗した旨と個別失敗理由がメッセージに含まれること（m-2）
    expect(error?.message).toContain('Chain completion with 1 configured trust anchor(s) also failed')
    expect(error?.message).toContain('Certificate chain validation failed (mock)')
    // ①＋②（1 anchor）で終わり、フォールバックの warn は出ないこと
    expect(x509Calls).toHaveLength(2)
    for (const call of x509Calls) {
      expect(call.opts).toEqual({ trustRootWhenNoAnchors: false, allowNoTrustAnchorsFound: false })
    }
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('strict モードで単一自己署名証明書の x5c が提示された場合、実 validator の trustAnchor 無し成功応答が拒否されること', async () => {
    // 実 validator: 単一自己署名証明書は allowSingleNoCAChainElement パスで error: false・trustAnchor 無しを
    // 返すため、strict の trustAnchor 必須判定で拒否されることを（モックでなく）実挙動で検証する
    const agent = buildAgent(new SDJwtPlugin(undefined, [realUnrelatedAnchorPem], { mode: 'strict' }), x509RealPlugin)
    // kid は解決可能な DID: 非 strict であればフォールバックで検証が成功してしまう条件
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: issuer,
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { kid: issuer, x5c: [realChainRootB64] },
    )
    await expect(agent.verifySdJwtVc({ credential })).rejects.toThrow('invalid_issuer: x5c certificate chain validation failed (strict mode)')
    // ①＋②（1 anchor）とも実 validator を通ること
    expect(x509Calls).toHaveLength(2)
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('strict モードで攻撃者の自作 leaf と自己署名 root の完全チェーンが提示された場合、無関係な正規 anchor 設定では実 validator で拒否されること', async () => {
    // 実 validator: 自己署名 root 込みの「チェーンとしては正しい」x5c でも、設定済み anchor に到達しない限り
    // strict では受理されないこと（isSameCertificate の anchor 照合が機能していること）を検証する
    const agent = buildAgent(new SDJwtPlugin(undefined, [realUnrelatedAnchorPem], { mode: 'strict' }), x509RealPlugin)
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: issuer,
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { kid: issuer, x5c: [realChainLeafB64, realChainRootB64] },
    )
    const error = await agent.verifySdJwtVc({ credential }).then(
      () => undefined,
      (e: unknown) => e as Error,
    )
    expect(error?.message).toContain('invalid_issuer: x5c certificate chain validation failed (strict mode)')
    // ①の失敗理由（anchor 不到達）と completion 失敗の旨がメッセージに含まれること
    expect(error?.message).toContain('Chain completion with 1 configured trust anchor(s) also failed')
    expect(x509Calls).toHaveLength(2)
    expect(x509Calls[1].chain).toEqual([realChainLeafB64, realChainRootB64, realUnrelatedAnchorPem])
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('strict モードで root 入りチェーンと一致する trust anchor が設定されている場合、実 validator の 1 回目の検証で成功し completion 再試行を行わないこと', async () => {
    // strict の過剰拒否がないことの固定: 正規の root 入りチェーン＋一致 anchor は①で受理される
    const agent = buildAgent(new SDJwtPlugin(undefined, [realChainRootPem], { mode: 'strict' }), x509RealPlugin)
    // leaf 証明書の秘密鍵を KMS に import し、x5c 経路（leaf の publicKeyJWK）でのみ署名検証が成立する状況を作る
    const importedKey = await baseAgent.keyManagerImport({
      kid: 'x5c-test-leaf-key',
      kms: 'local',
      type: 'Secp256r1',
      privateKeyHex: realChainLeafPrivateKeyHex,
    })
    const credential = await createCredentialSignedWithKeyRef(
      importedKey.kid,
      {
        ...claims,
        iss: 'urn:example:unresolvable-issuer',
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { x5c: [realChainLeafB64, realChainRootB64] },
    )
    const result = await agent.verifySdJwtVc({ credential })
    expect(result).toBeDefined()
    expect((result.payload as typeof claims).given_name).toBe('John')
    expect(x509Calls).toHaveLength(1)
    expect(x509Calls[0].chain).toEqual([realChainLeafB64, realChainRootB64])
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('複数の trust anchor が設定されている場合、1 番目の anchor の completion が失敗しても 2 番目の anchor で成功し以降の試行を打ち切ること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [unrelatedAnchorPem, trustedAnchorPem, unrelatedAnchorPem2]))
    x5cMockMode = 'complete-required'
    x5cMockSuccessJwk = issuerJwk
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
    // ① → ②1番目（失敗）→ ②2番目（成功）で break し、3 番目の anchor は試行しないこと
    expect(x509Calls).toHaveLength(3)
    expect(x509Calls[1].chain).toEqual([...dummyX5c, unrelatedAnchorPem])
    expect(x509Calls[2].chain).toEqual([...dummyX5c, trustedAnchorPem])
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('不正な PEM の anchor で validator が throw しても、後続 anchor の completion 試行が継続され検証が成功すること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [invalidAnchorPem, trustedAnchorPem]))
    x5cMockMode = 'complete-required'
    x5cMockSuccessJwk = issuerJwk
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
    // ① → ②不正 anchor（throw）→ ②正しい anchor（成功）と、throw が後続試行を道連れにしないこと
    expect(x509Calls).toHaveLength(3)
    expect(x509Calls[1].chain).toEqual([...dummyX5c, invalidAnchorPem])
    expect(x509Calls[2].chain).toEqual([...dummyX5c, trustedAnchorPem])
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('非 strict モードではデフォルトの validationOpts（trustRootWhenNoAnchors: true, allowNoTrustAnchorsFound: true）が x509VerifyCertificateChain に渡ること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [trustedAnchorPem]))
    x5cMockMode = 'complete-required'
    x5cMockSuccessJwk = issuerJwk
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: 'urn:example:unresolvable-issuer',
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { x5c: dummyX5c },
    )
    await agent.verifySdJwtVc({ credential })
    // ①②とも後方互換のデフォルト opts で呼ばれること（回帰検出）
    expect(x509Calls).toHaveLength(2)
    for (const call of x509Calls) {
      expect(call.opts).toEqual({ trustRootWhenNoAnchors: true, allowNoTrustAnchorsFound: true })
    }
  })

  it('非 strict モードでは trustAnchor 無しの成功応答でも従来どおり検証が成功すること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [trustedAnchorPem]))
    x5cMockMode = 'success-no-trust-anchor'
    x5cMockSuccessJwk = issuerJwk
    // no kid/did fallback possible: success can only come from the x5c-derived JWK
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: 'urn:example:unresolvable-issuer',
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { x5c: [dummyX5c[0]] },
    )
    const result = await agent.verifySdJwtVc({ credential })
    expect(result).toBeDefined()
    expect((result.payload as typeof claims).given_name).toBe('John')
    // 非 strict では trustAnchor 無しでも①で成功と判定され、completion は行われないこと
    expect(x509Calls).toHaveLength(1)
    expect(warnSpy).not.toHaveBeenCalledWith(expect.stringContaining('falling back'))
  })

  it('strict モードでも x5c ヘッダの無い提示は従来どおり kid 解決で検証が成功すること', async () => {
    const agent = buildAgent(new SDJwtPlugin(undefined, [trustedAnchorPem], { mode: 'strict' }))
    x5cMockMode = 'complete-required'
    const credential = await createCredentialWithHeader(
      {
        ...claims,
        iss: issuer,
        iat: Math.floor(new Date().getTime() / 1000),
        vct: '',
      },
      { kid: issuer },
    )
    const result = await agent.verifySdJwtVc({ credential })
    expect(result).toBeDefined()
    expect((result.payload as typeof claims).given_name).toBe('John')
    // x5c が無いので x509 検証は一切呼ばれないこと（strict は x5c 経路のみに作用）
    expect(x509Calls).toHaveLength(0)
  })
})
