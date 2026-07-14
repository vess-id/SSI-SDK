import * as x509 from '@peculiar/x509'
import { webcrypto } from 'node:crypto'
import { beforeAll, describe, expect, it } from 'vitest'
import { validateX509CertificateChain } from '../src'

const crypto = webcrypto as unknown as Crypto
x509.cryptoProvider.set(crypto)

const alg = { name: 'ECDSA', namedCurve: 'P-256' }
const signAlg = { name: 'ECDSA', hash: 'SHA-256' }
const notBefore = new Date('2020-01-01')
const notAfter = new Date('2055-01-01')

const genCA = async (name: string, serialNumber: string) => {
  const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
  const cert = await x509.X509CertificateGenerator.createSelfSigned(
    {
      serialNumber,
      name: `CN=${name}`,
      notBefore,
      notAfter,
      signingAlgorithm: signAlg,
      keys,
      extensions: [new x509.BasicConstraintsExtension(true, 2, true)],
    },
    crypto,
  )
  return { keys, cert }
}

const genLeaf = async (name: string, issuerName: string, issuerKeys: CryptoKeyPair, serialNumber: string) => {
  const keys = await crypto.subtle.generateKey(alg, true, ['sign', 'verify'])
  const cert = await x509.X509CertificateGenerator.create(
    {
      serialNumber,
      subject: `CN=${name}`,
      issuer: `CN=${issuerName}`,
      notBefore,
      notAfter,
      signingAlgorithm: signAlg,
      publicKey: keys.publicKey,
      signingKey: issuerKeys.privateKey,
    },
    crypto,
  )
  return { keys, cert }
}

// strict モード相当の opts（trustAnchor 照合の成否が結果の error / trustAnchor に反映される設定）
const strictOpts = { trustRootWhenNoAnchors: false, allowNoTrustAnchorsFound: false }

describe('validateX509CertificateChain trust anchor matching (isSameCertificate)', () => {
  let rootB64: string
  let rootPem: string
  let leafB64: string
  let selfSignedB64: string
  let selfSignedPem: string
  let unrelatedAnchorPem: string

  beforeAll(async () => {
    const root = await genCA('Test Root CA', '01')
    const leaf = await genLeaf('Test Leaf', 'Test Root CA', root.keys, '02')
    const selfSigned = await genCA('Test Self Signed', '03')
    const unrelated = await genCA('Unrelated Trust Anchor', '04')
    rootB64 = root.cert.toString('base64')
    rootPem = root.cert.toString('pem')
    leafB64 = leaf.cert.toString('base64')
    selfSignedB64 = selfSigned.cert.toString('base64')
    selfSignedPem = selfSigned.cert.toString('pem')
    unrelatedAnchorPem = unrelated.cert.toString('pem')
  })

  it('チェーンに含まれる証明書と同一の trust anchor が設定されている場合、trustAnchor がセットされ検証が成功すること', async () => {
    const result = await validateX509CertificateChain({
      chain: [leafB64, rootB64],
      trustAnchors: [rootPem],
      opts: strictOpts,
    })
    expect(result.error).toBe(false)
    expect(result.trustAnchor).toBeDefined()
    expect(result.trustAnchor?.subject.dn.DN).toContain('CN=Test Root CA')
  })

  it('無関係な trust anchor のみ設定されている場合、trustAnchor がセットされず検証が失敗すること', async () => {
    // isSameCertificate が常に true を返すバグ（rawData.toString() 比較）の回帰テスト:
    // 自己署名 root 込みの完全チェーンでも、無関係 anchor では trustAnchor が成立してはならない
    const result = await validateX509CertificateChain({
      chain: [leafB64, rootB64],
      trustAnchors: [unrelatedAnchorPem],
      opts: strictOpts,
    })
    expect(result.error).toBe(true)
    expect(result.trustAnchor).toBeUndefined()
  })

  it('単一の自己署名証明書と同一の trust anchor が設定されている場合、単一証明書パスでも trustAnchor がセットされること', async () => {
    const result = await validateX509CertificateChain({
      chain: [selfSignedB64],
      trustAnchors: [selfSignedPem],
      opts: { ...strictOpts, allowSingleNoCAChainElement: true },
    })
    expect(result.error).toBe(false)
    expect(result.trustAnchor).toBeDefined()
    expect(result.trustAnchor?.subject.dn.DN).toContain('CN=Test Self Signed')
  })

  it('単一の自己署名証明書に無関係な trust anchor のみ設定されている場合、成功応答でも trustAnchor がセットされないこと', async () => {
    const result = await validateX509CertificateChain({
      chain: [selfSignedB64],
      trustAnchors: [unrelatedAnchorPem],
      opts: { ...strictOpts, allowSingleNoCAChainElement: true },
    })
    expect(result.error).toBe(false)
    expect(result.trustAnchor).toBeUndefined()
  })

  it('不正な PEM が trust anchor に含まれる場合、validator が例外を投げること', async () => {
    await expect(
      validateX509CertificateChain({
        chain: [leafB64, rootB64],
        trustAnchors: ['-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----'],
        opts: strictOpts,
      }),
    ).rejects.toThrow()
  })
})
