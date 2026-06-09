import type { SdJwtTypeMetadata, SdJwtVcdm2Payload } from '@sphereon/ssi-types'
// @ts-ignore
import { toString } from 'uint8arrays/to-string'
import { Hasher, HasherSync } from '@sd-jwt/types'
import type { SdJwtPayload } from '@sd-jwt/core'
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc'

// Helper function to fetch API with error handling
export async function fetchUrlWithErrorHandling(url: string): Promise<Response> {
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`${response.status}: ${response.statusText}`)
  }
  return response
}

/**
 * Returns true if the given hostname is a literal IP / name that points at a
 * loopback, link-local, or private (RFC1918 / unique-local) address, or is
 * otherwise an internal target that must not be reachable from an issuer URL.
 *
 * NOTE: this package is built `platform: 'neutral'` (browser + Node), so we
 * cannot resolve DNS here. This guards against IP-literal and obvious internal
 * hostnames only; it does NOT close DNS-rebinding (a public name resolving to a
 * private address). Callers that need that should resolve+pin at a layer that
 * has DNS access, or restrict issuers to an allow-list.
 */
export function isPrivateOrLoopbackHost(hostname: string): boolean {
  // Strip IPv6 brackets if present, e.g. "[::1]"
  let host = hostname.trim().toLowerCase()
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1)
  }

  // Obvious internal / loopback names
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return true
  }

  // IPv4 literal checks
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (ipv4) {
    const [a, b] = [Number(ipv4[1]), Number(ipv4[2])]
    if (a === 0) return true // 0.0.0.0/8
    if (a === 127) return true // loopback 127.0.0.0/8
    if (a === 10) return true // private 10.0.0.0/8
    if (a === 169 && b === 254) return true // link-local 169.254.0.0/16 (incl. cloud metadata)
    if (a === 172 && b >= 16 && b <= 31) return true // private 172.16.0.0/12
    if (a === 192 && b === 168) return true // private 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true // CGNAT 100.64.0.0/10
    return false
  }

  // IPv6 literal checks
  if (host.includes(':')) {
    if (host === '::1' || host === '::') return true // loopback / unspecified
    if (host.startsWith('fe80')) return true // link-local fe80::/10
    if (host.startsWith('fc') || host.startsWith('fd')) return true // unique-local fc00::/7
    // IPv4-mapped IPv6 (::ffff:127.0.0.1 etc.) — re-check the embedded IPv4
    const mapped = host.match(/::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)
    if (mapped) return isPrivateOrLoopbackHost(mapped[1])
    return false
  }

  return false
}

/**
 * Validates that an issuer-derived URL is safe to fetch from the server side:
 * HTTPS-only, and not pointing at an internal/loopback/private host. Throws on
 * violation. Used to mitigate SSRF when resolving JWKS from a JWT `iss`.
 */
export function assertSafeFetchUrl(url: URL): void {
  if (url.protocol !== 'https:') {
    throw new Error('insecure_url: only https issuer URLs are allowed')
  }
  if (isPrivateOrLoopbackHost(url.hostname)) {
    throw new Error('blocked_url: issuer URL resolves to a disallowed (internal/loopback/private) host')
  }
}

/**
 * Fetches JSON from an issuer-derived URL with SSRF mitigations: HTTPS-only,
 * internal-host blocking, and manual redirect handling so every redirect hop is
 * re-validated rather than blindly followed.
 *
 * Upstream error details are intentionally not propagated to the caller to
 * avoid leaking internal network information.
 */
export async function fetchJsonFromIssuerUrl<T>(url: string, maxRedirects = 3): Promise<T> {
  let current = new URL(url)
  for (let hop = 0; hop <= maxRedirects; hop++) {
    assertSafeFetchUrl(current)
    const response = await fetch(current.toString(), { redirect: 'manual' })

    // Manual redirect handling: re-validate the next hop before following it.
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('invalid_redirect: redirect response without a location header')
      }
      current = new URL(location, current)
      continue
    }

    if (!response.ok) {
      // Do not echo upstream status text — avoids leaking internal responses.
      throw new Error(`fetch_failed: request to issuer URL failed with status ${response.status}`)
    }

    return (await response.json()) as T
  }
  throw new Error('too_many_redirects: issuer URL exceeded the allowed redirect count')
}

export type IntegrityAlg = 'sha256' | 'sha384' | 'sha512'

function extractHashAlgFromIntegrity(integrityValue?: string): IntegrityAlg | undefined {
  const val = integrityValue?.toLowerCase().trim().split('-')[0]
  if (val === 'sha256' || val === 'sha384' || val === 'sha512') {
    return val as IntegrityAlg
  }
  return undefined
}

export function extractHashFromIntegrity(integrityValue?: string): string | undefined {
  return integrityValue?.toLowerCase().trim().split('-')[1]
}

export async function validateIntegrity({
  input,
  integrityValue,
  hasher,
}: {
  input: any
  integrityValue?: string
  hasher: HasherSync | Hasher
}): Promise<boolean> {
  if (!integrityValue) {
    return true
  }
  const alg = extractHashAlgFromIntegrity(integrityValue)
  if (!alg) {
    return false
  }
  const calculatedHash = await createIntegrity({ hasher, input, alg })
  return calculatedHash == integrityValue
}

export async function createIntegrity({
  input,
  hasher,
  alg = 'sha256',
}: {
  input: any
  hasher: HasherSync | Hasher
  alg?: IntegrityAlg
}): Promise<string> {
  const calculatedHash = await hasher(typeof input === 'string' ? input : JSON.stringify(input), alg)
  return `${alg}-${toString(calculatedHash, 'base64')}`
}

export function assertValidTypeMetadata(metadata: SdJwtTypeMetadata, vct: string): void {
  if (metadata.vct !== vct) {
    throw new Error('VCT mismatch in metadata and credential')
  }
}

export function isVcdm2SdJwtPayload(payload: SdJwtPayload): payload is SdJwtVcdm2Payload {
  return (
    'type' in payload &&
    Array.isArray(payload.type) &&
    payload.type.includes('VerifiableCredential') &&
    '@context' in payload &&
    ((typeof payload['@context'] === 'string' && payload['@context'].length > 0) ||
      (Array.isArray(payload['@context']) && payload['@context'].length > 0 && payload['@context'].includes('https://www.w3.org/ns/credentials/v2')))
  )
}

export function isSdjwtVcPayload(payload: SdJwtPayload): payload is SdJwtVcPayload {
  return !isVcdm2SdJwtPayload(payload) && 'vct' in payload && typeof payload.vct === 'string'
}

export function getIssuerFromSdJwt(payload: SdJwtPayload): string {
  let issuer: string | undefined
  if (isSdjwtVcPayload(payload) || 'iss' in payload) {
    issuer = payload.iss as string
  } else if (isVcdm2SdJwtPayload(payload) || ('issuer' in payload && payload.issuer)) {
    issuer = typeof payload.issuer === 'string' ? payload.issuer : (payload.issuer as any)?.id
  }

  if (!issuer) {
    throw new Error('No issuer (iss or VCDM 2 issuer) found in SD-JWT or no VCDM2 SD-JWT or SD-JWT VC')
  }
  return issuer
}
