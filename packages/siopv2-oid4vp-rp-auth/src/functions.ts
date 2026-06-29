import {
  ClientIdentifierPrefix,
  ClientMetadataOpts,
  DcqlQueryLookupCallback,
  InMemoryRPSessionManager,
  PassBy,
  PresentationVerificationCallback,
  PresentationVerificationResult,
  PropertyTarget,
  ResponseMode,
  ResponseType,
  RevocationVerification,
  RP,
  RPBuilder,
  Scope,
  SubjectType,
  SupportedVersion,
  VerifyJwtCallback,
} from '@vess-id/did-auth-siop'
import { CreateJwtCallback, JwtHeader, JwtIssuer, JwtPayload, SigningAlgo } from '@vess-id/oid4vc-common'
import { IPresentationDefinition } from '@sphereon/pex'
import { getAgentDIDMethods, getAgentResolver } from '@sphereon/ssi-sdk-ext.did-utils'
import {
  isExternalIdentifierOIDFEntityIdOpts,
  isManagedIdentifierDidOpts,
  isManagedIdentifierDidResult,
  isManagedIdentifierX5cOpts,
  ManagedIdentifierOptsOrResult,
} from '@sphereon/ssi-sdk-ext.identifier-resolution'
import { JwtCompactResult } from '@sphereon/ssi-sdk-ext.jwt-service'
import { IVerifySdJwtPresentationResult } from '@vess-id/ssi-sdk.sd-jwt'
import { CredentialMapper, HasherSync, OriginalVerifiableCredential, PresentationSubmission } from '@sphereon/ssi-types'
import { IVerifyCallbackArgs, IVerifyCredentialResult, VerifyCallback } from '@sphereon/wellknown-dids-client'
import { TKeyType } from '@veramo/core'
import { JWTVerifyOptions } from 'did-jwt'
import { Resolvable } from 'did-resolver'
import { EventEmitter } from 'events'
import { validate as isValidUUID } from 'uuid'
import { IRequiredContext, IRPOptions, ISIOPIdentifierOptions } from './types/ISIOPv2RP'
import { DcqlQuery } from 'dcql'
import { defaultHasher } from '@sphereon/ssi-sdk.core'
import { createHash } from 'crypto'

export function getRequestVersion(rpOptions: IRPOptions): SupportedVersion {
  if (Array.isArray(rpOptions.supportedVersions) && rpOptions.supportedVersions.length > 0) {
    return rpOptions.supportedVersions[0]
  }
  return SupportedVersion.OID4VP_v1
}

function getWellKnownDIDVerifyCallback(siopIdentifierOpts: ISIOPIdentifierOptions, context: IRequiredContext) {
  return siopIdentifierOpts.wellknownDIDVerifyCallback
    ? siopIdentifierOpts.wellknownDIDVerifyCallback
    : async (args: IVerifyCallbackArgs): Promise<IVerifyCredentialResult> => {
        const result = await context.agent.cvVerifyCredential({
          credential: args.credential as OriginalVerifiableCredential,
          fetchRemoteContexts: true,
        })
        return { verified: result.result }
      }
}

export function getDcqlQueryLookupCallback(context: IRequiredContext): DcqlQueryLookupCallback {
  async function dcqlQueryLookup(queryId: string, version?: string, tenantId?: string): Promise<DcqlQuery> {
    console.log('[DCQL LOOKUP] Starting lookup for queryId:', queryId, 'version:', version, 'tenantId:', tenantId)
    // TODO Add caching?
    const filter = [
      {
        queryId,
        ...(tenantId && { tenantId }),
        ...(version && { version }),
      },
      ...(isValidUUID(queryId) ? [{ id: queryId }] : []),
    ]
    console.log('[DCQL LOOKUP] Filter:', JSON.stringify(filter, null, 2))

    const result = await context.agent.pdmGetDefinitions({
      filter,
    })
    console.log('[DCQL LOOKUP] Result count:', result?.length, 'results:', JSON.stringify(result, null, 2))

    if (result && result.length > 0) {
      console.log('[DCQL LOOKUP] Found DCQL query:', JSON.stringify(result[0].query, null, 2))
      return result[0].query
    }

    console.error('[DCQL LOOKUP] No dcql query found for queryId:', queryId)
    return Promise.reject(Error(`No dcql query found for queryId ${queryId}`))
  }

  return dcqlQueryLookup
}

export function getPresentationVerificationCallback(
  idOpts: ManagedIdentifierOptsOrResult,
  context: IRequiredContext,
): PresentationVerificationCallback {
  async function presentationVerificationCallback(
    args: any, // FIXME any
    presentationSubmission?: PresentationSubmission,
  ): Promise<PresentationVerificationResult> {
    if (CredentialMapper.isSdJwtEncoded(args)) {
      const result: IVerifySdJwtPresentationResult = await context.agent.verifySdJwtPresentation({
        presentation: args,
      })
      // fixme: investigate the correct way to handle this
      return { verified: !!result.payload }
    }

    if (CredentialMapper.isMsoMdocOid4VPEncoded(args)) {
      // TODO Funke reevaluate
      if (context.agent.mdocOid4vpRPVerify === undefined) {
        return Promise.reject('ImDLMdoc agent plugin must be enabled to support MsoMdoc types')
      }
      // OID4VP 1.0 DCQL: presentation_submission is optional
      const mdocArgs: any = { vp_token: args }
      if (presentationSubmission) {
        mdocArgs.presentation_submission = presentationSubmission
      }
      const verifyResult = await context.agent.mdocOid4vpRPVerify(mdocArgs)
      return { verified: !verifyResult.error }
    }

    const result = await context.agent.verifyPresentation({
      presentation: args,
      fetchRemoteContexts: true,
      domain: (await context.agent.identifierManagedGet(idOpts)).kid?.split('#')[0],
    })
    return { verified: result.verified }
  }

  return presentationVerificationCallback
}

export async function createRPBuilder(args: {
  rpOpts: IRPOptions
  definition?: IPresentationDefinition
  context: IRequiredContext
}): Promise<RPBuilder> {
  const { rpOpts, context } = args
  const { identifierOpts } = rpOpts

  const didMethods = identifierOpts.supportedDIDMethods ?? (await getAgentDIDMethods(context))
  const eventEmitter = rpOpts.eventEmitter ?? new EventEmitter()

  const defaultClientMetadata: ClientMetadataOpts = {
    // FIXME: All of the below should be configurable. Some should come from builder, some should be determined by the agent.
    // For now it is either preconfigured or everything passed in as a single object
    idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256, SigningAlgo.ES256K], // added newly
    requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256, SigningAlgo.ES256K], // added newly
    responseTypesSupported: [ResponseType.ID_TOKEN], // added newly
    client_name: 'Sphereon',
    vpFormatsSupported: {
      jwt_vc: { alg: ['EdDSA', 'ES256K'] },
      jwt_vp: { alg: ['ES256K', 'EdDSA'] },
    },
    scopesSupported: [Scope.OPENID_DIDAUTHN],
    subjectTypesSupported: [SubjectType.PAIRWISE],
    subject_syntax_types_supported: didMethods.map((method) => `did:${method}`),
    passBy: PassBy.VALUE,
  }

  const resolver =
    rpOpts.identifierOpts.resolveOpts?.resolver ??
    getAgentResolver(context, {
      resolverResolution: true,
      localResolution: true,
      uniresolverResolution: rpOpts.identifierOpts.resolveOpts?.noUniversalResolverFallback !== true,
    })
  //todo: probably wise to first look and see if we actually need the hasher to begin with
  let hasher: HasherSync | undefined = rpOpts.credentialOpts?.hasher
  if (!rpOpts.credentialOpts?.hasher || typeof rpOpts.credentialOpts?.hasher !== 'function') {
    hasher = defaultHasher
  }

  const builder = RP.builder({ requestVersion: getRequestVersion(rpOpts) })
    .withScope('openid', PropertyTarget.REQUEST_OBJECT)
    .withResponseMode(rpOpts.responseMode ?? ResponseMode.POST)
    .withResponseType(ResponseType.VP_TOKEN, PropertyTarget.REQUEST_OBJECT)
    // todo: move to options fill/correct method
    .withSupportedVersions(rpOpts.supportedVersions ?? [SupportedVersion.OID4VP_v1, SupportedVersion.SIOPv2_OID4VP_D28])

    .withEventEmitter(eventEmitter)
    .withSessionManager(rpOpts.sessionManager ?? new InMemoryRPSessionManager(eventEmitter))
    .withClientMetadata(rpOpts.clientMetadataOpts ?? defaultClientMetadata, PropertyTarget.REQUEST_OBJECT)
    .withVerifyJwtCallback(
      rpOpts.verifyJwtCallback
        ? rpOpts.verifyJwtCallback
        : getVerifyJwtCallback(
            {
              resolver,
              verifyOpts: {
                wellknownDIDVerifyCallback: getWellKnownDIDVerifyCallback(rpOpts.identifierOpts, context),
                checkLinkedDomain: 'if_present',
              },
            },
            context,
          ),
    )
    .withDcqlQueryLookup(getDcqlQueryLookupCallback(context))
    .withRevocationVerification(RevocationVerification.NEVER)
    .withPresentationVerification(getPresentationVerificationCallback(identifierOpts.idOpts, context))

  const oidfOpts = identifierOpts.oidfOpts
  if (oidfOpts && isExternalIdentifierOIDFEntityIdOpts(oidfOpts)) {
    builder.withEntityId(oidfOpts.identifier, PropertyTarget.REQUEST_OBJECT)
  } else {
    const resolution = await context.agent.identifierManagedGet(identifierOpts.idOpts)

    // OID4VP 1.0: Determine client_id based on clientIdScheme
    // The scheme is now embedded as a prefix in the client_id
    let clientId: string | undefined
    let preferredPrefix: ClientIdentifierPrefix | undefined

    if (rpOpts.clientIdScheme === 'x509_san_dns') {
      // X.509 certificate DNS SAN scheme
      if (!rpOpts.x509Opts) {
        throw new Error('x509Opts is required when clientIdScheme is x509_san_dns')
      }
      if (!rpOpts.x509Opts.domain) {
        throw new Error('x509Opts.domain is required when clientIdScheme is x509_san_dns')
      }

      // Use DNS domain from x509Opts as client_id
      clientId = rpOpts.x509Opts.domain
      preferredPrefix = ClientIdentifierPrefix.X509_SAN_DNS

      console.log(`[createRPBuilder] Using x509_san_dns scheme with domain: ${clientId}`)
    } else if (rpOpts.clientIdScheme === 'x509_hash') {
      // X.509 certificate hash scheme (HAIP): client_id = base64url(SHA-256(DER(leaf)))
      if (!rpOpts.x509Opts) {
        throw new Error('x509Opts is required when clientIdScheme is x509_hash')
      }

      // HAIP requires the authorization request to be sent as a signed request object so the
      // verifier can validate the x509_hash client_id against the x5c chain. Only reject an
      // explicitly unsigned request (PassBy.NONE); VALUE / REFERENCE / unset (default VALUE) are fine.
      if (rpOpts.clientMetadataOpts?.passBy === PassBy.NONE) {
        throw new Error(
          'clientIdScheme x509_hash requires a signed request object; clientMetadataOpts.passBy must be PassBy.VALUE or PassBy.REFERENCE (not PassBy.NONE)',
        )
      }

      clientId = computeX509HashClientId(rpOpts.x509Opts.certificate)
      preferredPrefix = ClientIdentifierPrefix.X509_HASH

      console.log(`[createRPBuilder] Using x509_hash scheme with client_id: ${clientId}`)
    } else if (rpOpts.clientIdScheme === 'redirect_uri') {
      // Use response_uri as client_id when redirect_uri scheme is specified
      if (!rpOpts.responseUri) {
        console.log('[createRPBuilder] clientIdScheme=redirect_uri without responseUri - skipping client_id setup')
      } else {
        clientId = rpOpts.responseUri
        preferredPrefix = ClientIdentifierPrefix.REDIRECT_URI
      }
    } else {
      // Default to DID-based client_id (backward compatible)
      clientId =
        rpOpts.clientMetadataOpts?.client_id ??
        resolution.issuer ??
        (isManagedIdentifierDidResult(resolution) ? resolution.did : resolution.jwkThumbprint)
      preferredPrefix = ClientIdentifierPrefix.DECENTRALIZED_IDENTIFIER
    }

    if (clientId) {
      const clientIdPrefixed = prefixClientId(clientId, preferredPrefix)
      builder.withClientId(clientIdPrefixed, PropertyTarget.REQUEST_OBJECT)
    }
  }

  if (hasher) {
    builder.withHasher(hasher)
  }
  //fixme: this has been removed in the new version of did-auth-siop
  /*if (!rpOpts.clientMetadataOpts?.subjectTypesSupported) {
    // Do not update in case it is already provided via client metadata opts
    didMethods.forEach((method) => builder.addDidMethod(method))
  }*/
  //fixme: this has been removed in the new version of did-auth-siop
  // builder.withWellknownDIDVerifyCallback(getWellKnownDIDVerifyCallback(didOpts, context))

  if (rpOpts.responseRedirectUri) {
    builder.withResponseRedirectUri(rpOpts.responseRedirectUri)
  }

  // OID4VP 1.0: Configure request object PassBy based on clientMetadata.passBy
  // - PassBy.VALUE: Request object passed by value (inline in URL)
  // - PassBy.REFERENCE: Request object passed by reference (request_uri)
  // - PassBy.NONE: No request object (plain URL parameters)
  console.log(`[createRPBuilder] Using clientIdScheme: ${rpOpts.clientIdScheme}, passBy: ${rpOpts.clientMetadataOpts?.passBy}`)

  // For PassBy.REFERENCE, we need to set the reference URI template
  if (rpOpts.clientMetadataOpts?.passBy === PassBy.REFERENCE && rpOpts.requestByReferenceURI) {
    console.log(`[createRPBuilder] Setting reference URI template: ${rpOpts.requestByReferenceURI}`)
    builder.withRequestByReference(rpOpts.requestByReferenceURI)
  }

  //const key = resolution.key
  //fixme: this has been removed in the new version of did-auth-siop
  //builder.withSuppliedSignature(SuppliedSigner(key, context, getSigningAlgo(key.type) as unknown as KeyAlgo), did, kid, getSigningAlgo(key.type))

  /*if (isManagedIdentifierDidResult(resolution)) {
    //fixme: only accepts dids in version used. New SIOP lib also accepts other types
    builder.withSuppliedSignature(
      SuppliedSigner(key, context, getSigningAlgo(key.type) as unknown as KeyAlgo),
      resolution.did,
      resolution.kid,
      getSigningAlgo(key.type),
    )
  }*/
  // Configure JWT signing callback
  // Use provided callback if available, otherwise create default signCallback
  const createJwtCallback = rpOpts.createJwtCallback ?? signCallback(rpOpts.identifierOpts.idOpts, context, rpOpts.x509Opts)
  builder.withCreateJwtCallback(createJwtCallback satisfies CreateJwtCallback<any>)
  return builder
}

export function signCallback(
  idOpts: ManagedIdentifierOptsOrResult,
  context: IRequiredContext,
  x509Opts?: IRPOptions['x509Opts'],
): (jwtIssuer: JwtIssuer, jwt: { header: JwtHeader; payload: JwtPayload }, kid?: string) => Promise<string> {
  return async (jwtIssuer: JwtIssuer, jwt: { header: JwtHeader; payload: JwtPayload }, kid?: string) => {
    if (!(isManagedIdentifierDidOpts(idOpts) || isManagedIdentifierX5cOpts(idOpts))) {
      return Promise.reject(Error(`JWT issuer method ${jwtIssuer.method} not yet supported`))
    }

    // Prepare JWT header
    let header = jwt.header

    // If x509Opts provided, add x5c header
    if (x509Opts) {
      // Convert PEM certificates to base64 (remove headers/footers)
      const certBase64 = pemToBase64(x509Opts.certificate)
      const chainBase64 = (x509Opts.certificateChain || []).map(pemToBase64)

      // x5c header: [leaf cert, intermediate cert(s), root cert]
      const x5c = [certBase64, ...chainBase64]

      header = {
        ...header,
        typ: 'oauth-authz-req+jwt',
        alg: x509Opts.alg || 'ES256',
        x5c,
      }

      console.log('[signCallback] Added x5c header with certificate chain')
    }

    const result: JwtCompactResult = await context.agent.jwtCreateJwsCompactSignature({
      // FIXME fix cose-key inference
      // @ts-ignore
      issuer: {
        identifier: idOpts.identifier,
        kmsKeyRef: x509Opts?.keyRef || idOpts.kmsKeyRef,
        noIdentifierInHeader: !!x509Opts, // Don't include kid in header for x509
      },
      // FIXME fix JWK key_ops
      // @ts-ignore
      protectedHeader: header,
      payload: jwt.payload,
    })
    return result.jwt
  }
}

/**
 * Convert PEM format to base64 (strip armor, CR and LF line endings).
 *
 * Both `\r` and `\n` must be removed: a real multi-line PEM with CRLF endings would
 * otherwise leave embedded `\r` inside the base64 body (`.trim()` only removes leading/
 * trailing whitespace). The resulting string is used verbatim as an x5c JWT header value,
 * which must be clean base64.
 *
 * @internal exported only for unit testing.
 */
export function pemToBase64(pem: string): string {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/[\r\n]/g, '')
    .trim()
}

/**
 * Compute the Client Identifier value for the `x509_hash` Client Identifier
 * Prefix (HAIP / OID4VP 1.0): the base64url encoding of the SHA-256 hash of the
 * DER-encoded leaf certificate.
 *
 * @param leafCertificatePem leaf certificate in PEM format
 * @returns base64url(SHA-256(DER(leaf)))
 */
export function computeX509HashClientId(leafCertificatePem: string): string {
  const der = Buffer.from(pemToBase64(leafCertificatePem), 'base64')
  return createHash('sha256').update(der).digest('base64url')
}

function getVerifyJwtCallback(
  _opts: {
    resolver?: Resolvable
    verifyOpts?: JWTVerifyOptions & {
      checkLinkedDomain: 'never' | 'if_present' | 'always'
      wellknownDIDVerifyCallback?: VerifyCallback
    }
  },
  context: IRequiredContext,
): VerifyJwtCallback {
  return async (_jwtVerifier, jwt) => {
    const result = await context.agent.jwtVerifyJwsSignature({ jws: jwt.raw })
    console.log(result.message)
    return !result.error
  }
}

export async function createRP({ rpOptions, context }: { rpOptions: IRPOptions; context: IRequiredContext }): Promise<RP> {
  return (await createRPBuilder({ rpOpts: rpOptions, context })).build()
}

export function getSigningAlgo(type: TKeyType): SigningAlgo {
  switch (type) {
    case 'Ed25519':
      return SigningAlgo.EDDSA
    case 'Secp256k1':
      return SigningAlgo.ES256K
    case 'Secp256r1':
      return SigningAlgo.ES256
    // @ts-ignore
    case 'RSA':
      return SigningAlgo.RS256
    default:
      throw Error('Key type not yet supported')
  }
}

/**
 * Add appropriate client_id prefix for OID4VP 1.0
 * @param clientId - The client identifier (DID, URL, etc.)
 * @param preferredPrefix - Optional preferred prefix to use
 * @returns Client ID with appropriate prefix
 */
export function prefixClientId(clientId: string, preferredPrefix?: ClientIdentifierPrefix): string {
  // Check if clientId already has a known prefix
  const knownPrefixes = Object.values(ClientIdentifierPrefix)
  for (const prefix of knownPrefixes) {
    if (clientId.startsWith(`${prefix}:`)) {
      // Already has a prefix, return as is
      return clientId
    }
  }

  // Apply preferred prefix if specified
  if (preferredPrefix) {
    return `${preferredPrefix}:${clientId}`
  }

  // Auto-detect and apply appropriate prefix based on format
  if (clientId.startsWith('did:')) {
    return `${ClientIdentifierPrefix.DECENTRALIZED_IDENTIFIER}:${clientId}`
  }

  if (clientId.startsWith('http://') || clientId.startsWith('https://')) {
    return `${ClientIdentifierPrefix.REDIRECT_URI}:${clientId}`
  }

  // Return as is if no prefix can be determined
  return clientId
}
