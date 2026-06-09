import {
  AuthorizationRequestPayload,
  AuthorizationRequestState,
  AuthorizationResponsePayload,
  AuthorizationResponseStateWithVerifiedData,
  CallbackOpts,
  ClaimPayloadCommonOpts,
  ClientMetadataOpts,
  CreateJwtCallback,
  IRPSessionManager,
  PresentationVerificationCallback,
  RequestObjectPayload,
  ResponseMode,
  ResponseURIType,
  SupportedVersion,
  VerifiedAuthorizationResponse,
  VerifyJwtCallback,
} from '@vess-id/did-auth-siop'
import { CheckLinkedDomain } from '@vess-id/did-auth-siop-adapter'
import { DIDDocument } from '@sphereon/did-uni-client'
import { JwtIssuer } from '@vess-id/oid4vc-common'
import { IPresentationDefinition } from '@sphereon/pex'
import { IDIDOptions } from '@sphereon/ssi-sdk-ext.did-utils'
import { ExternalIdentifierOIDFEntityIdOpts, IIdentifierResolution, ManagedIdentifierOptsOrResult } from '@sphereon/ssi-sdk-ext.identifier-resolution'
import { IJwtService } from '@sphereon/ssi-sdk-ext.jwt-service'
import { ICredentialValidation, SchemaValidation } from '@sphereon/ssi-sdk.credential-validation'
import { ImDLMdoc } from '@vess-id/ssi-sdk.mdl-mdoc'
import { ImportDcqlQueryItem, IPDManager, VersionControlMode } from '@vess-id/ssi-sdk.pd-manager'
import { IPresentationExchange } from '@sphereon/ssi-sdk.presentation-exchange'
import { ISDJwtPlugin } from '@vess-id/ssi-sdk.sd-jwt'
import { AuthorizationRequestStateStatus } from '@vess-id/ssi-sdk.siopv2-oid4vp-common'
import { HasherSync } from '@sphereon/ssi-types'
import { VerifyCallback } from '@sphereon/wellknown-dids-client'
import { IAgentContext, ICredentialVerifier, IDIDManager, IKeyManager, IPluginMethodMap, IResolver } from '@veramo/core'
import { DcqlQuery } from 'dcql'
import { Resolvable } from 'did-resolver'
import { EventEmitter } from 'events'

export interface ISIOPv2RP extends IPluginMethodMap {
  siopCreateAuthRequestURI(createArgs: ICreateAuthRequestArgs, context: IRequiredContext): Promise<string>
  siopCreateAuthRequestPayloads(createArgs: ICreateAuthRequestArgs, context: IRequiredContext): Promise<IAuthorizationRequestPayloads>
  siopGetAuthRequestState(args: IGetAuthRequestStateArgs, context: IRequiredContext): Promise<AuthorizationRequestState | undefined>
  siopGetAuthResponseState(
    args: IGetAuthResponseStateArgs,
    context: IRequiredContext,
  ): Promise<AuthorizationResponseStateWithVerifiedData | undefined>
  siopUpdateAuthRequestState(args: IUpdateRequestStateArgs, context: IRequiredContext): Promise<AuthorizationRequestState>
  siopDeleteAuthState(args: IDeleteAuthStateArgs, context: IRequiredContext): Promise<boolean>
  siopVerifyAuthResponse(args: IVerifyAuthResponseStateArgs, context: IRequiredContext): Promise<VerifiedAuthorizationResponse>
  siopImportDefinitions(args: ImportDefinitionsArgs, context: IRequiredContext): Promise<void>
  siopGetRedirectURI(args: IGetRedirectUriArgs, context: IRequiredContext): Promise<string | undefined>
}

export interface ISiopv2RPOpts {
  defaultOpts?: IRPDefaultOpts
  instanceOpts?: IPEXInstanceOptions[]
}

export interface IRPDefaultOpts extends IRPOptions {}

export interface ICreateAuthRequestArgs {
  queryId: string
  correlationId: string
  useQueryIdInstance?: boolean
  responseURIType: ResponseURIType
  responseURI: string
  responseRedirectURI?: string
  jwtIssuer?: JwtIssuer
  requestByReferenceURI?: string
  nonce?: string
  state?: string
  claims?: ClaimPayloadCommonOpts
  callback?: CallbackOpts
}

export interface IGetAuthRequestStateArgs {
  correlationId: string
  queryId?: string
  errorOnNotFound?: boolean
}

export interface IGetAuthResponseStateArgs {
  correlationId: string
  queryId?: string
  errorOnNotFound?: boolean
  progressRequestStateTo?: AuthorizationRequestStateStatus
}

export interface IUpdateRequestStateArgs {
  queryId?: string
  correlationId: string
  state: AuthorizationRequestStateStatus
  error?: string
}

export interface IDeleteAuthStateArgs {
  correlationId: string
  queryId?: string
}

export interface IVerifyAuthResponseStateArgs {
  authorizationResponse: string | AuthorizationResponsePayload
  queryId?: string
  correlationId: string
  audience?: string
  dcqlQuery?: DcqlQuery
}
export interface ImportDefinitionsArgs {
  importItems: Array<ImportDcqlQueryItem>
  tenantId?: string
  version?: string
  versionControlMode?: VersionControlMode
}

export interface IGetRedirectUriArgs {
  correlationId: string
  queryId?: string
  state?: string
}

export interface IAuthorizationRequestPayloads {
  authorizationRequest: AuthorizationRequestPayload
  requestObject?: string
  requestObjectDecoded?: RequestObjectPayload
}

export interface IPEXDefinitionPersistArgs extends IPEXInstanceOptions {
  definition: IPresentationDefinition
  ttl?: number
}

export interface ISiopRPInstanceArgs {
  createWhenNotPresent: boolean
  queryId?: string
  responseRedirectURI?: string
}

export interface IPEXInstanceOptions extends IPresentationOptions {
  rpOpts?: IRPOptions
}

export interface IRPOptions {
  responseMode?: ResponseMode
  supportedVersions?: SupportedVersion[] // The supported version by the RP. The first version will be the default version
  sessionManager?: IRPSessionManager
  clientMetadataOpts?: ClientMetadataOpts
  expiresIn?: number
  eventEmitter?: EventEmitter
  credentialOpts?: CredentialOpts
  verificationPolicies?: VerificationPolicies
  requestByReferenceURI?: string // Template URI for request_uri when using PassBy.REFERENCE
  identifierOpts: ISIOPIdentifierOptions
  verifyJwtCallback?: VerifyJwtCallback
  createJwtCallback?: CreateJwtCallback // JWT signing callback for request objects
  responseRedirectUri?: string
  /**
   * Client ID prefix to use for OID4VP 1.0
   * Note: In OID4VP 1.0, client_id_scheme is replaced by prefix in client_id
   *
   * @default 'redirect_uri' - Use redirect_uri as client_id (OID4VP 1.0 recommended)
   * - 'redirect_uri': Simple URL-based prefix (no signing required)
   *   client_id = "redirect_uri:https://verifier.vess.id/callback"
   *
   * - 'did': DID-based prefix (backward compatible, signing required)
   *   client_id = "decentralized_identifier:did:web:verifier.vess.id"
   *
   * - 'x509_san_dns': X.509 certificate DNS SAN prefix (signing required, enterprise)
   *   client_id = "x509_san_dns:verifier.vess.id"
   */
  clientIdScheme?: 'redirect_uri' | 'did' | 'x509_san_dns'
  /**
   * Response URI to use when clientIdScheme is 'redirect_uri'
   * This will be used as the client_id with redirect_uri prefix
   * If not provided, the responseURI from ICreateAuthRequestArgs will be used
   */
  responseUri?: string
  /**
   * X.509 certificate options for x509_san_dns scheme
   * Required when clientIdScheme is 'x509_san_dns'
   */
  x509Opts?: {
    /**
     * DNS domain for client_id (e.g., "verifier.vess.id")
     * Must match certificate SAN DNS entry
     */
    domain: string

    /**
     * X.509 certificate in PEM format
     */
    certificate: string

    /**
     * Private key reference (kid/keyRef) for signing
     * Note: Private key is managed by Veramo KMS
     */
    keyRef: string

    /**
     * Certificate chain (intermediate + root CA) in PEM format
     * Used for x5c JWT header
     */
    certificateChain?: string[]

    /**
     * Signing algorithm (default: ES256 for ECDSA P-256)
     */
    alg?: 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512'
  }
}

export interface IPresentationOptions {
  queryId: string
  presentationVerifyCallback?: PresentationVerificationCallback
}

export type VerificationPolicies = {
  schemaValidation: SchemaValidation
}

export interface PerDidResolver {
  didMethod: string
  resolver: Resolvable
}

export interface IAuthRequestDetails {
  rpDIDDocument?: DIDDocument
  id: string
  alsoKnownAs?: string[]
}

export interface ISIOPIdentifierOptions extends Omit<IDIDOptions, 'idOpts'> {
  // we replace the legacy idOpts with the Managed Identifier opts from the identifier resolution module
  idOpts: ManagedIdentifierOptsOrResult
  oidfOpts?: ExternalIdentifierOIDFEntityIdOpts
  checkLinkedDomains?: CheckLinkedDomain
  wellknownDIDVerifyCallback?: VerifyCallback
}

// todo make the necessary changes for mdl-mdoc types
export type CredentialOpts = {
  hasher?: HasherSync
}

export type IRequiredContext = IAgentContext<
  IResolver &
    IDIDManager &
    IKeyManager &
    IIdentifierResolution &
    ICredentialValidation &
    ICredentialVerifier &
    IPresentationExchange &
    IPDManager &
    ISDJwtPlugin &
    IJwtService &
    ImDLMdoc
>
