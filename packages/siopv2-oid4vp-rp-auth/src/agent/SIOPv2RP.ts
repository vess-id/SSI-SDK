import {
  AuthorizationRequestState,
  AuthorizationResponsePayload,
  AuthorizationResponseState,
  AuthorizationResponseStateStatus,
  AuthorizationResponseStateWithVerifiedData,
  decodeUriAsJson,
  EncodedDcqlPresentationVpToken,
  VerifiedAuthorizationResponse,
} from '@vess-id/did-auth-siop'
import { getAgentResolver } from '@sphereon/ssi-sdk-ext.did-utils'
import { shaHasher as defaultHasher } from '@sphereon/ssi-sdk.core'
import { validate as isValidUUID } from 'uuid'
import type { ImportDcqlQueryItem } from '@sphereon/ssi-sdk.pd-manager'
import {
  AdditionalClaims,
  CredentialMapper,
  HasherSync,
  ICredentialSubject,
  IPresentation,
  IVerifiableCredential,
  IVerifiablePresentation,
  JwtDecodedVerifiablePresentation,
  MdocDeviceResponse,
  MdocOid4vpMdocVpToken,
  OriginalVerifiablePresentation,
  SdJwtDecodedVerifiableCredential,
} from '@sphereon/ssi-types'
import { IAgentPlugin } from '@veramo/core'
import { DcqlQuery } from 'dcql'
import {
  IAuthorizationRequestPayloads,
  ICreateAuthRequestArgs,
  IGetAuthRequestStateArgs,
  IGetAuthResponseStateArgs,
  IGetRedirectUriArgs,
  ImportDefinitionsArgs,
  IPEXInstanceOptions,
  IRequiredContext,
  IRPDefaultOpts,
  IRPOptions,
  ISiopRPInstanceArgs,
  ISiopv2RPOpts,
  IUpdateRequestStateArgs,
  IVerifyAuthResponseStateArgs,
  schema,
} from '../index'
import { RPInstance } from '../RPInstance'
import { ISIOPv2RP } from '../types/ISIOPv2RP'

export class SIOPv2RP implements IAgentPlugin {
  private readonly opts: ISiopv2RPOpts
  private static readonly _DEFAULT_OPTS_KEY = '_default'
  private readonly instances: Map<string, RPInstance> = new Map()
  readonly schema = schema.IDidAuthSiopOpAuthenticator

  readonly methods: ISIOPv2RP = {
    siopCreateAuthRequestURI: this.createAuthorizationRequestURI.bind(this),
    siopCreateAuthRequestPayloads: this.createAuthorizationRequestPayloads.bind(this),
    siopGetAuthRequestState: this.siopGetRequestState.bind(this),
    siopGetAuthResponseState: this.siopGetResponseState.bind(this),
    siopUpdateAuthRequestState: this.siopUpdateRequestState.bind(this),
    siopDeleteAuthState: this.siopDeleteState.bind(this),
    siopVerifyAuthResponse: this.siopVerifyAuthResponse.bind(this),
    siopImportDefinitions: this.siopImportDefinitions.bind(this),
    siopGetRedirectURI: this.siopGetRedirectURI.bind(this),
  }

  constructor(opts: ISiopv2RPOpts) {
    this.opts = opts
  }

  public setDefaultOpts(rpDefaultOpts: IRPDefaultOpts, context: IRequiredContext) {
    // We allow setting default options later, because in some cases you might want to query the agent for defaults. This cannot happen when the agent is being build (this is when the constructor is being called)
    this.opts.defaultOpts = rpDefaultOpts
    // We however do require the agent to be responsible for resolution, otherwise people might encounter strange errors, that are very hard to track down
    if (
      !this.opts.defaultOpts.identifierOpts.resolveOpts?.resolver ||
      typeof this.opts.defaultOpts.identifierOpts.resolveOpts.resolver.resolve !== 'function'
    ) {
      this.opts.defaultOpts.identifierOpts.resolveOpts = {
        ...this.opts.defaultOpts.identifierOpts.resolveOpts,
        resolver: getAgentResolver(context, { uniresolverResolution: true, resolverResolution: true, localResolution: true }),
      }
    }
  }

  private async createAuthorizationRequestURI(createArgs: ICreateAuthRequestArgs, context: IRequiredContext): Promise<string> {
    return await this.getRPInstance(
      {
        createWhenNotPresent: true,
        responseRedirectURI: createArgs.responseRedirectURI,
        ...(createArgs.useQueryIdInstance === true && { queryId: createArgs.queryId }),
      },
      context,
    )
      .then((rp) => rp.createAuthorizationRequestURI(createArgs, context))
      .then((URI) => URI.encodedUri)
  }

  private async createAuthorizationRequestPayloads(
    createArgs: ICreateAuthRequestArgs,
    context: IRequiredContext,
  ): Promise<IAuthorizationRequestPayloads> {
    return await this.getRPInstance({ createWhenNotPresent: true, queryId: createArgs.queryId }, context)
      .then((rp) => rp.createAuthorizationRequest(createArgs, context))
      .then(async (request) => {
        const authRequest: IAuthorizationRequestPayloads = {
          authorizationRequest: request.payload,
          requestObject: await request.requestObjectJwt(),
          requestObjectDecoded: request.requestObject?.getPayload(),
        }
        return authRequest
      })
  }

  private async siopGetRequestState(args: IGetAuthRequestStateArgs, context: IRequiredContext): Promise<AuthorizationRequestState | undefined> {
    return await this.getRPInstance({ createWhenNotPresent: false, queryId: args.queryId }, context).then((rp) =>
      rp.get(context).then((rp) => rp.sessionManager.getRequestStateByCorrelationId(args.correlationId, args.errorOnNotFound)),
    )
  }

  private async siopGetResponseState(
    args: IGetAuthResponseStateArgs,
    context: IRequiredContext,
  ): Promise<AuthorizationResponseStateWithVerifiedData | undefined> {
    const rpInstance: RPInstance = await this.getRPInstance({ createWhenNotPresent: false, queryId: args.queryId }, context)
    const authorizationResponseState: AuthorizationResponseState | undefined = await rpInstance
      .get(context)
      .then((rp) => rp.sessionManager.getResponseStateByCorrelationId(args.correlationId, args.errorOnNotFound))
    if (authorizationResponseState === undefined) {
      return undefined
    }

    const responseState = authorizationResponseState as AuthorizationResponseStateWithVerifiedData
    if (responseState.status === AuthorizationResponseStateStatus.VERIFIED) {
      let hasher: HasherSync | undefined
      if (
        CredentialMapper.isSdJwtEncoded(responseState.response.payload.vp_token as OriginalVerifiablePresentation) &&
        (!rpInstance.rpOptions.credentialOpts?.hasher || typeof rpInstance.rpOptions.credentialOpts?.hasher !== 'function')
      ) {
        hasher = defaultHasher
      }

      // FIXME SSISDK-64 currently assuming that all vp tokens are or type EncodedDcqlPresentationVpToken as we only work with DCQL now. But the types still indicate it can be another type of vp token
      // OID4VP 1.0: Handle vp_token that might already be parsed as object or stringified
      const rawVpToken = responseState.response.payload.vp_token
      const vpToken = rawVpToken && (typeof rawVpToken === 'string' ? JSON.parse(rawVpToken as EncodedDcqlPresentationVpToken) : rawVpToken)
      const claims = []
      for (const [credentialQueryId, presentationValue] of Object.entries(vpToken)) {
        // Support multiple VPs per credential query (DCQL multiple: true)
        const presentations: OriginalVerifiablePresentation[] = Array.isArray(presentationValue)
          ? presentationValue.length === 0
            ? (() => {
                throw Error(`DCQL query '${credentialQueryId}' has empty array of presentations`)
              })()
            : (presentationValue as OriginalVerifiablePresentation[])
          : [presentationValue as OriginalVerifiablePresentation]

        for (const singleVP of presentations) {
          // Check if this is an mdoc DeviceResponse (CBOR encoded)
          const isMdocDeviceResponse = this.isMdocFormat(singleVP)

          let presentationDecoded: any
          if (isMdocDeviceResponse) {
            // mdoc DeviceResponse processing
            // Convert to Uint8Array if needed
            let deviceResponseBytes: Uint8Array
            if (singleVP instanceof Uint8Array) {
              deviceResponseBytes = singleVP
            } else if (typeof Buffer !== 'undefined' && Buffer.isBuffer(singleVP)) {
              deviceResponseBytes = new Uint8Array(singleVP)
            } else if (typeof singleVP === 'string') {
              deviceResponseBytes = new Uint8Array(Buffer.from(singleVP, 'base64url'))
            } else {
              throw new Error('Invalid mdoc DeviceResponse format')
            }
            presentationDecoded = await this.decodeMdocDeviceResponse(deviceResponseBytes, rpInstance, context)
          } else {
            // W3C VC / SD-JWT processing
            presentationDecoded = CredentialMapper.decodeVerifiablePresentation(
              singleVP as OriginalVerifiablePresentation,
              hasher,
            )
          }
          console.log(`presentationDecoded: ${JSON.stringify(presentationDecoded)}`)

          const allClaims: AdditionalClaims = {}
          const presentationOrClaims = this.presentationOrClaimsFrom(presentationDecoded)

          // Handle mdoc DeviceResponse claims
          if (presentationOrClaims && typeof presentationOrClaims === 'object' && !('verifiableCredential' in presentationOrClaims) && !('vct' in presentationOrClaims)) {
            // This is mdoc claims (AdditionalClaims)
            claims.push({
              id: credentialQueryId,
              type: (presentationDecoded as any).docType || 'mdoc',
              claims: presentationOrClaims,
            })
          } else if ('verifiableCredential' in presentationOrClaims) {
            for (const credential of presentationOrClaims.verifiableCredential) {
              const vc = credential as IVerifiableCredential
              const schemaValidationResult = await context.agent.cvVerifySchema({
                credential,
                hasher,
                validationPolicy: rpInstance.rpOptions.verificationPolicies?.schemaValidation,
              })
              if (!schemaValidationResult.result) {
                responseState.status = AuthorizationResponseStateStatus.ERROR
                responseState.error = new Error(schemaValidationResult.error)
                return responseState
              }

              const credentialSubject = vc.credentialSubject as ICredentialSubject & AdditionalClaims
              if (!('id' in allClaims)) {
                allClaims['id'] = credentialSubject.id
              }

              Object.entries(credentialSubject).forEach(([key, value]) => {
                if (!(key in allClaims)) {
                  allClaims[key] = value
                }
              })

              claims.push({
                id: credentialQueryId,
                type: vc.type[0],
                claims: allClaims,
              })
            }
          } else {
            claims.push({
              id: credentialQueryId,
              type: (presentationDecoded as SdJwtDecodedVerifiableCredential).decodedPayload.vct,
              claims: presentationOrClaims,
            })
          }
        }
      }

      responseState.verifiedData = {
        ...(responseState.response.payload.vp_token && {
          authorization_response: {
            vp_token:
              typeof responseState.response.payload.vp_token === 'string'
                ? JSON.parse(responseState.response.payload.vp_token)
                : responseState.response.payload.vp_token,
          },
        }),
        ...(claims.length > 0 && { credential_claims: claims }),
      }
    }

    return responseState
  }

  private presentationOrClaimsFrom = (
    presentationDecoded:
      | JwtDecodedVerifiablePresentation
      | IVerifiablePresentation
      | SdJwtDecodedVerifiableCredential
      | MdocOid4vpMdocVpToken
      | MdocDeviceResponse
      | { type: 'MdocDeviceResponse'; claims: AdditionalClaims; docType?: string }
      | any, // Add any to allow our custom mdoc type
  ): AdditionalClaims | IPresentation => {
    // mdoc DeviceResponse handling
    if (presentationDecoded && typeof presentationDecoded === 'object' && 'type' in presentationDecoded && (presentationDecoded as any).type === 'MdocDeviceResponse') {
      return (presentationDecoded as any).claims as AdditionalClaims
    }

    // SD-JWT handling
    if (CredentialMapper.isSdJwtDecodedCredential(presentationDecoded)) {
      return presentationDecoded.decodedPayload
    }

    // W3C VC handling
    return CredentialMapper.toUniformPresentation(presentationDecoded as OriginalVerifiablePresentation)
  }

  private async siopUpdateRequestState(args: IUpdateRequestStateArgs, context: IRequiredContext): Promise<AuthorizationRequestState> {
    // OID4VP 1.0: Support both 'authorization_request_created' and 'authorization_request_retrieved' states
    if (args.state !== 'authorization_request_created' && args.state !== 'authorization_request_retrieved') {
      throw Error(`Only 'authorization_request_created' and 'authorization_request_retrieved' status values are supported for this method`)
    }
    return await this.getRPInstance({ createWhenNotPresent: false, queryId: args.queryId }, context)
      // todo: In the SIOP library we need to update the signal method to be more like this method
      .then((rp) =>
        rp.get(context).then(async (rp) => {
          // Signal that the auth request has been retrieved (transitions state from created to retrieved)
          await rp.signalAuthRequestRetrieved({
            correlationId: args.correlationId,
            error: args.error ? new Error(args.error) : undefined,
          })
          return (await rp.sessionManager.getRequestStateByCorrelationId(args.correlationId, true)) as AuthorizationRequestState
        }),
      )
  }

  private async siopDeleteState(args: IGetAuthResponseStateArgs, context: IRequiredContext): Promise<boolean> {
    return await this.getRPInstance({ createWhenNotPresent: false, queryId: args.queryId }, context)
      .then((rp) => rp.get(context).then((rp) => rp.sessionManager.deleteStateForCorrelationId(args.correlationId)))
      .then(() => true)
  }

  private async siopVerifyAuthResponse(args: IVerifyAuthResponseStateArgs, context: IRequiredContext): Promise<VerifiedAuthorizationResponse> {
    if (!args.authorizationResponse) {
      throw Error('No SIOPv2 Authorization Response received')
    }
    const authResponse =
      typeof args.authorizationResponse === 'string'
        ? (decodeUriAsJson(args.authorizationResponse) as AuthorizationResponsePayload)
        : args.authorizationResponse
    return await this.getRPInstance({ createWhenNotPresent: false, queryId: args.queryId }, context).then((rp) =>
      rp.get(context).then((rp) =>
        rp.verifyAuthorizationResponse(authResponse, {
          correlationId: args.correlationId,
          ...(args.dcqlQuery && { dcqlQuery: args.dcqlQuery }),
          audience: args.audience,
        }),
      ),
    )
  }

  private async siopImportDefinitions(args: ImportDefinitionsArgs, context: IRequiredContext): Promise<void> {
    const { importItems, tenantId, version, versionControlMode } = args
    await Promise.all(
      importItems.map(async (importItem: ImportDcqlQueryItem) => {
        DcqlQuery.validate(importItem.query)
        console.log(`persisting DCQL definition ${importItem.queryId} with versionControlMode ${versionControlMode}`)

        return context.agent.pdmPersistDefinition({
          definitionItem: {
            queryId: importItem.queryId!,
            tenantId: tenantId,
            version: version,
            query: importItem.query,
          },
          opts: { versionControlMode: versionControlMode },
        })
      }),
    )
  }

  private async siopGetRedirectURI(args: IGetRedirectUriArgs, context: IRequiredContext): Promise<string | undefined> {
    const instanceId = args.queryId ?? SIOPv2RP._DEFAULT_OPTS_KEY
    if (this.instances.has(instanceId)) {
      const rpInstance = this.instances.get(instanceId)
      if (rpInstance !== undefined) {
        const rp = await rpInstance.get(context)
        return await rp.getResponseRedirectUri({
          correlation_id: args.correlationId,
          correlationId: args.correlationId,
          ...(args.state && { state: args.state }),
        })
      }
    }
    return undefined
  }

  async getRPInstance({ createWhenNotPresent, queryId, responseRedirectURI }: ISiopRPInstanceArgs, context: IRequiredContext): Promise<RPInstance> {
    let rpInstanceId: string = SIOPv2RP._DEFAULT_OPTS_KEY
    let rpInstance: RPInstance | undefined
    if (queryId) {
      if (this.instances.has(queryId)) {
        rpInstanceId = queryId
        rpInstance = this.instances.get(rpInstanceId)!
      } else if (isValidUUID(queryId)) {
        try {
          // Check whether queryId is actually the PD item id
          const pd = await context.agent.pdmGetDefinition({ itemId: queryId })
          if (this.instances.has(pd.queryId)) {
            rpInstanceId = pd.queryId
            rpInstance = this.instances.get(rpInstanceId)!
          }
        } catch (ignore) {}
      }
      if (createWhenNotPresent) {
        rpInstanceId = queryId
      } else {
        rpInstance = this.instances.get(rpInstanceId)
      }
    } else {
      rpInstance = this.instances.get(rpInstanceId)
    }

    if (!rpInstance) {
      if (!createWhenNotPresent) {
        return Promise.reject(`No RP instance found for key ${rpInstanceId}`)
      }
      const instanceOpts = this.getInstanceOpts(queryId)
      const rpOpts = await this.getRPOptions(context, { queryId, responseRedirectURI: responseRedirectURI })
      if (!rpOpts.identifierOpts.resolveOpts?.resolver || typeof rpOpts.identifierOpts.resolveOpts.resolver.resolve !== 'function') {
        if (!rpOpts.identifierOpts?.resolveOpts) {
          rpOpts.identifierOpts = { ...rpOpts.identifierOpts }
          rpOpts.identifierOpts.resolveOpts = { ...rpOpts.identifierOpts.resolveOpts }
        }
        console.log('Using agent DID resolver for RP instance with definition id ' + queryId)
        rpOpts.identifierOpts.resolveOpts.resolver = getAgentResolver(context, {
          uniresolverResolution: true,
          localResolution: true,
          resolverResolution: true,
        })
      }
      rpInstance = new RPInstance({ rpOpts, pexOpts: instanceOpts })
      this.instances.set(rpInstanceId, rpInstance)
    }
    if (responseRedirectURI) {
      rpInstance.rpOptions.responseRedirectUri = responseRedirectURI
    }
    return rpInstance
  }

  async getRPOptions(context: IRequiredContext, opts: { queryId?: string; responseRedirectURI?: string }): Promise<IRPOptions> {
    const { queryId, responseRedirectURI: responseRedirectURI } = opts
    const options = this.getInstanceOpts(queryId)?.rpOpts ?? this.opts.defaultOpts
    if (!options) {
      throw Error(`Could not get specific nor default options for definition ${queryId}`)
    }
    if (this.opts.defaultOpts) {
      if (!options.identifierOpts) {
        options.identifierOpts = this.opts.defaultOpts?.identifierOpts
      } else {
        if (!options.identifierOpts.idOpts) {
          options.identifierOpts.idOpts = this.opts.defaultOpts.identifierOpts.idOpts
        }
        if (!options.identifierOpts.supportedDIDMethods) {
          options.identifierOpts.supportedDIDMethods = this.opts.defaultOpts.identifierOpts.supportedDIDMethods
        }
        if (!options.supportedVersions) {
          options.supportedVersions = this.opts.defaultOpts.supportedVersions
        }
      }
      if (!options.identifierOpts.resolveOpts || typeof options.identifierOpts.resolveOpts.resolver?.resolve !== 'function') {
        options.identifierOpts.resolveOpts = {
          ...this.opts.defaultOpts.identifierOpts.resolveOpts,
          resolver:
            this.opts.defaultOpts.identifierOpts?.resolveOpts?.resolver ??
            getAgentResolver(context, { localResolution: true, resolverResolution: true, uniresolverResolution: true }),
        }
      }
    }
    if (responseRedirectURI !== undefined && responseRedirectURI !== options.responseRedirectUri) {
      options.responseRedirectUri = responseRedirectURI
    }
    return options
  }

  getInstanceOpts(queryId?: string): IPEXInstanceOptions | undefined {
    if (!this.opts.instanceOpts) return undefined

    const instanceOpt = queryId ? this.opts.instanceOpts.find((i) => i.queryId === queryId) : undefined

    return instanceOpt ?? this.getDefaultOptions(queryId)
  }

  private getDefaultOptions(queryId: string | undefined) {
    if (!this.opts.instanceOpts) return undefined

    const defaultOptions = this.opts.instanceOpts.find((i) => i.queryId === 'default')
    if (defaultOptions) {
      const clonedOptions = { ...defaultOptions }
      if (queryId !== undefined) {
        clonedOptions.queryId = queryId
      }
      return clonedOptions
    }

    return undefined
  }

  /**
   * Check if the presentation value is an mdoc DeviceResponse (CBOR encoded)
   * mdoc DeviceResponses are Uint8Array or Buffer
   */
  private isMdocFormat(vp: any): boolean {
    console.log('[isMdocFormat] Checking format for vp:', typeof vp, vp instanceof Uint8Array ? '(Uint8Array)' : typeof vp === 'string' ? `(string, first 60 chars: ${vp.substring(0, 60)})` : '')
    if (!vp) return false

    // Check if it's Uint8Array or Buffer
    if (vp instanceof Uint8Array) {
      console.log('[isMdocFormat] Is Uint8Array, returning true')
      return true
    }
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(vp)) {
      console.log('[isMdocFormat] Is Buffer, returning true')
      return true
    }

    // Check if it's base64url encoded string that looks like CBOR
    if (typeof vp === 'string') {
      try {
        // Try to decode base64url
        const decoded = Buffer.from(vp, 'base64url')
        // CBOR data typically starts with specific bytes
        // DeviceResponse is a CBOR map, which starts with 0xa1-0xbf (map of 1-31 items) or 0xb8-0xbb (map with 1-4 byte length)
        const firstByte = decoded[0]
        const ismdoc = (firstByte >= 0xa0 && firstByte <= 0xbf) || (firstByte >= 0xb8 && firstByte <= 0xbb)
        console.log('[isMdocFormat] Is string, firstByte: 0x' + firstByte.toString(16) + ', isMdoc:', ismdoc)
        return ismdoc
      } catch (e) {
        console.log('[isMdocFormat] Error decoding base64url:', e.message)
        return false
      }
    }

    console.log('[isMdocFormat] Unknown format, returning false')
    return false
  }

  /**
   * Decode and verify mdoc DeviceResponse
   * This method uses @vess-id/mdl or @auth0/mdl to verify the DeviceResponse
   */
  private async decodeMdocDeviceResponse(
    deviceResponseBytes: Uint8Array,
    rpInstance: RPInstance,
    context: IRequiredContext,
    authorizationRequestPayload?: any,
  ): Promise<{ type: 'MdocDeviceResponse'; claims: AdditionalClaims; docType?: string }> {
    console.log('[decodeMdocDeviceResponse] START - Processing mdoc DeviceResponse', { bytesLength: deviceResponseBytes.length })
    try {
      // Try to import @vess-id/mdl (or fallback to @auth0/mdl)
      let Verifier: any
      let mdlModule: any

      try {
        // Dynamic import with type assertion to avoid build-time errors
        mdlModule = await import('@vess-id/mdl' as any)
        Verifier = mdlModule.Verifier
      } catch (e) {
        // Fallback to @auth0/mdl if @vess-id/mdl is not available
        try {
          mdlModule = await import('@auth0/mdl' as any)
          Verifier = mdlModule.Verifier
        } catch (e2) {
          throw new Error('Neither @vess-id/mdl nor @auth0/mdl is available. Please install one of them to support mdoc verification.')
        }
      }

      // Get trusted CA certificates from RP options
      // TODO: This should be configurable via rpInstance.rpOptions
      const trustedCerts: string[] = []

      // For now, we'll do basic parsing without full verification
      // In production, you should provide trusted CA certificates
      const verifier = new Verifier(trustedCerts)

      // Get diagnostic information (works even without trusted certs)
      const diagnosticInfo = await verifier.getDiagnosticInformation(deviceResponseBytes, {})
      console.log('[decodeMdocDeviceResponse] diagnosticInfo structure:', JSON.stringify(diagnosticInfo, null, 2))

      // Extract claims from the diagnostic information
      const claims: AdditionalClaims = {}
      let docType: string | undefined

      // Get docType from general info
      if (diagnosticInfo?.general?.type) {
        // diagnosticInfo doesn't have docType in general, need to get it from documents
        // For now, we'll leave it undefined and it will be set from the document if available
      }

      // Extract attributes from diagnosticInfo
      // The @vess-id/mdl library returns attributes in a flat array structure
      if (diagnosticInfo?.attributes && Array.isArray(diagnosticInfo.attributes)) {
        console.log('[decodeMdocDeviceResponse] Extracting claims from attributes array, count:', diagnosticInfo.attributes.length)
        for (const attr of diagnosticInfo.attributes) {
          if (attr && typeof attr === 'object' && 'id' in attr && 'value' in attr) {
            const namespace = (attr as any).ns || 'org.iso.18013.5.1'
            const elementId = (attr as any).id
            const elementValue = (attr as any).value

            // Use namespace.elementId as the claim key
            claims[`${namespace}.${elementId}`] = elementValue
            // Also add with just elementId for easier access
            if (!(elementId in claims)) {
              claims[elementId] = elementValue
            }
          }
        }
      }

      // Also extract deviceAttributes if present
      if (diagnosticInfo?.deviceAttributes && Array.isArray(diagnosticInfo.deviceAttributes)) {
        console.log('[decodeMdocDeviceResponse] Extracting claims from deviceAttributes array, count:', diagnosticInfo.deviceAttributes.length)
        for (const attr of diagnosticInfo.deviceAttributes) {
          if (attr && typeof attr === 'object' && 'id' in attr && 'value' in attr) {
            const namespace = (attr as any).ns || 'org.iso.18013.5.1'
            const elementId = (attr as any).id
            const elementValue = (attr as any).value
            const key = `${namespace}.${elementId}`
            // Only add if not already present (issuerSigned takes precedence)
            if (!(key in claims)) {
              claims[key] = elementValue
            }
            if (!(elementId in claims)) {
              claims[elementId] = elementValue
            }
          }
        }
      }

      console.log(`mdoc DeviceResponse decoded. DocType: ${docType}, Claims: ${JSON.stringify(claims)}`)

      return {
        type: 'MdocDeviceResponse',
        claims,
        docType,
      }
    } catch (error) {
      console.error('Failed to decode mdoc DeviceResponse:', error)
      throw new Error(`mdoc DeviceResponse decoding failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }
}
