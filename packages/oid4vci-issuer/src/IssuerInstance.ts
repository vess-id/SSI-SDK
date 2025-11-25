import { CredentialDataSupplier, VcIssuer } from '@vess-id/oid4vci-issuer'
import { createVciIssuerBuilder } from './functions'
import {
  AuthorizationServerMetadata,
  CNonceState,
  CredentialOfferSession,
  IssuerMetadata,
  IStateManager,
  URIState,
} from '@vess-id/oid4vci-common'
import { IIssuerOptions, IMetadataOptions, IRequiredContext } from './types/IOID4VCIIssuer'

/**
 * State manager options for distributed session management
 * These allow using external state managers (e.g., Redis) instead of in-memory storage
 */
export interface IStateManagerOptions {
  cNonceStateManager?: IStateManager<CNonceState>
  credentialOfferStateManager?: IStateManager<CredentialOfferSession>
  credentialOfferURIStateManager?: IStateManager<URIState>
}

export class IssuerInstance {
  private _issuer: VcIssuer | undefined
  private readonly _metadataOptions: IMetadataOptions
  private readonly _issuerOptions: IIssuerOptions
  private _issuerMetadata: IssuerMetadata
  private readonly _authorizationServerMetadata: AuthorizationServerMetadata
  private readonly _stateManagerOptions?: IStateManagerOptions

  public constructor({
    issuerOpts,
    metadataOpts,
    issuerMetadata,
    authorizationServerMetadata,
    stateManagerOptions,
  }: {
    issuerOpts: IIssuerOptions
    metadataOpts: IMetadataOptions
    issuerMetadata: IssuerMetadata
    authorizationServerMetadata: AuthorizationServerMetadata
    stateManagerOptions?: IStateManagerOptions
  }) {
    this._issuerOptions = issuerOpts
    this._metadataOptions = metadataOpts
    this._issuerMetadata = issuerMetadata
    this._authorizationServerMetadata = authorizationServerMetadata
    this._stateManagerOptions = stateManagerOptions
  }

  public async get(opts: { context: IRequiredContext; credentialDataSupplier?: CredentialDataSupplier }): Promise<VcIssuer> {
    if (!this._issuer) {
      const builder = await createVciIssuerBuilder(
        {
          issuerOpts: this.issuerOptions,
          issuerMetadata: this.issuerMetadata,
          authorizationServerMetadata: this.authorizationServerMetadata,
          credentialDataSupplier: opts?.credentialDataSupplier,
          // Pass external state managers if provided
          cNonceStateManager: this._stateManagerOptions?.cNonceStateManager,
          credentialOfferStateManager: this._stateManagerOptions?.credentialOfferStateManager,
          credentialOfferURIStateManager: this._stateManagerOptions?.credentialOfferURIStateManager,
        },
        opts.context,
      )
      this._issuer = builder.build()
    }
    return this._issuer
  }

  get issuerOptions() {
    return this._issuerOptions
  }

  get metadataOptions() {
    return this._metadataOptions
  }

  get issuerMetadata() {
    return this._issuerMetadata
  }

  set issuerMetadata(value: IssuerMetadata) {
    this._issuerMetadata = value
  }

  get authorizationServerMetadata() {
    return this._authorizationServerMetadata
  }
}
