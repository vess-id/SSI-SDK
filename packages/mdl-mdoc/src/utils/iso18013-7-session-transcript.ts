import { encode as cborEncode, decode as cborDecode } from 'cbor-x'
import { createHash } from 'crypto'

/**
 * OID4VP 1.0 (Final) SessionTranscript for Redirect-based flow
 *
 * Based on OpenID4VP 1.0 Appendix B.2.6
 *
 * SessionTranscript = [
 *   DeviceEngagementBytes,  // null for OID4VP
 *   EReaderKeyBytes,        // null for OID4VP
 *   OpenID4VPHandover       // OID4VP 1.0 Handover structure
 * ]
 *
 * OpenID4VPHandover = [
 *   "OpenID4VPHandover",          // Fixed identifier
 *   OpenID4VPHandoverInfoHash     // SHA-256 hash of HandoverInfo
 * ]
 *
 * OpenID4VPHandoverInfo = [
 *   clientId,        // client_id from Authorization Request
 *   nonce,           // nonce from Authorization Request (Verifier-generated)
 *   jwkThumbprint,   // JWK SHA-256 Thumbprint (Byte String) or null
 *   responseUri      // response_uri from Authorization Request
 * ]
 */

/**
 * OID4VP Authorization Request structure for SessionTranscript
 * OID4VP 1.0 Final Specification compliant
 */
export interface OID4VPAuthorizationRequest {
  /** OID4VP client_id */
  client_id: string
  /** OID4VP response_uri */
  response_uri: string
  /** OID4VP nonce (verifier generated) */
  nonce: string
  /** OID4VP state (optional) */
  state?: string
  /** OID4VP response_type (常に "vp_token") */
  response_type?: string
  /** OID4VP response_mode (常に "direct_post") */
  response_mode?: string
  /** DCQL query (ISO 18013-7 Annex B) */
  dcql_query?: any
  /** Presentation Definition (PE 2.0, optional - dcql_queryと排他的) */
  presentation_definition?: any
  /** Client metadata */
  client_metadata?: any
}

/**
 * SessionTranscript生成のパラメータ (OID4VP 1.0 Final用)
 */
export interface CreateSessionTranscriptForOID4VPArgs {
  /** OID4VP Authorization Request parameters */
  authorizationRequest: OID4VPAuthorizationRequest
  /** JWK Thumbprint for encrypted response (null for direct_post without encryption) */
  jwkThumbprint?: Uint8Array | null
}

/**
 * SessionTranscript生成のパラメータ (QRコード近接通信用)
 * ISO 18013-5 Section 9.1.1準拠
 */
export interface CreateSessionTranscriptForProximityQRArgs {
  /** Device Engagement (CBOR encoded) */
  deviceEngagement: Uint8Array
  /** Ephemeral Reader Public Key (オプション、QRの場合は通常null) */
  eReaderPublicKey?: Uint8Array | null
}

/**
 * SessionTranscript生成のパラメータ (NFC/BLE近接通信用)
 * ISO 18013-5 Section 9.1.2/9.1.3準拠
 */
export interface CreateSessionTranscriptForProximityNFCArgs {
  /** Device Engagement (CBOR encoded) */
  deviceEngagement: Uint8Array
  /** Ephemeral Reader Public Key (DH鍵交換用、必須) */
  eReaderPublicKey: Uint8Array
  /** Handover Select Message (NFC用、オプション) */
  handoverSelect?: Uint8Array
}

/**
 * ISO 18013-7準拠のSessionTranscript生成ユーティリティ
 *
 * OID4VPにおけるmdoc提示のためのSessionTranscriptを生成します。
 * Handover構造にDCQL queryとOID4VP Authorization Requestの
 * 全パラメータを含めることで、ISO 18013-7完全準拠を実現します。
 */
export class ISO18013_7_SessionTranscriptUtils {
  /**
   * OID4VP 1.0用のSessionTranscriptを生成
   *
   * OID4VP 1.0 Appendix B.2.6準拠 (Redirect-based flow)
   *
   * @param args - SessionTranscript生成パラメータ
   * @returns CBOR encoded SessionTranscript
   *
   * @example
   * ```typescript
   * const sessionTranscript = ISO18013_7_SessionTranscriptUtils.createForOID4VP({
   *   authorizationRequest: {
   *     client_id: "https://verifier.example.com",
   *     response_uri: "https://verifier.example.com/callback",
   *     nonce: "verifier-nonce-456",
   *     state: "correlation-id-789",
   *     dcql_query: {...},
   *   },
   *   jwkThumbprint: null // or Uint8Array for encrypted responses
   * });
   * ```
   */
  static createForOID4VP(args: CreateSessionTranscriptForOID4VPArgs): Uint8Array {
    try {
      const { authorizationRequest, jwkThumbprint = null } = args

      // OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
      const handoverInfo = [
        authorizationRequest.client_id,
        authorizationRequest.nonce,
        jwkThumbprint, // null for direct_post without encryption
        authorizationRequest.response_uri,
      ]

      // CBOR encode OpenID4VPHandoverInfo
      const handoverInfoBytes = cborEncode(handoverInfo)

      // Calculate SHA-256 hash of handoverInfoBytes
      const hash = createHash('sha256').update(handoverInfoBytes).digest()

      // OpenID4VPHandover = ["OpenID4VPHandover", hash]
      // Use Buffer instead of Uint8Array to avoid Tag 64 encoding
      const handover = ['OpenID4VPHandover', Buffer.from(hash)]

      // SessionTranscript = [null, null, OpenID4VPHandover]
      const sessionTranscript = [
        null, // DeviceEngagementBytes - OID4VP では null
        null, // EReaderKeyBytes - OID4VP では null
        handover,
      ]

      // CBORエンコード
      const encoded = cborEncode(sessionTranscript)
      return new Uint8Array(encoded)
    } catch (error) {
      console.error('Failed to create SessionTranscript for OID4VP:', error)
      throw new Error(`SessionTranscript creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  /**
   * QRコード近接通信用のSessionTranscriptを生成
   *
   * ISO 18013-5 Section 9.1.1準拠
   * SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
   * QRコードの場合、Handoverは通常nullまたは空
   *
   * @param args - SessionTranscript生成パラメータ
   * @returns CBOR encoded SessionTranscript
   *
   * @example
   * ```typescript
   * const deviceEngagement = cborEncode({
   *   version: "1.0",
   *   security: 256,
   *   deviceRetrievalMethods: [{ type: 1, version: 1 }]
   * });
   *
   * const sessionTranscript = ISO18013_7_SessionTranscriptUtils.createForProximityQR({
   *   deviceEngagement: new Uint8Array(deviceEngagement),
   *   eReaderPublicKey: null
   * });
   * ```
   */
  static createForProximityQR(args: CreateSessionTranscriptForProximityQRArgs): Uint8Array {
    try {
      // SessionTranscript構造を作成
      // [DeviceEngagementBytes, EReaderKeyBytes, Handover]
      // QRコードの場合、Handoverはnull（デバイス認証なし）
      const sessionTranscript = [
        args.deviceEngagement, // DeviceEngagementBytes
        args.eReaderPublicKey || null, // EReaderKeyBytes - QRでは通常null
        null, // Handover - QRでは不要
      ]

      // CBORエンコード
      const encoded = cborEncode(sessionTranscript)
      return new Uint8Array(encoded)
    } catch (error) {
      console.error('Failed to create SessionTranscript for Proximity QR:', error)
      throw new Error(`SessionTranscript creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  /**
   * NFC/BLE近接通信用のSessionTranscriptを生成
   *
   * ISO 18013-5 Section 9.1.2/9.1.3準拠
   * SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
   * NFC/BLEの場合、暗号化鍵交換のためEReaderKeyBytesが必要
   *
   * @param args - SessionTranscript生成パラメータ
   * @returns CBOR encoded SessionTranscript
   *
   * @example
   * ```typescript
   * const sessionTranscript = ISO18013_7_SessionTranscriptUtils.createForProximityNFC({
   *   deviceEngagement: deviceEngagementBytes,
   *   eReaderPublicKey: readerPublicKeyBytes,
   *   handoverSelect: handoverSelectMessageBytes
   * });
   * ```
   */
  static createForProximityNFC(args: CreateSessionTranscriptForProximityNFCArgs): Uint8Array {
    try {
      // Handover構造を作成（NFC/BLE用）
      const handover = [
        args.handoverSelect || null, // handoverSelectMessage
        null, // handoverRequestMessage - 近接通信では通常不使用
        null, // handoverResponseMessage - 近接通信では通常不使用
      ]

      // SessionTranscript構造を作成
      // [DeviceEngagementBytes, EReaderKeyBytes, Handover]
      const sessionTranscript = [
        args.deviceEngagement, // DeviceEngagementBytes
        args.eReaderPublicKey, // EReaderKeyBytes - DH鍵交換用
        handover, // Handover
      ]

      // CBORエンコード
      const encoded = cborEncode(sessionTranscript)
      return new Uint8Array(encoded)
    } catch (error) {
      console.error('Failed to create SessionTranscript for Proximity NFC:', error)
      throw new Error(`SessionTranscript creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  /**
   * SessionTranscriptをデコードしてHandover構造を抽出
   *
   * デバッグ・検証用
   *
   * @param sessionTranscriptBytes - CBOR encoded SessionTranscript
   * @returns デコードされたSessionTranscript構造
   */
  static decodeSessionTranscript(sessionTranscriptBytes: Uint8Array): {
    deviceEngagementBytes: any
    eReaderKeyBytes: any
    handover: {
      handoverSelectMessage: any
      handoverRequestMessage: any
      handoverResponseMessage: any
    }
  } {
    try {
      const decoded = cborDecode(sessionTranscriptBytes)

      if (!Array.isArray(decoded) || decoded.length < 3) {
        throw new Error('Invalid SessionTranscript structure')
      }

      const [deviceEngagementBytes, eReaderKeyBytes, handover] = decoded

      if (!Array.isArray(handover) || handover.length < 3) {
        throw new Error('Invalid Handover structure')
      }

      return {
        deviceEngagementBytes,
        eReaderKeyBytes,
        handover: {
          handoverSelectMessage: handover[0],
          handoverRequestMessage: handover[1],
          handoverResponseMessage: handover[2],
        },
      }
    } catch (error) {
      console.error('Failed to decode SessionTranscript:', error)
      throw new Error(`SessionTranscript decoding failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    }
  }

  /**
   * SessionTranscript構造を検証
   *
   * ISO 18013-5/18013-7準拠性をチェック
   *
   * @param sessionTranscriptBytes - CBOR encoded SessionTranscript
   * @param expectedType - 期待するSessionTranscriptのタイプ (デフォルト: 'OID4VP')
   * @returns 検証結果
   */
  static validateSessionTranscript(
    sessionTranscriptBytes: Uint8Array,
    expectedType: 'OID4VP' | 'ProximityQR' | 'ProximityNFC' = 'OID4VP',
  ): {
    isValid: boolean
    errors: string[]
    warnings: string[]
  } {
    const result = {
      isValid: true,
      errors: [] as string[],
      warnings: [] as string[],
    }

    try {
      const decoded = this.decodeSessionTranscript(sessionTranscriptBytes)

      switch (expectedType) {
        case 'OID4VP':
          // OID4VP検証: DeviceEngagementBytes と EReaderKeyBytes は null
          if (decoded.deviceEngagementBytes !== null) {
            result.warnings.push('DeviceEngagementBytes should be null for OID4VP')
          }

          if (decoded.eReaderKeyBytes !== null) {
            result.warnings.push('EReaderKeyBytes should be null for OID4VP')
          }

          // Handover検証
          const handover = decoded.handover

          if (handover.handoverSelectMessage !== null) {
            result.warnings.push('handoverSelectMessage should be null for OID4VP')
          }

          if (!handover.handoverRequestMessage) {
            result.errors.push('handoverRequestMessage is missing')
            result.isValid = false
          } else {
            // handoverRequestMessage の必須フィールドをチェック
            const req = handover.handoverRequestMessage

            if (!req.client_id) {
              result.errors.push('client_id is missing in handoverRequestMessage')
              result.isValid = false
            }

            if (!req.response_uri) {
              result.errors.push('response_uri is missing in handoverRequestMessage')
              result.isValid = false
            }

            if (!req.nonce) {
              result.errors.push('nonce is missing in handoverRequestMessage')
              result.isValid = false
            }

            // DCQL query または Presentation Definition のいずれかが必要
            if (!req.dcql_query && !req.presentation_definition) {
              result.warnings.push('Neither dcql_query nor presentation_definition is present')
            }

            // deviceSession (mdoc nonce) の存在確認
            if (!req.deviceSession) {
              result.warnings.push('deviceSession (mdoc nonce) is missing')
            }
          }

          if (handover.handoverResponseMessage !== null) {
            result.warnings.push('handoverResponseMessage should be null for OID4VP')
          }
          break

        case 'ProximityQR':
          // QRコード近接通信検証
          if (!decoded.deviceEngagementBytes) {
            result.errors.push('DeviceEngagementBytes is required for Proximity QR')
            result.isValid = false
          }

          if (decoded.eReaderKeyBytes !== null) {
            result.warnings.push('EReaderKeyBytes should be null for Proximity QR (unless reader authentication is used)')
          }

          if (decoded.handover && decoded.handover.handoverRequestMessage) {
            result.warnings.push('Handover should be null for Proximity QR')
          }
          break

        case 'ProximityNFC':
          // NFC/BLE近接通信検証
          if (!decoded.deviceEngagementBytes) {
            result.errors.push('DeviceEngagementBytes is required for Proximity NFC')
            result.isValid = false
          }

          if (!decoded.eReaderKeyBytes) {
            result.errors.push('EReaderKeyBytes is required for Proximity NFC (for key agreement)')
            result.isValid = false
          }

          // Handover は存在してもよい（handoverSelectMessage）
          break

        default:
          result.errors.push(`Unknown SessionTranscript type: ${expectedType}`)
          result.isValid = false
      }
    } catch (error) {
      result.errors.push(`Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`)
      result.isValid = false
    }

    return result
  }
}
