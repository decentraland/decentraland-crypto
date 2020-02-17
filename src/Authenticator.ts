import { hash, sign, recover } from 'eth-crypto'
import { Eth } from 'web3x/eth'
import { Address } from 'web3x/address'
import { EthereumProvider } from 'web3x/providers'

import { SignatureValidator } from './contracts/SignatureValidator'
import {
  AuthIdentity,
  AuthChain,
  EthAddress,
  AuthLinkType,
  IdentityType,
  AuditInfo,
  AuthLink,
  Signature,
  ValidationResult
} from './types'
import { moveMinutes } from './helper/utils'

export const VALID_SIGNATURE: string = 'VALID_SIGNATURE'

export class Authenticator {
  /** Validate that the signature belongs to the Ethereum address */
  static async validateSignature(
    expectedFinalAuthority: string,
    authChain: AuthChain,
    provider: EthereumProvider,
    dateToValidateExpirationInMillis: number = Date.now()
  ): Promise<ValidationResult> {
    let currentAuthority: string = ''

    for (let authLink of authChain) {
      const validator: ValidatorType = getValidatorByType(authLink.type)
      try {
        const { nextAuthority } = await validator(currentAuthority, authLink, {
          provider,
          dateToValidateExpirationInMillis
        })
        currentAuthority = nextAuthority ? nextAuthority : ''
      } catch (e) {
        return {
          ok: false,
          message: `ERROR. Link type: ${authLink.type}. ${e.message}.`
        }
      }
    }

    const ok = currentAuthority === expectedFinalAuthority

    return {
      ok,
      message: ok
        ? undefined
        : `ERROR: Invalid final authority. Expected: ${expectedFinalAuthority}. Current ${currentAuthority}.`
    }
  }

  static createEthereumMessageHash(msg: string) {
    let msgWithPrefix: string = `\x19Ethereum Signed Message:\n${msg.length}${msg}`
    const msgHash = hash.keccak256(msgWithPrefix)
    return msgHash
  }

  // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1271.md
  static createEIP1271MessageHash(msg: string) {
    return hash.keccak256([
      {
        type: 'string',
        value: msg
      }
    ])
  }

  static createSimpleAuthChain(
    finalPayload: string,
    ownerAddress: EthAddress,
    signature: Signature
  ): AuthChain {
    return [
      {
        type: AuthLinkType.SIGNER,
        payload: ownerAddress,
        signature: ''
      },
      {
        type: AuthLinkType.ECDSA_SIGNED_ENTITY,
        payload: finalPayload,
        signature: signature
      }
    ]
  }

  static createAuthChain(
    ownerIdentity: IdentityType,
    ephemeralIdentity: IdentityType,
    ephemeralMinutesDuration: number,
    entityId: string
  ): AuthChain {
    const expiration = moveMinutes(ephemeralMinutesDuration)

    const ephemeralMessage = Authenticator.getEphemeralMessage(
      ephemeralIdentity.address,
      expiration
    )
    const firstSignature = Authenticator.createSignature(
      ownerIdentity,
      ephemeralMessage
    )
    const secondSignature = Authenticator.createSignature(
      ephemeralIdentity,
      entityId
    )

    const authChain: AuthChain = [
      {
        type: AuthLinkType.SIGNER,
        payload: ownerIdentity.address,
        signature: ''
      },
      {
        type: AuthLinkType.ECDSA_PERSONAL_EPHEMERAL,
        payload: ephemeralMessage,
        signature: firstSignature
      },
      {
        type: AuthLinkType.ECDSA_SIGNED_ENTITY,
        payload: entityId,
        signature: secondSignature
      }
    ]

    return authChain
  }

  static async initializeAuthChain(
    ethAddress: EthAddress,
    ephemeralIdentity: IdentityType,
    ephemeralMinutesDuration: number,
    signer: (message: string) => Promise<string>
  ): Promise<AuthIdentity> {
    let expiration = new Date()
    expiration.setMinutes(expiration.getMinutes() + ephemeralMinutesDuration)

    const ephemeralMessage = Authenticator.getEphemeralMessage(
      ephemeralIdentity.address,
      expiration
    )
    const firstSignature = await signer(ephemeralMessage)

    const authChain: AuthChain = [
      { type: AuthLinkType.SIGNER, payload: ethAddress, signature: '' },
      {
        type: getEphemeralSignatureType(firstSignature),
        payload: ephemeralMessage,
        signature: firstSignature
      }
    ]

    return {
      ephemeralIdentity,
      expiration,
      authChain
    }
  }

  static signPayload(authIdentity: AuthIdentity, entityId: string) {
    const secondSignature = Authenticator.createSignature(
      authIdentity.ephemeralIdentity,
      entityId
    )
    return [
      ...authIdentity.authChain,
      {
        type: AuthLinkType.ECDSA_SIGNED_ENTITY,
        payload: entityId,
        signature: secondSignature
      }
    ]
  }

  static createSignature(identity: IdentityType, message: string) {
    return sign(
      identity.privateKey,
      Authenticator.createEthereumMessageHash(message)
    )
  }

  static ownerAddress(auditInfo: AuditInfo): EthAddress {
    if (auditInfo.authChain.length > 0) {
      if (auditInfo.authChain[0].type === AuthLinkType.SIGNER) {
        return auditInfo.authChain[0].payload
      }
    }
    return 'Invalid-Owner-Address'
  }

  static getEphemeralMessage(ephemeralAddress: string, expiration: Date) {
    return `Decentraland Login\nEphemeral address: ${ephemeralAddress}\nExpiration: ${expiration.toISOString()}`
  }
}

type ValidatorType = (
  authority: string,
  authLink: AuthLink,
  options?: ValidationOptions
) => Promise<{ error?: string; nextAuthority?: string }>

type ValidationOptions = {
  dateToValidateExpirationInMillis?: number
  provider?: EthereumProvider
}

export const SIGNER_VALIDATOR: ValidatorType = async (
  _: string,
  authLink: AuthLink
) => {
  return { nextAuthority: authLink.payload }
}

export const ECDSA_SIGNED_ENTITY_VALIDATOR: ValidatorType = async (
  authority: string,
  authLink: AuthLink
) => {
  const signerAddress = recover(
    sanitizeSignature(authLink.signature),
    Authenticator.createEthereumMessageHash(authLink.payload)
  )
  const expectedSignedAddress = authority.toLocaleLowerCase()
  const actualSignedAddress = signerAddress.toLocaleLowerCase()

  if (expectedSignedAddress === actualSignedAddress) {
    return { nextAuthority: authLink.payload }
  }

  throw new Error(
    `Invalid signer address. Expected: ${expectedSignedAddress}. Actual: ${actualSignedAddress}`
  )
}

export const ECDSA_PERSONAL_EPHEMERAL_VALIDATOR: ValidatorType = async (
  authority: string,
  authLink: AuthLink,
  options?: ValidationOptions
) => {
  const { message, ephemeralAddress, expiration } = parseEmphemeralPayload(
    authLink.payload
  )

  const dateToValidateExpirationInMillis = options!
    .dateToValidateExpirationInMillis
    ? options!.dateToValidateExpirationInMillis
    : Date.now()

  if (expiration > dateToValidateExpirationInMillis) {
    const signerAddress = recover(
      sanitizeSignature(authLink.signature),
      Authenticator.createEthereumMessageHash(message)
    )
    const expectedSignedAddress = authority.toLocaleLowerCase()
    const actualSignedAddress = signerAddress.toLocaleLowerCase()

    if (expectedSignedAddress === actualSignedAddress) {
      return { nextAuthority: ephemeralAddress }
    }

    throw new Error(
      `Invalid signer address. Expected: ${expectedSignedAddress}. Actual: ${actualSignedAddress}`
    )
  }

  throw new Error(
    `Ephemeral key expired. Expiration: ${expiration}. Test: ${dateToValidateExpirationInMillis}`
  )
}

export const ECDSA_EIP_1654_EPHEMERAL_VALIDATOR: ValidatorType = async (
  authority: string,
  authLink: AuthLink,
  options?: ValidationOptions
) => {
  // bytes4(keccak256("isValidSignature(bytes32,bytes)")
  const ERC1271_MAGIC_VALUE = '0x1626ba7e'

  const provider = options!.provider
  if (!provider) {
    throw new Error('Missing provider')
  }

  const eth = new Eth(provider)
  const signatureValidator = new SignatureValidator(
    eth,
    Address.fromString(authority)
  )

  const { message, ephemeralAddress, expiration } = parseEmphemeralPayload(
    authLink.payload
  )

  const dateToValidateExpirationInMillis = options?.dateToValidateExpirationInMillis
    ? options?.dateToValidateExpirationInMillis
    : Date.now()
  if (expiration > dateToValidateExpirationInMillis) {
    const result = await signatureValidator.methods
      .isValidSignature(
        Authenticator.createEIP1271MessageHash(message),
        authLink.signature
      )
      .call()

    if (result === ERC1271_MAGIC_VALUE) {
      return { nextAuthority: ephemeralAddress }
    }

    throw new Error(
      `Invalid validation. Expected: ${ERC1271_MAGIC_VALUE}.Actual: ${result}`
    )
  }

  throw new Error(
    `Ephemeral key expired. Expiration: ${expiration}. Test: ${dateToValidateExpirationInMillis}`
  )
}

const ERROR_VALIDATOR: ValidatorType = async (_: string, __: AuthLink) => {
  return { error: 'Error Validator.' }
}

export function getEphemeralSignatureType(signature: string): AuthLinkType {
  // ERC 1654 support https://github.com/ethereum/EIPs/issues/1654
  if (signature.length > 150) {
    return AuthLinkType.ECDSA_EIP_1654_EPHEMERAL
  } else {
    return AuthLinkType.ECDSA_PERSONAL_EPHEMERAL
  }
}

export function parseEmphemeralPayload(
  payload: string
): { message: string; ephemeralAddress: string; expiration: number } {
  // authLink payload structure: <human-readable message >\nEphemeral address: <ephemeral-eth - address >\nExpiration: <timestamp>
  // authLink payload example: Decentraland Login\nEphemeral address: 0x123456\nExpiration: 2020 - 01 - 20T22: 57: 11.334Z
  const message = payload.replace(/\r/g, '')
  const payloadParts: string[] = message.split('\n')
  const ephemeralAddress: string = payloadParts[1].substring(
    'Ephemeral address: '.length
  )
  const expirationString: string = payloadParts[2].substring(
    'Expiration: '.length
  )

  const expiration = Date.parse(expirationString)

  return { message, ephemeralAddress, expiration }
}

function sanitizeSignature(signature: string): string {
  let sanitizedSignature = signature

  const version = parseInt(signature.slice(-2), 16)

  if (version === 0 || version === 1) {
    sanitizedSignature =
      signature.substr(0, signature.length - 2) + (version + 27).toString(16)
  }

  return sanitizedSignature
}

function getValidatorByType(type: AuthLinkType): ValidatorType {
  switch (type) {
    case AuthLinkType.SIGNER:
      return SIGNER_VALIDATOR
    case AuthLinkType.ECDSA_PERSONAL_EPHEMERAL:
      return ECDSA_PERSONAL_EPHEMERAL_VALIDATOR
    case AuthLinkType.ECDSA_SIGNED_ENTITY:
      return ECDSA_SIGNED_ENTITY_VALIDATOR
    case AuthLinkType.ECDSA_EIP_1654_EPHEMERAL:
      return ECDSA_EIP_1654_EPHEMERAL_VALIDATOR
    default:
      return ERROR_VALIDATOR
  }
}
