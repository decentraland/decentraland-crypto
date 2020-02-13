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
  Signature
} from './types'

export class Authenticator {
  /** Validate that the signature belongs to the Ethereum address */
  static async validateSignature(
    expectedFinalAuthority: string,
    authChain: AuthChain,
    provider: EthereumProvider
  ): Promise<boolean> {
    let currentAuthority: string = ''

    for (let authLink of authChain) {
      const validator: ValidatorType = getValidatorByType(authLink.type)
      const { error, nextAuthority } = await validator(
        currentAuthority,
        authLink,
        provider
      )
      if (error) {
        return false
      }
      currentAuthority = nextAuthority ? nextAuthority : ''
    }

    return currentAuthority === expectedFinalAuthority
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
    entityId: string,
    ephemeralExpirationInMillis?: number
  ): AuthChain {
    let expiration
    if (ephemeralExpirationInMillis === undefined) {
      expiration = new Date()
      expiration.setMinutes(expiration.getMinutes() + ephemeralMinutesDuration)
    } else {
      expiration = new Date(ephemeralExpirationInMillis)
    }

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
    signer: (message: string) => Promise<string>,
    ephemeralExpirationInMillis?: number
  ): Promise<AuthIdentity> {
    let expiration
    if (ephemeralExpirationInMillis === undefined) {
      expiration = new Date()
      expiration.setMinutes(expiration.getMinutes() + ephemeralMinutesDuration)
    } else {
      expiration = new Date(ephemeralExpirationInMillis)
    }

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
  provider?: EthereumProvider
) => Promise<{ error?: boolean; nextAuthority?: string }>

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
  try {
    const signerAddress = recover(
      authLink.signature,
      Authenticator.createEthereumMessageHash(authLink.payload)
    )
    if (authority.toLocaleLowerCase() === signerAddress.toLocaleLowerCase()) {
      return { nextAuthority: authLink.payload }
    }
  } catch (e) {
    // console.error(e)
  }
  return { error: true }
}

export const ECDSA_PERSONAL_EPHEMERAL_VALIDATOR: ValidatorType = async (
  authority: string,
  authLink: AuthLink
) => {
  try {
    // authLink payload structure: <human-readable message>\nEphemeral address: <ephemeral-eth-address>\nExpiration: <timestamp>
    // authLink payload example  : Decentraland Login\nEphemeral address: 0x123456\nExpiration: 2020-01-20T22:57:11.334Z
    const payloadParts: string[] = authLink.payload.split('\n')
    const ephemeralAddress: string = payloadParts[1].substring(
      'Ephemeral address: '.length
    )
    const expirationString: string = payloadParts[2].substring(
      'Expiration: '.length
    )
    const expiration = Date.parse(expirationString)

    if (expiration > Date.now()) {
      const signerAddress = recover(
        authLink.signature,
        Authenticator.createEthereumMessageHash(authLink.payload)
      )
      if (authority.toLocaleLowerCase() === signerAddress.toLocaleLowerCase()) {
        return { nextAuthority: ephemeralAddress }
      }
    }
  } catch (e) {
    // console.error(e)
  }
  return { error: true }
}

export const ECDSA_EIP_1654_EPHEMERAL_VALIDATOR: ValidatorType = async (
  authority: string,
  authLink: AuthLink,
  provider: EthereumProvider
) => {
  // bytes4(keccak256("isValidSignature(bytes32,bytes)")
  const ERC1271_MAGIC_VALUE = '0x1626ba7e'

  try {
    if (!provider) {
      throw new Error('Missing provider')
    }

    const eth = new Eth(provider)
    const signatureValidator = new SignatureValidator(
      eth,
      Address.fromString(authority)
    )

    // authLink payload structure: <human-readable message >\nEphemeral address: <ephemeral-eth - address >\nExpiration: <timestamp>
    // authLink payload example: Decentraland Login\nEphemeral address: 0x123456\nExpiration: 2020 - 01 - 20T22: 57: 11.334Z
    const payloadParts: string[] = authLink.payload.split('\n')
    const ephemeralAddress: string = payloadParts[1].substring(
      'Ephemeral address: '.length
    )
    const expirationString: string = payloadParts[2].substring(
      'Expiration: '.length
    )
    const expiration = Date.parse(expirationString)

    if (expiration > Date.now()) {
      const result = await signatureValidator.methods
        .isValidSignature(
          Authenticator.createEIP1271MessageHash(authLink.payload),
          authLink.signature
        )
        .call()

      if (result === ERC1271_MAGIC_VALUE) {
        return { nextAuthority: ephemeralAddress }
      }
    }
  } catch (e) {
    // console.error(e)
  }
  return { error: true }
}

const ERROR_VALIDATOR: ValidatorType = async (_: string, __: AuthLink) => {
  return { error: true }
}

export function getEphemeralSignatureType(signature: string): AuthLinkType {
  // ERC 1654 support https://github.com/ethereum/EIPs/issues/1654
  if (signature.length > 150) {
    return AuthLinkType.ECDSA_EIP_1654_EPHEMERAL
  } else {
    return AuthLinkType.ECDSA_PERSONAL_EPHEMERAL
  }
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
