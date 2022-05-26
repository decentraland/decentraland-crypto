import { keccak256 } from 'ethereum-cryptography/keccak'
import { utf8ToBytes } from 'ethereum-cryptography/utils'
import RequestManager, { bytesToHex, hexToBytes } from 'eth-connect'
import { SignatureValidator } from './contracts/SignatureValidator'
import {
  AuthIdentity,
  AuthChain,
  EthAddress,
  AuthLinkType,
  IdentityType,
  AuthLink,
  Signature,
  ValidationResult
} from './types'
import { moveMinutes } from './helper/utils'
import Blocks from './helper/blocks'
import { computeAddress, recoverPublicKey, sign } from './crypto'

export const VALID_SIGNATURE: string = 'VALID_SIGNATURE'

const PERSONAL_SIGNATURE_LENGTH = 132

export class Authenticator {
  /** Validate that the signature belongs to the Ethereum address */
  static async validateSignature(
    expectedFinalAuthority: string,
    authChain: AuthChain,
    provider: any,
    dateToValidateExpirationInMillis: number = Date.now()
  ): Promise<ValidationResult> {
    let currentAuthority: string = ''

    if (!Authenticator.isValidAuthChain(authChain)) {
      return {
        ok: false,
        message: 'ERROR: Malformed authChain'
      }
    }

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

  // TODO: unit test
  static isValidAuthChain(authChain: AuthChain): boolean {
    for (const [index, authLink] of authChain.entries()) {
      // SIGNER should be the first one
      if (index === 0 && authLink.type !== AuthLinkType.SIGNER) {
        return false
      }

      // SIGNER should be unique
      if (authLink.type === AuthLinkType.SIGNER && index !== 0) {
        return false
      }
    }

    return true
  }

  // TODO: unit test
  static createEthereumMessageHash(msg: string) {
    let msgWithPrefix: string = `\x19Ethereum Signed Message:\n${msg.length}${msg}`
    const msgHash = keccak256(utf8ToBytes(msgWithPrefix))
    return msgHash
  }

  // TODO: unit test
  // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1271.md
  static createEIP1271MessageHash(msg: string) {
    return keccak256(utf8ToBytes(msg))
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
        type: getSignedIdentitySignatureType(signature),
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
        type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
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
        type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
        payload: entityId,
        signature: secondSignature
      }
    ]
  }

  // TODO: unit test
  static createSignature(identity: IdentityType, message: string) {
    return sign(
      hexToBytes(identity.privateKey),
      Authenticator.createEthereumMessageHash(message)
    )
  }

  // TODO: unit test
  static ownerAddress(authChain: AuthChain): EthAddress {
    if (authChain.length > 0) {
      if (authChain[0].type === AuthLinkType.SIGNER) {
        return authChain[0].payload
      }
    }
    return 'Invalid-Owner-Address'
  }

  // TODO: unit test
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
  dateToValidateExpirationInMillis: number
  provider?: any
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
  const signerAddress = computeAddress(
    recoverPublicKey(
      hexToBytes(authLink.signature),
      Authenticator.createEthereumMessageHash(authLink.payload)
    )
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
    const signerAddress = computeAddress(
      recoverPublicKey(
        hexToBytes(authLink.signature),
        Authenticator.createEthereumMessageHash(message)
      )
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
  const { message, ephemeralAddress, expiration } = parseEmphemeralPayload(
    authLink.payload
  )

  const dateToValidateExpirationInMillis = options?.dateToValidateExpirationInMillis
    ? options?.dateToValidateExpirationInMillis
    : Date.now()
  if (expiration > dateToValidateExpirationInMillis) {
    if (
      await isValidEIP1654Message(
        options!.provider,
        authority,
        message,
        authLink.signature,
        dateToValidateExpirationInMillis
      )
    ) {
      return { nextAuthority: ephemeralAddress }
    }
  }

  throw new Error(
    `Ephemeral key expired. Expiration: ${expiration}. Test: ${dateToValidateExpirationInMillis}`
  )
}

export const EIP_1654_SIGNED_ENTITY_VALIDATOR: ValidatorType = async (
  authority: string,
  authLink: AuthLink,
  options?: ValidationOptions
) => {
  if (
    await isValidEIP1654Message(
      options!.provider,
      authority,
      authLink.payload,
      authLink.signature,
      options!.dateToValidateExpirationInMillis
    )
  ) {
    return { nextAuthority: authLink.payload }
  }

  throw new Error(`Invalid validation`)
}

const ERROR_VALIDATOR: ValidatorType = async (_: string, __: AuthLink) => {
  return { error: 'Error Validator.' }
}

export function getEphemeralSignatureType(signature: string): AuthLinkType {
  if (signature.length === PERSONAL_SIGNATURE_LENGTH) {
    return AuthLinkType.ECDSA_PERSONAL_EPHEMERAL
  } else {
    return AuthLinkType.ECDSA_EIP_1654_EPHEMERAL
  }
}

export function getSignedIdentitySignatureType(
  signature: string
): AuthLinkType {
  if (signature.length === PERSONAL_SIGNATURE_LENGTH) {
    return AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY
  } else {
    return AuthLinkType.ECDSA_EIP_1654_SIGNED_ENTITY
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

async function isValidEIP1654Message(
  provider: any | undefined,
  contractAddress: string,
  message: string,
  signature: string,
  dateToValidateExpirationInMillis: number
) {
  // bytes4(keccak256("isValidSignature(bytes32,bytes)")
  const ERC1654_MAGIC_VALUE = '1626ba7e'

  if (!provider) {
    throw new Error('Missing provider')
  }
  const requestManager = new RequestManager(provider)
  const signatureValidator = await SignatureValidator(
    requestManager,
    contractAddress
  )

  const hashedMessage = Authenticator.createEIP1271MessageHash(message)
  const _signature = hexToBytes(signature)
  let result = bytesToHex(
    await signatureValidator.isValidSignature(hashedMessage, _signature)
  )

  if (result === ERC1654_MAGIC_VALUE) {
    return true
  } else {
    // check based on the dateToValidateExpirationInMillis
    const dater = new Blocks(requestManager)
    try {
      const { block } = await dater.getDate(
        dateToValidateExpirationInMillis,
        false
      )

      result = bytesToHex(
        await signatureValidator.isValidSignature(
          hashedMessage,
          _signature,
          block
        )
      )
    } catch (e) {
      throw new Error(`Invalid validation. Error: ${e.message}`)
    }

    if (result === ERC1654_MAGIC_VALUE) {
      return true
    }

    throw new Error(
      `Invalid validation. Expected: ${ERC1654_MAGIC_VALUE}. Actual: ${result}`
    )
  }
  return false
}

function getValidatorByType(type: AuthLinkType): ValidatorType {
  switch (type) {
    case AuthLinkType.SIGNER:
      return SIGNER_VALIDATOR
    case AuthLinkType.ECDSA_PERSONAL_EPHEMERAL:
      return ECDSA_PERSONAL_EPHEMERAL_VALIDATOR
    case AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY:
      return ECDSA_SIGNED_ENTITY_VALIDATOR
    case AuthLinkType.ECDSA_EIP_1654_EPHEMERAL:
      return ECDSA_EIP_1654_EPHEMERAL_VALIDATOR
    case AuthLinkType.ECDSA_EIP_1654_SIGNED_ENTITY:
      return EIP_1654_SIGNED_ENTITY_VALIDATOR
    default:
      return ERROR_VALIDATOR
  }
}
