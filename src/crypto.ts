import {
  bytesToHex,
  concatBytes,
  getAddress,
  hexToBytes,
  isHex,
  sha3,
  stringToUtf8Bytes,
  toHex
} from 'eth-connect'
import { utils, getPublicKey } from 'ethereum-cryptography/secp256k1'
import { ecdsaRecover, ecdsaSign } from 'ethereum-cryptography/secp256k1-compat'

/**
 * returns the publicKey for the privateKey with which the messageHash was signed
 * @param  {string} signature
 * @param  {string} hash
 */
export function recoverPublicKey(
  signature: Uint8Array,
  hash: Uint8Array
): Uint8Array {
  if (signature.length !== 65) {
    throw new Error('Invalid signature length' + signature.length)
  }

  // split into v-value and sig
  const sigOnly = signature.slice(0, signature.length - 1) // all but last 2 chars
  const recoveryNumber = signature[64] === 0x1c ? 1 : 0
  const pubKey = ecdsaRecover(sigOnly, recoveryNumber, hash, false)
  // remove trailing '04'
  return pubKey.slice(1)
}

function sanitizeSignature(signature: Uint8Array): Uint8Array {
  if (signature.length !== 65) throw new Error('Invalid ethereum signature')

  const version = signature[64]

  if (version === 0 || version === 1) {
    const newSignature = new Uint8Array(signature)
    newSignature[64] = version + 27
    return newSignature
  }

  return signature
}

export function recoverAddressFromEthSignature(
  signature: Uint8Array | string,
  msg: string | Uint8Array
) {
  if (typeof signature === 'string') {
    if (isHex(signature))
      return recoverAddressFromEthSignature(hexToBytes(signature), msg)
    throw new Error('String signatures must be encoded in hex')
  }

  return computeAddress(
    recoverPublicKey(
      sanitizeSignature(signature),
      createEthereumMessageHash(msg)
    )
  )
}

export function sign(privateKey: Uint8Array, hash: Uint8Array): string {
  const sigObj = ecdsaSign(hash, privateKey)
  const recoveryId = sigObj.recid === 1 ? '1c' : '1b'
  return toHex(sigObj.signature) + recoveryId
}

export function createEthereumMessageHash(msg: string | Uint8Array) {
  const message = typeof msg === 'string' ? stringToUtf8Bytes(msg) : msg
  const bytes = concatBytes(
    stringToUtf8Bytes(`\x19Ethereum Signed Message:\n`),
    stringToUtf8Bytes(String(message.length)),
    message
  )
  return hexToBytes(sha3(bytes))
}

// Emulates eth_personalSign
export function ethSign(
  privateKey: Uint8Array,
  message: Uint8Array | string
): string {
  return sign(privateKey, createEthereumMessageHash(message))
}

export function computeAddress(key: Uint8Array): string {
  // Strip off the leading "0x04"
  const publicKey = key.length === 65 && key[0] === 0x04 ? key.slice(1) : key
  return getAddress(sha3(publicKey).substring(24))
}

/**
 * This method should not be used. It may use non-secure random number generators.
 */
export function createUnsafeIdentity() {
  const privateKey = utils.randomPrivateKey()
  // remove heading 0x04
  const publicKey = getPublicKey(privateKey).slice(1)
  const address = computeAddress(publicKey)

  return {
    privateKey: bytesToHex(privateKey),
    publicKey: bytesToHex(publicKey),
    address
  }
}
