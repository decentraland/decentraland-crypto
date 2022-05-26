import { getAddress } from 'eth-connect'
import { keccak256 } from 'ethereum-cryptography/keccak'
import { utils, getPublicKey } from 'ethereum-cryptography/secp256k1'
import { ecdsaRecover, ecdsaSign } from 'ethereum-cryptography/secp256k1-compat'
import { bytesToHex, toHex } from 'ethereum-cryptography/utils'

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
  let pubKey = ecdsaRecover(sigOnly, recoveryNumber, hash, false)
  // remove trailing '04'
  return pubKey.slice(1)
}

export function sign(privateKey: Uint8Array, hash: Uint8Array): string {
  const sigObj = ecdsaSign(hash, privateKey)
  const recoveryId = sigObj.recid === 1 ? '1c' : '1b'
  return '0x' + toHex(sigObj.signature) + recoveryId
}

export function computeAddress(key: Uint8Array): string {
  // Strip off the leading "0x04"
  let publicKey = key.length == 65 && key[0] == 0x04 ? key.slice(1) : key
  return getAddress(toHex(keccak256(publicKey)).substring(24))
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
    privateKey: '0x' + bytesToHex(privateKey),
    publicKey: bytesToHex(publicKey),
    address
  }
}
