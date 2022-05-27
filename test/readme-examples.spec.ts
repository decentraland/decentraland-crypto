import { hexToBytes } from 'eth-connect'
import { Authenticator } from '../src/Authenticator'
import { createIdentity } from 'eth-crypto'
import { bytesToHex, utf8ToBytes } from 'ethereum-cryptography/utils'
import { keccak256 } from 'ethereum-cryptography/keccak'
import {
  ethSign,
  recoverAddressFromEthSignature,
  recoverPublicKey,
  sign
} from '../src/crypto'

describe('eth-crypto', function () {
  it('sanity: recovers a signature', async () => {
    const identity = createIdentity()
    const hash = keccak256(utf8ToBytes('test'))
    const signature = sign(hexToBytes(identity.privateKey), hash)
    const recoveredPub = recoverPublicKey(hexToBytes(signature), hash)
    expect(bytesToHex(recoveredPub)).toEqual(identity.publicKey)
  })

  it('sanity: recovers an eth signature', async () => {
    const identity = createIdentity()
    const signature = ethSign(hexToBytes(identity.privateKey), 'test')
    const recoveredPub = recoverAddressFromEthSignature(signature, 'test')
    expect(recoveredPub).toEqual(identity.address)
  })

  it('createAuthChain with mock signature', async () => {
    const ephemeralIdentity = createIdentity()
    const realAccount = createIdentity()
    const message = 'test'

    const authChain = Authenticator.createAuthChain(
      realAccount,
      ephemeralIdentity,
      10,
      message
    )

    expect(authChain[0].type).toEqual('SIGNER')
    expect(authChain[0].payload).toEqual(realAccount.address)

    expect(authChain[1].type).toEqual('ECDSA_EPHEMERAL')
    const recovered = recoverAddressFromEthSignature(
      authChain[1].signature,
      authChain[1].payload
    )
    expect(recovered).toEqual(realAccount.address)
    expect(authChain.length).toEqual(3)
  })

  it('initializeAuthChain with mock signature', async () => {
    const ephemeralIdentity = createIdentity()
    const realAccount = createIdentity()

    const authenticator = await Authenticator.initializeAuthChain(
      realAccount.address,
      ephemeralIdentity,
      10,
      async (message) => {
        return Authenticator.createSignature(realAccount, message)
      }
    )

    expect(authenticator.authChain[0].type).toEqual('SIGNER')
    expect(authenticator.authChain[0].payload).toEqual(realAccount.address)

    expect(authenticator.authChain[1].type).toEqual('ECDSA_EPHEMERAL')
    const recovered = recoverAddressFromEthSignature(
      authenticator.authChain[1].signature,
      authenticator.authChain[1].payload
    )
    expect(recovered).toEqual(realAccount.address)
    expect(authenticator.authChain.length).toEqual(2)
  })
})
