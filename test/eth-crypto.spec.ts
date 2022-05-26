import * as chai from 'chai'
import * as chaiAsPromised from 'chai-as-promised'
import * as sinon from 'sinon'
import { getAddress, hexToBytes, HTTPProvider } from 'eth-connect'
import { Authenticator } from '../src/Authenticator'
import { AuthLinkType, AuthChain } from '../src/types'
import { createIdentity } from 'eth-crypto'
import { bytesToHex, utf8ToBytes } from 'ethereum-cryptography/utils'
import { keccak256 } from 'ethereum-cryptography/keccak'
import { computeAddress, recoverPublicKey, sign } from '../src/crypto'

chai.use(chaiAsPromised)
const expect = chai.expect

describe('static-signatures', () => {
  const ephemeralIdentity = {
    privateKey:
      '0x8d11d14dd05b58fa150ec39ceab942dbff334af4dd4e87df4244106023d758ce',
    publicKey:
      'a1a8de183be2f189bdfacf83ca4262016840c590abee0b2048288c3b9090dae87538eda022d7c6f82a5ed617b7138db1a63ebe92f7b1afc6de032d6568525f13',
    address: '0x68560651BD91509EB22b90f6F748422A26CA3425'
  }
  const realAccount = {
    privateKey:
      '0x800cbd114eba965fcb41c252b920e916d2be8851496f21f24f1b4dcadf51688e',
    publicKey:
      'e9f386a334fb21ce11151a88b54f4aebaf0e7ab7b8ad7b3be9c503857b278c7a7f4ccb611c5edd046e07bf1d1969c966b28fa9bfb10bf7bfa239625968bcfc4f',
    address: '0x13FE90239bfda363eC33a849b716616958c04f0F'
  }

  it('tests createSignature', () => {
    const message = 'menduz'
    const hash = Authenticator.createEthereumMessageHash(message)
    const sig = Authenticator.createSignature(realAccount, message)
    const addr = computeAddress(recoverPublicKey(hexToBytes(sig), hash))
    expect(addr).to.eq(realAccount.address)
  })

  it('createAuthChain with mock signature', async () => {
    const chain = Authenticator.createAuthChain(
      realAccount,
      ephemeralIdentity,
      10,
      'test'
    )
    expect(chain.length).to.deep.eq(3)

    // validate first part
    expect(chain[0].type).to.deep.eq('SIGNER')
    expect(chain[0].payload).to.deep.eq(getAddress(realAccount.address))

    // second part, signed with real account
    {
      expect(chain[1].type).to.deep.eq('ECDSA_EPHEMERAL')
      const hash = Authenticator.createEthereumMessageHash(chain[1].payload)
      const recovered = computeAddress(
        recoverPublicKey(hexToBytes(chain[1].signature), hash)
      )
      expect(recovered).to.deep.eq(getAddress(realAccount.address))
    }
    // third part, signed with ephemeral
    {
      expect(chain[2].type).to.deep.eq('ECDSA_SIGNED_ENTITY')
      const hash = Authenticator.createEthereumMessageHash(chain[2].payload)
      const recovered = computeAddress(
        recoverPublicKey(hexToBytes(chain[2].signature), hash)
      )
      expect(recovered).to.deep.eq(getAddress(ephemeralIdentity.address))
    }
  })
})

describe('eth-crypto', function() {
  this.timeout(999999)
  it('recovers a signature', async () => {
    const identity = createIdentity()
    const hash = keccak256(utf8ToBytes('test'))
    const signature = sign(hexToBytes(identity.privateKey), hash)
    const recoveredPub = recoverPublicKey(hexToBytes(signature), hash)
    expect(bytesToHex(recoveredPub)).to.eq(identity.publicKey)
  })

  it('initializeAuthChain with mock signature', async () => {
    const ephemeralIdentity = createIdentity()
    const realAccount = createIdentity()

    const chain = await Authenticator.initializeAuthChain(
      realAccount.address,
      ephemeralIdentity,
      10,
      async message => {
        return Authenticator.createSignature(realAccount, message)
      }
    )

    expect(chain.authChain.length).to.deep.eq(2)
    expect(chain.authChain[0].type).to.deep.eq('SIGNER')
    expect(chain.authChain[0].payload).to.deep.eq(realAccount.address)

    expect(chain.authChain[1].type).to.deep.eq('ECDSA_EPHEMERAL')
    const hash = Authenticator.createEthereumMessageHash(chain.authChain[1].payload)
    const recovered = computeAddress(
      recoverPublicKey(hexToBytes(chain.authChain[1].signature), hash)
    )
    expect(recovered).to.deep.eq(ephemeralIdentity.address)
  })
})
