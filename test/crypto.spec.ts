import * as chai from 'chai'
import * as chaiAsPromised from 'chai-as-promised'
import { keccak256 } from 'ethereum-cryptography/keccak'
import { bytesToHex, utf8ToBytes } from 'ethereum-cryptography/utils'
import { hexToBytes } from 'eth-connect'
import { AuthChain, Authenticator, AuthLinkType } from '../src'
import {
  computeAddress,
  createUnsafeIdentity,
  recoverPublicKey,
  sign
} from '../src/crypto'

chai.use(chaiAsPromised)
const expect = chai.expect

const prodAuthChain: AuthChain = [
  {
    type: AuthLinkType.SIGNER,
    payload: '0x3ea8147dabfe6818b0f8c1f8d756f4ad20321a65',
    signature: ''
  },
  {
    type: AuthLinkType.ECDSA_PERSONAL_EPHEMERAL,
    payload:
      'Decentraland Login\nEphemeral address: 0x05Ac0D29E42F9ae09B0EfA250BD3385FC3D0a68B\nExpiration: 2022-03-11T22:35:52.090Z',
    signature:
      '0xda87889b7d8aa91255d3f736b2519b6d3af42ce15f8fbc17dedf3d69f647835c7de6f6bfb37dd18fd5df1a7ad14ff3d118c2c880647f28b1b77b73453c97f2ea1b'
  },
  {
    type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
    payload: 'QmfQtX7BrXzZx7UwupsqNwKGirSZUVBpjN5whujwcp9qyk',
    signature:
      '0x201205d50cae412c4d4de3c08eeffee5ea7d3fa7a310a3d47f7521a9d14988ff7affcfa7c8381ec9d8416bab0231d71be210bbc21c7694fb1470592cec65a6141b'
  }
]

describe('Crypto utils', function() {
  this.timeout(999999)
  it('recovers a signature', async () => {
    const identity = createUnsafeIdentity()
    const hash = keccak256(utf8ToBytes('test'))
    const signature = sign(hexToBytes(identity.privateKey), hash)
    const recoveredPub = recoverPublicKey(hexToBytes(signature), hash)
    expect(bytesToHex(recoveredPub)).to.eq(identity.publicKey)
  })
  it('recovers a the key correctly 1', async () => {
    const hash = Authenticator.createEthereumMessageHash(prodAuthChain[1].payload)
    const recovered = computeAddress(
      recoverPublicKey(hexToBytes(prodAuthChain[1].signature), hash)
    )
    expect(recovered.toLowerCase()).to.eq(prodAuthChain[0].payload.toLowerCase())
  })
  it('recovers a the key correctly 2', async () => {
    const hash = Authenticator.createEthereumMessageHash(prodAuthChain[2].payload)
    const recovered = computeAddress(
      recoverPublicKey(hexToBytes(prodAuthChain[2].signature), hash)
    )
    expect(recovered.toLowerCase()).to.eq(
      '0x05Ac0D29E42F9ae09B0EfA250BD3385FC3D0a68B'.toLowerCase()
    )
  })

  it('initializeAuthChain with mock signature', async () => {
    const ephemeralIdentity = createUnsafeIdentity()
    const realAccount = createUnsafeIdentity()

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
    const hash = keccak256(utf8ToBytes(chain.authChain[1].payload))
    const recovered = computeAddress(
      recoverPublicKey(hexToBytes(chain.authChain[1].signature), hash)
    )
    expect(recovered).to.deep.eq(ephemeralIdentity.address)
  })
})
