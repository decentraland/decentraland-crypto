import { keccak256 } from 'ethereum-cryptography/keccak'
import { bytesToHex, utf8ToBytes } from 'ethereum-cryptography/utils'
import { hexToBytes } from 'eth-connect'
import { AuthChain, Authenticator, AuthLinkType } from '../src'
import { createUnsafeIdentity, ethSign, recoverAddressFromEthSignature, recoverPublicKey, sign } from '../src/crypto'

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

describe('Crypto utils', function () {
  describe('when recovering a signature from a key pair and hash', () => {
    it('should recover the original public key', async () => {
      const identity = createUnsafeIdentity()
      const hash = keccak256(utf8ToBytes('test'))
      const signature = sign(hexToBytes(identity.privateKey), hash)
      const recoveredPub = recoverPublicKey(hexToBytes(signature), hash)
      expect(bytesToHex(recoveredPub)).toEqual(identity.publicKey)
    })
  })

  describe('when recovering addresses from a production auth chain', () => {
    it('should recover the signer address from the ephemeral link', async () => {
      const recovered = recoverAddressFromEthSignature(prodAuthChain[1].signature ?? '', prodAuthChain[1].payload)
      expect(recovered.toLowerCase()).toEqual(prodAuthChain[0].payload.toLowerCase())
    })

    it('should recover the ephemeral address from the signed entity link', async () => {
      const recovered = recoverAddressFromEthSignature(prodAuthChain[2].signature ?? '', prodAuthChain[2].payload)
      expect(recovered.toLowerCase()).toEqual('0x05Ac0D29E42F9ae09B0EfA250BD3385FC3D0a68B'.toLowerCase())
    })
  })

  const tests = [
    {
      address: '0xEB014f8c8B418Db6b45774c326A0E64C78914dC0',
      privateKey: hexToBytes('0xbe6383dad004f233317e46ddb46ad31b16064d14447a95cc1d8c8d4bc61c3728'),
      data: 'Some data',
      signature:
        '0xa8037a6116c176a25e6fc224947fde9e79a2deaa0dd8b67b366fbdfdbffc01f953e41351267b20d4a89ebfe9c8f03c04de9b345add4a52f15bd026b63c8fb1501b'
    },
    {
      address: '0xEB014f8c8B418Db6b45774c326A0E64C78914dC0',
      privateKey: hexToBytes('0xbe6383dad004f233317e46ddb46ad31b16064d14447a95cc1d8c8d4bc61c3728'),
      data: 'Some data!%$$%&@*',
      signature:
        '0x05252412b097c5d080c994d1ea12abcee6f1cae23feb225517a0b691a66e12866b3f54292f9cfef98f390670b4d010fc4af7fcd46e41d72870602c117b14921c1c'
    },
    {
      address: '0xEB014f8c8B418Db6b45774c326A0E64C78914dC0',
      privateKey: hexToBytes('0xbe6383dad004f233317e46ddb46ad31b16064d14447a95cc1d8c8d4bc61c3728'),
      data: hexToBytes('0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
      signature:
        '0xddd493679d80c9c74e0e5abd256a496dfb31b51cd39ea2c7c9e8a2a07de94a90257107a00d9cb631bacb85b208d66bfa7a80c639536b34884505eff352677dd01c'
    }
  ] as const

  tests.forEach((test, ix) => {
    describe(`when signing and recovering test vector ${ix}`, () => {
      it('should produce the expected signature', () => {
        const signature = ethSign(test.privateKey, test.data)
        expect(signature).toEqual(test.signature)
      })

      it('should recover the correct address from the signature bytes', () => {
        const address = recoverAddressFromEthSignature(hexToBytes(test.signature), test.data)
        expect(address).toEqual(test.address)
      })

      it('should recover the correct address from a sign-then-recover round trip', () => {
        const sig = ethSign(test.privateKey, test.data)
        const address = recoverAddressFromEthSignature(sig, test.data)
        expect(address).toEqual(test.address)
      })
    })
  })

  describe('when initializing an auth chain with a mock signer', () => {
    let ephemeralIdentity: ReturnType<typeof createUnsafeIdentity>
    let realAccount: ReturnType<typeof createUnsafeIdentity>

    beforeEach(() => {
      ephemeralIdentity = createUnsafeIdentity()
      realAccount = createUnsafeIdentity()
    })

    it('should create a SIGNER link with the real account address', async () => {
      const chain = await Authenticator.initializeAuthChain(
        realAccount.address,
        ephemeralIdentity,
        10,
        async (message) => Authenticator.createSignature(realAccount, message)
      )
      expect(chain.authChain[0].type).toEqual('SIGNER')
      expect(chain.authChain[0].payload).toEqual(realAccount.address)
    })

    it('should create an ECDSA_EPHEMERAL link signed by the real account', async () => {
      const chain = await Authenticator.initializeAuthChain(
        realAccount.address,
        ephemeralIdentity,
        10,
        async (message) => Authenticator.createSignature(realAccount, message)
      )
      expect(chain.authChain[1].type).toEqual('ECDSA_EPHEMERAL')
      const recovered = recoverAddressFromEthSignature(chain.authChain[1].signature ?? '', chain.authChain[1].payload)
      expect(recovered).toEqual(realAccount.address)
    })
  })
})
