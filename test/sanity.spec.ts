import { getAddress, HTTPProvider } from 'eth-connect'
import fetch from 'node-fetch'
import { Authenticator } from '../src/Authenticator'
import { AuthLinkType, AuthChain } from '../src/types'
import { recoverAddressFromEthSignature } from '../src/crypto'

const mainnetProvider = new HTTPProvider(process.env.ETHEREUM_MAINNET_RPC || '', {
  fetch: fetch as any
})

describe('Sanity', function () {
  it('Should work with production example', async function () {
    jest.useFakeTimers().setSystemTime(0)
    const chain: AuthChain = [
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

    const result = await Authenticator.validateSignature(
      'QmfQtX7BrXzZx7UwupsqNwKGirSZUVBpjN5whujwcp9qyk',
      chain,
      mainnetProvider
    )

    // Restore
    jest.useRealTimers()

    expect(result).toEqual({ ok: true, message: undefined })
  })
})

describe('static-signatures', () => {
  const ephemeralIdentity = {
    privateKey: '0x8d11d14dd05b58fa150ec39ceab942dbff334af4dd4e87df4244106023d758ce',
    publicKey:
      'a1a8de183be2f189bdfacf83ca4262016840c590abee0b2048288c3b9090dae87538eda022d7c6f82a5ed617b7138db1a63ebe92f7b1afc6de032d6568525f13',
    address: '0x68560651BD91509EB22b90f6F748422A26CA3425'
  }
  const realAccount = {
    privateKey: '0x800cbd114eba965fcb41c252b920e916d2be8851496f21f24f1b4dcadf51688e',
    publicKey:
      'e9f386a334fb21ce11151a88b54f4aebaf0e7ab7b8ad7b3be9c503857b278c7a7f4ccb611c5edd046e07bf1d1969c966b28fa9bfb10bf7bfa239625968bcfc4f',
    address: '0x13FE90239bfda363eC33a849b716616958c04f0F'
  }

  it('tests createSignature', () => {
    const message = 'menduz'
    const sig = Authenticator.createSignature(realAccount, message)
    const addr = recoverAddressFromEthSignature(sig, message)
    expect(addr).toEqual(realAccount.address)
  })

  it('createAuthChain with mock signature', async () => {
    const chain = Authenticator.createAuthChain(realAccount, ephemeralIdentity, 10, 'test')
    expect(chain.length).toEqual(3)

    // validate first part
    expect(chain[0].type).toEqual('SIGNER')
    expect(chain[0].payload).toEqual(getAddress(realAccount.address))

    // second part, signed with real account
    {
      expect(chain[1].type).toEqual('ECDSA_EPHEMERAL')
      const recovered = recoverAddressFromEthSignature(chain[1].signature ?? '', chain[1].payload)
      expect(recovered).toEqual(getAddress(realAccount.address))
    }
    // third part, signed with ephemeral
    {
      expect(chain[2].type).toEqual('ECDSA_SIGNED_ENTITY')
      const recovered = recoverAddressFromEthSignature(chain[2].signature ?? '', chain[2].payload)
      expect(recovered).toEqual(getAddress(ephemeralIdentity.address))
    }
  })
})
