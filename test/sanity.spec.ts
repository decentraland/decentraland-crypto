import * as chai from 'chai'
import * as chaiAsPromised from 'chai-as-promised'
import * as sinon from 'sinon'
import { HTTPProvider } from 'eth-connect'
import { Authenticator } from '../src/Authenticator'
import { AuthLinkType, AuthChain } from '../src/types'

chai.use(chaiAsPromised)
const expect = chai.expect

describe('Sanity', function() {
  this.timeout(999999)

  it('Should work with production example', async function() {
    const clock = sinon.useFakeTimers(0)
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
      new HTTPProvider(
        'https://mainnet.infura.io/v3/640777fe168f4b0091c93726b4f0463a'
      )
    )

    // Restore
    clock.restore()

    expect(result).to.deep.equal({ ok: true, message: undefined })
  })
})
