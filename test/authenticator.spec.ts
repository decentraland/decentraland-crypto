import * as chai from 'chai'
import * as chaiAsPromised from 'chai-as-promised'
import * as sinon from 'sinon'
import * as EthCrypto from 'eth-crypto'
import { HttpProvider } from 'web3x/providers'

import {
  Authenticator,
  getEphemeralSignatureType,
  ECDSA_EIP_1654_EPHEMERAL_VALIDATOR,
  ECDSA_PERSONAL_EPHEMERAL_VALIDATOR
} from '../src/Authenticator'
import { AuthLinkType } from '../src/types'

chai.use(chaiAsPromised)
const expect = chai.expect

const PERSONAL_SIGNATURE =
  '0x49c5d57fc804e6a06f83ee8d499aec293a84328766864d96349db599ef9ebacc072892ec1f3e2777bdc8265b53d8b84edd646bdc711dd5290c18adcc5de4a2831b'
const CONTRACT_WALLET_SIGNATURE =
  '0xea441043d745d130e8a2560d7c5e8a9e9d9dae8530015f3bd90eaea5040c81ca419a2a2f29c48439985a58fa7aa7b4bb06e4111a054bfa8095b65b2f3c1ecae41ccdb959d51dda310325d0294cf6a9f0691d08abfb9978d4f2e7e504042b663ef2123712bf864ef161cf579c4b3e3faf3767865a5bb4535d9fc2b9f6664e403d241b'

describe('Decentraland Crypto', function () {
  this.timeout(999999)

  describe('Get signature type', function () {
    it('should return the correct signature type', function () {
      expect(getEphemeralSignatureType(PERSONAL_SIGNATURE)).to.be.equal(
        AuthLinkType.ECDSA_PERSONAL_EPHEMERAL
      )

      expect(getEphemeralSignatureType(CONTRACT_WALLET_SIGNATURE)).to.be.equal(
        AuthLinkType.ECDSA_EIP_1654_EPHEMERAL
      )
    })
  })

  describe('Validate Signature', function () {
    it('should validate signtuare :: personal sign', async function () {
      const identity = EthCrypto.createIdentity()
      const ephemeral = EthCrypto.createIdentity()
      const chain = Authenticator.createAuthChain(
        identity,
        ephemeral,
        5,
        'message'
      )
      const isValid = await Authenticator.validateSignature(
        'message',
        chain,
        null
      )

      expect(isValid).to.be.equal(true)
    })

    it('should validate a signature :: EIP 1654', async function () {
      // Date.now() should return 0 to avoid expiration
      const clock = sinon.useFakeTimers(0)
      const ephemeral = '0x1F19d3EC0BE294f913967364c1D5B416e6A74555'
      const authority = '0x3B21028719a4ACa7EBee35B0157a6F1B0cF0d0c5'
      const authLink = {
        type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
        payload: `Decentraland Login\nEphemeral address: ${ephemeral}\nExpiration: Tue Jan 21 2020 16:34:32 GMT+0000 (Coordinated Universal Time)`,
        signature: CONTRACT_WALLET_SIGNATURE
      }

      const res = await ECDSA_EIP_1654_EPHEMERAL_VALIDATOR(
        authority,
        authLink,
        new HttpProvider(
          'https://mainnet.infura.io/v3/640777fe168f4b0091c93726b4f0463a'
        )
      )

      expect(res.nextAuthority).to.be.equal(ephemeral)
      // Restore
      clock.restore()
    })

    it('reverts if signature was expired', async function () {
      const authority = '0x1f19d3ec0be294f913967364c1d5b416e6a74555'
      const authLink = {
        type: AuthLinkType.ECDSA_PERSONAL_EPHEMERAL,
        payload:
          'Decentraland Login\nEphemeral address: 0x1F19d3EC0BE294f913967364c1D5B416e6A74555\nExpiration: Tue Jan 21 2020 16:34:32 GMT+0000 (Coordinated Universal Time)',
        signature: PERSONAL_SIGNATURE
      }

      const res = await ECDSA_PERSONAL_EPHEMERAL_VALIDATOR(
        authority,
        authLink,
        new HttpProvider(
          'https://mainnet.infura.io/v3/640777fe168f4b0091c93726b4f0463a'
        )
      )

      expect(res.error).to.be.equal(true)
    })
  })
})
