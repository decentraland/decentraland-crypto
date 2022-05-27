import * as EthCrypto from 'eth-crypto'
import { HTTPProvider } from 'eth-connect'
import 'isomorphic-fetch'

import {
  Authenticator,
  getEphemeralSignatureType,
  ECDSA_EIP_1654_EPHEMERAL_VALIDATOR,
  ECDSA_PERSONAL_EPHEMERAL_VALIDATOR
} from '../src/Authenticator'
import { AuthLinkType, AuthChain } from '../src/types'
import { moveMinutes } from '../src/helper/utils'

const PERSONAL_SIGNATURE =
  '0x49c5d57fc804e6a06f83ee8d499aec293a84328766864d96349db599ef9ebacc072892ec1f3e2777bdc8265b53d8b84edd646bdc711dd5290c18adcc5de4a2831b'
const CONTRACT_WALLET_SIGNATURE =
  '0xea441043d745d130e8a2560d7c5e8a9e9d9dae8530015f3bd90eaea5040c81ca419a2a2f29c48439985a58fa7aa7b4bb06e4111a054bfa8095b65b2f3c1ecae41ccdb959d51dda310325d0294cf6a9f0691d08abfb9978d4f2e7e504042b663ef2123712bf864ef161cf579c4b3e3faf3767865a5bb4535d9fc2b9f6664e403d241b'

describe('Decentraland Crypto', function() {
  jest.setTimeout(999999)
  describe('Get signature type', function() {
    it('should return the correct signature type', function() {
      expect(getEphemeralSignatureType(PERSONAL_SIGNATURE)).toEqual(
        AuthLinkType.ECDSA_PERSONAL_EPHEMERAL
      )

      expect(getEphemeralSignatureType(CONTRACT_WALLET_SIGNATURE)).toEqual(
        AuthLinkType.ECDSA_EIP_1654_EPHEMERAL
      )
    })
  })

  describe('Validate Signature', function() {
    it('should validate request :: personal sign', async function() {
      const identity = EthCrypto.createIdentity()
      const ephemeral = EthCrypto.createIdentity()
      const chain = Authenticator.createAuthChain(
        identity,
        ephemeral,
        5,
        'message'
      )
      const result = await Authenticator.validateSignature(
        'message',
        chain,
        new HTTPProvider('https://rpc.decentraland.org/mainnet')
      )

      expect(result).toEqual({ ok: true, message: undefined })
    })

    it('should validate request :: EIP 1654', async function() {
      jest.useFakeTimers().setSystemTime(0)
      const chain: AuthChain = [
        {
          type: AuthLinkType.SIGNER,
          payload: '0x3b21028719a4aca7ebee35b0157a6f1b0cf0d0c5',
          signature: ''
        },
        {
          type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
          payload:
            'Decentraland Login\nEphemeral address: 0x69fBdE5Da06eb76e8E7F6Fd2FEEd968F28b951a5\nExpiration: Tue Aug 06 7112 10:14:51 GMT-0300 (Argentina Standard Time)',
          signature:
            '0x03524dbe44d19aacc8162b4d5d17820c370872de7bfd25d1add2b842adb1de546b454fc973b6d215883c30f4c21774ae71683869317d773f27e6bfaa9a2a05101b36946c3444914bb93f17a29d88e2449bcafdb6478b4835102c522197fa6f63d13ce5ab1d5c11c95db0c210fb4380995dff672392e5569c86d7c6bb2a44c53a151c'
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
          payload: 'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
          signature:
            '0xd73b0315dd39080d9b6d1a613a56732a75d68d2cef2a38f3b7be12bdab3c59830c92c6bdf394dcb47ba1aa736e0338cf9112c9eee59dbe4109b8af6a993b12d71b'
        }
      ]

      const result = await Authenticator.validateSignature(
        'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
        chain,
        new HTTPProvider('https://rpc.decentraland.org/mainnet')
      )

      // Restore
      jest.useRealTimers()

      expect(result.ok).toEqual(true)
    })

    it('should validate request for an specific time :: EIP 1654', async function() {
      const chain: AuthChain = [
        {
          type: AuthLinkType.SIGNER,
          payload: '0x49D4480d1F82E642Fc5697A8ba42f1065cA0f31E',
          signature: ''
        },
        {
          type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
          payload:
            'Decentraland Login\nEphemeral address: 0x390Be489333A19608634B1fBd5434129786Ab1E1\nExpiration: 2020-02-21T11:37:38.686Z',
          signature:
            '0xbef29294f9e5ad138824d7dc78baf4c5ca2d15d5fe39ea8c80c29463d3a8dafc362a61f5cd34cbe7a2a68d1ca6062331b9b2ff01db31c1c95bdc42454ce7c6da1cdca27f6f34993fe3e31273dfcd4070c005a7448e8971c259441b206d6b0dab4f11c14a31de529fa59f2a326321f5100fbb0ace11250457e3f3f731367529204c1c'
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
          payload: 'QmXXYddXKWVGFMEgtGoPMCu6dbJ35TyYR4AkDHw9mUc1s1',
          signature:
            '0xd125495751f34c973b86a76ea243fba5aa91bd3eb9eb38a45112c83dd0a5efd633dade4a71a6a3a48dc20224684b86621f2ac0c3f1b803af2963bec5fa407f3b1b'
        }
      ]

      const result = await Authenticator.validateSignature(
        'QmXXYddXKWVGFMEgtGoPMCu6dbJ35TyYR4AkDHw9mUc1s1',
        chain,
        new HTTPProvider(
          'https://mainnet.infura.io/v3/2c902c2e3b8947d3b34bba7ca48635fc'
        ),
        1581680328512 // time when deployed
      )

      expect(result.ok).toEqual(true)
    })

    it('should validate a signature :: EIP 1654', async function() {
      // Date.now() should return 0 to avoid expiration
      jest.useFakeTimers().setSystemTime(0)
      const ephemeral = '0x1F19d3EC0BE294f913967364c1D5B416e6A74555'
      const authority = '0x3B21028719a4ACa7EBee35B0157a6F1B0cF0d0c5'
      const authLink = {
        type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
        payload: `Decentraland Login\nEphemeral address: ${ephemeral}\nExpiration: Tue Jan 21 2020 16:34:32 GMT+0000 (Coordinated Universal Time)`,
        signature: CONTRACT_WALLET_SIGNATURE
      }

      const result = await ECDSA_EIP_1654_EPHEMERAL_VALIDATOR(
        authority,
        authLink,
        {
          provider: new HTTPProvider('https://rpc.decentraland.org/mainnet'),
          dateToValidateExpirationInMillis: Date.now()
        }
      )

      // Restore
      jest.useRealTimers()

      expect(result.nextAuthority).toEqual(ephemeral)
    })

    it('should validate simple signatures :: personal sign', async function() {
      const chain = Authenticator.createSimpleAuthChain(
        'QmWyFNeHbxXaPtUnzKvDZPpKSa4d5anZEZEFJ8TC1WgcfU',
        '0xeC6E6c0841a2bA474E92Bf42BaF76bFe80e8657C',
        '0xaaafb0368c13c42e401e71162cb55a062b3b0a5389e0740e7dc34e623b12f0fd65e2fadac51ab5f0de8f69b1311f23f1f218753e8a957043a2a789ba721141f91c'
      )

      const result = await Authenticator.validateSignature(
        'QmWyFNeHbxXaPtUnzKvDZPpKSa4d5anZEZEFJ8TC1WgcfU',
        chain,
        new HTTPProvider(
          'https://mainnet.infura.io/v3/2c902c2e3b8947d3b34bba7ca48635fc'
        )
      )

      expect(result.ok).toEqual(true)
    })

    it('should validate simple signatures :: EIP 1654', async function() {
      const chain = Authenticator.createSimpleAuthChain(
        'QmNUd7Cyoo9CREGsACkvBrQSb3KjhWX379FVsdjTCGsTAz',
        '0x6b7d7e82c984a0F4489c722fd11906F017f57704',
        '0x7fba0fbe75d0b28a224ec49ad99f6025f9055880db9ed1a35bc527a372c54ebe2461406aa07097bc47017da4319e19e517c49952697f074bcdc702f36afa72b01c759138c6ca4675367458884eb9b820c51af60a79efe1904ebcf2c1950fc7a2c02f3595a82ea1cc9d67a680c2f9b34df6abf5b344e857773dfe4210c6f85405151b'
      )

      const result = await Authenticator.validateSignature(
        'QmNUd7Cyoo9CREGsACkvBrQSb3KjhWX379FVsdjTCGsTAz',
        chain,
        new HTTPProvider(
          'https://mainnet.infura.io/v3/2c902c2e3b8947d3b34bba7ca48635fc'
        ),
        1584541612291
      )

      expect(result.ok).toEqual(true)
    })

    it('should support /r :: EIP 1654', async function() {
      // Date.now() should return 0 to avoid expiration
      jest.useFakeTimers().setSystemTime(0)
      const ephemeral = '0x1F19d3EC0BE294f913967364c1D5B416e6A74555'
      const authority = '0x3B21028719a4ACa7EBee35B0157a6F1B0cF0d0c5'
      const authLink = {
        type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
        payload: `Decentraland Login\r\nEphemeral address: ${ephemeral}\r\nExpiration: Tue Jan 21 2020 16:34:32 GMT+0000 (Coordinated Universal Time)`,
        signature: CONTRACT_WALLET_SIGNATURE
      }

      const result = await ECDSA_EIP_1654_EPHEMERAL_VALIDATOR(
        authority,
        authLink,
        {
          provider: new HTTPProvider('https://rpc.decentraland.org/mainnet'),
          dateToValidateExpirationInMillis: Date.now()
        }
      )

      // Restore
      jest.useRealTimers()

      expect(result.nextAuthority).toEqual(ephemeral)
    })

    it('should support /r :: personal sign', async function() {
      // Date.now() should return 0 to avoid expiration
      jest.useFakeTimers().setSystemTime(0)
      const chain: AuthChain = [
        {
          type: AuthLinkType.SIGNER,
          payload: '0xf053efea93c7aeb3251a3c5f422864dddab354a9',
          signature: ''
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_EPHEMERAL,
          payload:
            'Decentraland Login\r\nEphemeral address: 0xd59c1F11bF5BDd5ae7305FA36D66089343f1C8FC\r\nExpiration: 2020-03-15T00:45:29.278Z',
          signature:
            '0x0fc56c45d201d17339aa84b39469d08b01e71bf992b3b709ae6babca7ab51fa63ef05436551effdd65981cf62624876b3e7a745e01738b6e17c8b43890feaaa81c'
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
          payload: 'QmUe3LmUJ4NACAKJzwQhn5rZVpLLSyBLWBmTSzJYEesDNx',
          signature:
            '0xe752475faa184dada05f10fa56c28b4a2d0391b5b92efe6af5ff77ca331594eb0102b23d74816afbb8645eaeff71af20b9eb92c621da0ecc55109cedd720f65d1c'
        }
      ]

      const result = await Authenticator.validateSignature(
        'QmUe3LmUJ4NACAKJzwQhn5rZVpLLSyBLWBmTSzJYEesDNx',
        chain,
        new HTTPProvider('https://rpc.decentraland.org/mainnet')
      )

      // Restore
      jest.useRealTimers()

      expect(result.ok).toEqual(true)
    })

    it('supports signature with old versions', async function() {
      // Date.now() should return 0 to avoid expiration
      jest.useFakeTimers().setSystemTime(0)
      const chain: AuthChain = [
        {
          type: AuthLinkType.SIGNER,
          payload: '0xbcac4dafb7e215f2f6cb3312af6d5e4f9d9e7eda',
          signature: ''
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_EPHEMERAL,
          payload:
            'Decentraland Login\nEphemeral address: 0x08bdc29abFB11C6a1BB201b7EF3c41273aEA23EA\nExpiration: 2020-03-16T20:38:09.875Z',
          signature:
            '0x3a66ecdb318c1b6a72aaf991418804044ad30a2015d0846f52240e7bdb533853736e9308c619593a7ed20ecf9361b988fbf9e4957a12f062276eda2a37b7dfda01'
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
          payload: 'QmbGrShBQs4XiuoTNX6znAvXNdqtub8DtXyaxdSTZbHLCu',
          signature:
            '0x25ce09ec7f3e77040e886a2ad441467877a0c285b31bdde5c2f8517dc9b802454720b34c456eb592ebbcb14cc908d445b2e1bc1695469b2ba80a4882676f71921c'
        }
      ]

      const result = await Authenticator.validateSignature(
        'QmbGrShBQs4XiuoTNX6znAvXNdqtub8DtXyaxdSTZbHLCu',
        chain,
        new HTTPProvider('https://rpc.decentraland.org/mainnet')
      )

      // Restore
      jest.useRealTimers()

      expect(result.ok).toEqual(true)
    })

    it('reverts if signature was expired', async function() {
      const authority = '0x1f19d3ec0be294f913967364c1d5b416e6a74555'
      const authLink = {
        type: AuthLinkType.ECDSA_PERSONAL_EPHEMERAL,
        payload:
          'Decentraland Login\nEphemeral address: 0x1F19d3EC0BE294f913967364c1D5B416e6A74555\nExpiration: 2020-01-15T00:45:29.278Z',
        signature: PERSONAL_SIGNATURE
      }
      try {
        await ECDSA_PERSONAL_EPHEMERAL_VALIDATOR(authority, authLink, {
          provider: new HTTPProvider('https://rpc.decentraland.org/mainnet'),
          dateToValidateExpirationInMillis: Date.now()
        })
      } catch (e) {
        expect(e.message).toMatch('Ephemeral key expired.')
      }
    })

    it('expiration check can be configured', async function() {
      const identity = EthCrypto.createIdentity()
      const ephemeral = EthCrypto.createIdentity()
      const chain = Authenticator.createAuthChain(
        identity,
        ephemeral,
        -5,
        'message'
      )

      // Since the ephemeral expired 5 minutes ago, validation should fail
      let result = await Authenticator.validateSignature(
        'message',
        chain,
        new HTTPProvider('https://rpc.decentraland.org/mainnet')
      )

      expect(result.message).toMatch(
        'ERROR. Link type: ECDSA_EPHEMERAL. Ephemeral key expired.'
      )

      // Since we are checking the ephemeral against 10 minutes ago, validation should pass
      result = await Authenticator.validateSignature(
        'message',
        chain,
        new HTTPProvider('https://rpc.decentraland.org/mainnet'),
        moveMinutes(-10).getTime()
      )

      expect(result.ok).toEqual(true)
    })

    it('should validate authChain', async function() {
      jest.useFakeTimers().setSystemTime(0)
      const provider = new HTTPProvider('https://rpc.decentraland.org/mainnet')
      let chain: AuthChain = [
        {
          type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
          payload: '0xFAKEAddress',
          signature: ''
        },
        {
          type: AuthLinkType.SIGNER,
          payload: '0x3b21028719a4aca7ebee35b0157a6f1b0cf0d0c5',
          signature: ''
        },
        {
          type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
          payload:
            'Decentraland Login\nEphemeral address: 0x69fBdE5Da06eb76e8E7F6Fd2FEEd968F28b951a5\nExpiration: Tue Aug 06 7112 10:14:51 GMT-0300 (Argentina Standard Time)',
          signature:
            '0x03524dbe44d19aacc8162b4d5d17820c370872de7bfd25d1add2b842adb1de546b454fc973b6d215883c30f4c21774ae71683869317d773f27e6bfaa9a2a05101b36946c3444914bb93f17a29d88e2449bcafdb6478b4835102c522197fa6f63d13ce5ab1d5c11c95db0c210fb4380995dff672392e5569c86d7c6bb2a44c53a151c'
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
          payload: 'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
          signature:
            '0xd73b0315dd39080d9b6d1a613a56732a75d68d2cef2a38f3b7be12bdab3c59830c92c6bdf394dcb47ba1aa736e0338cf9112c9eee59dbe4109b8af6a993b12d71b'
        }
      ]

      let result = await Authenticator.validateSignature(
        'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
        chain,
        provider
      )

      expect(result.message).toMatch('ERROR: Malformed authChain')
      expect(Authenticator.isValidAuthChain(chain)).toEqual(false)

      chain = [
        {
          type: AuthLinkType.SIGNER,
          payload: '0x3b21028719a4aca7ebee35b0157a6f1b0cf0d0c5',
          signature: ''
        },
        {
          type: AuthLinkType.SIGNER,
          payload: '0xFAKEAddress',
          signature: ''
        },
        {
          type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
          payload:
            'Decentraland Login\nEphemeral address: 0x69fBdE5Da06eb76e8E7F6Fd2FEEd968F28b951a5\nExpiration: Tue Aug 06 7112 10:14:51 GMT-0300 (Argentina Standard Time)',
          signature:
            '0x03524dbe44d19aacc8162b4d5d17820c370872de7bfd25d1add2b842adb1de546b454fc973b6d215883c30f4c21774ae71683869317d773f27e6bfaa9a2a05101b36946c3444914bb93f17a29d88e2449bcafdb6478b4835102c522197fa6f63d13ce5ab1d5c11c95db0c210fb4380995dff672392e5569c86d7c6bb2a44c53a151c'
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
          payload: 'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
          signature:
            '0xd73b0315dd39080d9b6d1a613a56732a75d68d2cef2a38f3b7be12bdab3c59830c92c6bdf394dcb47ba1aa736e0338cf9112c9eee59dbe4109b8af6a993b12d71b'
        }
      ]

      result = await Authenticator.validateSignature(
        'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
        chain,
        provider
      )
      expect(Authenticator.isValidAuthChain(chain)).toEqual(false)

      expect(result.message).toMatch('ERROR: Malformed authChain')

      chain = [
        {
          type: AuthLinkType.SIGNER,
          payload: '0xFAKEAddress',
          signature: ''
        },
        {
          type: AuthLinkType.SIGNER,
          payload: '0x3b21028719a4aca7ebee35b0157a6f1b0cf0d0c5',
          signature: ''
        },
        {
          type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
          payload:
            'Decentraland Login\nEphemeral address: 0x69fBdE5Da06eb76e8E7F6Fd2FEEd968F28b951a5\nExpiration: Tue Aug 06 7112 10:14:51 GMT-0300 (Argentina Standard Time)',
          signature:
            '0x03524dbe44d19aacc8162b4d5d17820c370872de7bfd25d1add2b842adb1de546b454fc973b6d215883c30f4c21774ae71683869317d773f27e6bfaa9a2a05101b36946c3444914bb93f17a29d88e2449bcafdb6478b4835102c522197fa6f63d13ce5ab1d5c11c95db0c210fb4380995dff672392e5569c86d7c6bb2a44c53a151c'
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
          payload: 'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
          signature:
            '0xd73b0315dd39080d9b6d1a613a56732a75d68d2cef2a38f3b7be12bdab3c59830c92c6bdf394dcb47ba1aa736e0338cf9112c9eee59dbe4109b8af6a993b12d71b'
        }
      ]

      result = await Authenticator.validateSignature(
        'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
        chain,
        provider
      )
      expect(result.message).toMatch('ERROR: Malformed authChain')
      expect(Authenticator.isValidAuthChain(chain)).toEqual(false)

      // Restore
      jest.useRealTimers()

      chain = [
        {
          type: AuthLinkType.SIGNER,
          payload: '0x3b21028719a4aca7ebee35b0157a6f1b0cf0d0c5',
          signature: ''
        },
        {
          type: AuthLinkType.ECDSA_EIP_1654_EPHEMERAL,
          payload:
            'Decentraland Login\nEphemeral address: 0x69fBdE5Da06eb76e8E7F6Fd2FEEd968F28b951a5\nExpiration: Tue Aug 06 7112 10:14:51 GMT-0300 (Argentina Standard Time)',
          signature:
            '0x03524dbe44d19aacc8162b4d5d17820c370872de7bfd25d1add2b842adb1de546b454fc973b6d215883c30f4c21774ae71683869317d773f27e6bfaa9a2a05101b36946c3444914bb93f17a29d88e2449bcafdb6478b4835102c522197fa6f63d13ce5ab1d5c11c95db0c210fb4380995dff672392e5569c86d7c6bb2a44c53a151c'
        },
        {
          type: AuthLinkType.ECDSA_PERSONAL_SIGNED_ENTITY,
          payload: 'QmUsqJaHc5HQaBrojhBdjF4fr5MQc6CqhwZjqwhVRftNAo',
          signature:
            '0xd73b0315dd39080d9b6d1a613a56732a75d68d2cef2a38f3b7be12bdab3c59830c92c6bdf394dcb47ba1aa736e0338cf9112c9eee59dbe4109b8af6a993b12d71b'
        }
      ]
      expect(Authenticator.isValidAuthChain(chain)).toEqual(true)
    })
  })
})
