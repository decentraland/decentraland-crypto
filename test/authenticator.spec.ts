import * as chai from 'chai'
import * as chaiAsPromised from 'chai-as-promised'
import * as EthCrypto from 'eth-crypto'

import { Authenticator } from '../src/Authenticator'

chai.use(chaiAsPromised)
const expect = chai.expect

describe('Decentraland Crypto', function () {
  this.timeout(999999)

  describe('Validate Signature', function () {
    it('should validate signtuare', async function () {
      const identity = EthCrypto.createIdentity()
      const ephemeral = EthCrypto.createIdentity()
      const chain = Authenticator.createAuthChain(
        identity,
        ephemeral,
        5,
        'message'
      )
      const isValid = await Authenticator.validateSignature('message', chain)

      expect(isValid, true)
    })
  })
})
