export type Signature = string
export type EthAddress = string

import { AuthChain, AuthLinkType, AuthLink } from '@dcl/schemas'
export { AuthChain, AuthLinkType, AuthLink }

export type IdentityType = {
  privateKey: string
  publicKey: string
  address: string
}

export type AuthIdentity = {
  ephemeralIdentity: IdentityType
  expiration: Date
  authChain: AuthChain
}

export type ValidationResult = {
  ok: boolean
  message?: string
}
