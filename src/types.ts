export type Signature = string
export type EthAddress = string

export type IdentityType = {
  privateKey: string
  publicKey: string
  address: string
}

export type AuthChain = AuthLink[]

export type AuthLink = {
  type: AuthLinkType
  payload: string
  signature: Signature
}

export enum AuthLinkType {
  SIGNER = 'SIGNER',
  ECDSA_PERSONAL_EPHEMERAL = 'ECDSA_EPHEMERAL',
  ECDSA_PERSONAL_SIGNED_ENTITY = 'ECDSA_SIGNED_ENTITY',
  // https://github.com/ethereum/EIPs/issues/1654
  ECDSA_EIP_1654_EPHEMERAL = 'ECDSA_EIP_1654_EPHEMERAL',
  ECDSA_EIP_1654_SIGNED_ENTITY = 'ECDSA_EIP_1654_SIGNED_ENTITY'
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
