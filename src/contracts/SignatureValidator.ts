import RequestManager, { AbiItem, Contract, ContractFactory } from 'eth-connect'

type SignatureValidator = Contract & {
  isValidSignature(hash: Uint8Array, signature: Uint8Array, block?: string | number): Promise<Uint8Array>
}

export async function SignatureValidator(requestManager: RequestManager, address: string): Promise<SignatureValidator> {
  const abi: AbiItem[] = [
    {
      constant: true,
      inputs: [
        {
          name: 'hash',
          type: 'bytes32'
        },
        {
          name: '_signature',
          type: 'bytes'
        }
      ],
      name: 'isValidSignature',
      outputs: [
        {
          name: 'magicValue',
          type: 'bytes4'
        }
      ],
      payable: false,
      stateMutability: 'view',
      type: 'function'
    }
  ]

  return (await new ContractFactory(requestManager, abi).at(address)) as any
}
