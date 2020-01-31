import { Address } from 'web3x/address';
import { TransactionReceipt } from 'web3x/formatters';
import { Contract, ContractOptions, TxCall } from 'web3x/contract';
import { Eth } from 'web3x/eth';
import abi from './SignatureValidatorAbi';
interface SignatureValidatorEvents { }
interface SignatureValidatorEventLogs { }
interface SignatureValidatorTxEventLogs { }
export interface SignatureValidatorTransactionReceipt
    extends TransactionReceipt<SignatureValidatorTxEventLogs> { }
interface SignatureValidatorMethods {
    isValidSignature(hash: string, _signature: string): TxCall<string>
}
export interface SignatureValidatorDefinition {
    methods: SignatureValidatorMethods
    events: SignatureValidatorEvents
    eventLogs: SignatureValidatorEventLogs
}
export class SignatureValidator extends Contract<SignatureValidatorDefinition> {
    constructor(eth: Eth, address?: Address, options?: ContractOptions) {
        super(eth, abi, address, options)
    }
}
export let SignatureValidatorAbi = abi
