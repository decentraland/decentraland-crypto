import { ContractAbi} from 'web3x/contract';
export default new ContractAbi([
  {
    "constant": true,
    "inputs": [
      {
        "name": "hash",
        "type": "bytes32"
      },
      {
        "name": "_signature",
        "type": "bytes"
      }
    ],
    "name": "isValidSignature",
    "outputs": [
      {
        "name": "magicValue",
        "type": "bytes4"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  }
]);