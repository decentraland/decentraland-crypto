import { Eth } from 'web3x/eth'
import { EthereumProvider } from 'web3x/providers'
import { BlockHeaderResponse } from 'web3x/formatters'

export type SavedBlock = {
  number: number
  timestamp: number
}

export type BlockResponse = {
  block: number
  timestamp: number
}

export default class Blocks {
  eth: Eth
  checkedBlocks: { [key: string]: number[] }
  saveBlocks: boolean
  savedBlocks: { [key: string]: SavedBlock }
  requests: number
  blockTime?: number
  firstTimestamp?: number

  constructor(eth: EthereumProvider, save: boolean = true) {
    this.eth = new Eth(eth)
    this.checkedBlocks = {}
    this.saveBlocks = save
    if (save) {
      this.savedBlocks = {}
    }
    this.requests = 0
  }

  async fillBlockTime() {
    let latest = await this.getBlockWrapper('latest')
    let first = await this.getBlockWrapper(1)

    this.blockTime =
      (latest.timestamp - first.timestamp) / Number(latest.number) - 1
    this.firstTimestamp = first.timestamp
  }

  async getDate(date: number, after: boolean = true): Promise<BlockResponse> {
    const dateInSeconds = date / 1000
    const now = Date.now() / 1000

    if (
      typeof this.firstTimestamp === 'undefined' ||
      typeof this.blockTime === 'undefined'
    ) {
      await this.fillBlockTime()
    }

    if (dateInSeconds < this.firstTimestamp!) {
      return {
        block: 1,
        timestamp: dateInSeconds
      }
    }

    if (
      dateInSeconds >= now ||
      dateInSeconds > this.savedBlocks['latest'].timestamp
    ) {
      return {
        block: await this.eth.getBlockNumber(),
        timestamp: dateInSeconds
      }
    }

    this.checkedBlocks[dateInSeconds] = []

    let predictedBlock = await this.getBlockWrapper(
      Math.ceil((dateInSeconds - this.firstTimestamp! / this.blockTime!) / 1000)
    )

    return {
      block: await this.findBetter(dateInSeconds, predictedBlock, after),
      timestamp: dateInSeconds
    }
  }

  async findBetter(
    date: number,
    predictedBlock: SavedBlock,
    after: boolean,
    blockTime: number = this.blockTime!
  ) {
    if (await this.isBetterBlock(date, predictedBlock, after)) {
      return predictedBlock.number
    }

    const difference = date - predictedBlock.timestamp
    let skip = Math.ceil(difference / blockTime)

    if (skip === 0) {
      skip = difference < 0 ? -1 : 1
    }

    const nextPredictedBlock = await this.getBlockWrapper(
      this.getNextBlock(date, predictedBlock.number, skip)
    )

    blockTime = Math.abs(
      (predictedBlock.timestamp - nextPredictedBlock.timestamp) /
      (predictedBlock.number - nextPredictedBlock.number)
    )

    return this.findBetter(date, nextPredictedBlock, after, blockTime)
  }

  async isBetterBlock(
    date: number,
    predictedBlock: SavedBlock,
    after: boolean
  ) {
    const blockTime = predictedBlock.timestamp

    if (after) {
      if (blockTime < date) {
        return false
      }

      let previousBlock = await this.getBlockWrapper(predictedBlock.number - 1)

      if (blockTime >= date && previousBlock.timestamp < date) {
        return true
      }
    } else {
      if (blockTime >= date) {
        return false
      }

      let nextBlock = await this.getBlockWrapper(predictedBlock.number + 1)
      if (blockTime < date && nextBlock.timestamp >= date) {
        return true
      }
    }

    return false
  }

  getNextBlock(date: number, currentBlock: number, skip: number) {
    let nextBlock = currentBlock + skip

    if (this.checkedBlocks[date].includes(nextBlock)) {
      return this.getNextBlock(date, currentBlock, skip < 0 ? ++skip : --skip)
    }

    this.checkedBlocks[date].push(nextBlock)

    return nextBlock
  }

  async getBlockWrapper(block: number | string): Promise<SavedBlock> {
    if (!this.saveBlocks) {
      const fetchedBlock: BlockHeaderResponse = await this.eth.getBlock(block)
      return {
        number: fetchedBlock.number!,
        timestamp: fetchedBlock.timestamp
      }
    }

    if (this.savedBlocks[block.toString()]) {
      return this.savedBlocks[block]
    }

    if (
      typeof block === 'number' &&
      this.savedBlocks['latest'] &&
      this.savedBlocks['latest'].number <= block
    ) {
      return this.savedBlocks['latest']
    }

    let { timestamp } = await this.eth.getBlock(block)

    this.savedBlocks[block.toString()] = {
      number:
        block === 'latest' ? await this.eth.getBlockNumber() : Number(block),
      timestamp
    }

    this.requests++

    return this.savedBlocks[block.toString()]
  }
}
