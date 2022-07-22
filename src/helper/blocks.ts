import RequestManager, { BlockIdentifier, toBigNumber } from 'eth-connect'

export type SavedBlock = {
  number: number
  timestamp: number
}

export type BlockResponse = {
  block: number
  timestamp: number
}

export default class Blocks {
  checkedBlocks: { [key: string]: number[] }
  saveBlocks: boolean
  savedBlocks: { [key: string]: SavedBlock }
  requests: number
  blockTime?: number
  firstTimestamp?: number

  constructor(private requestManager: RequestManager, save: boolean = true) {
    this.checkedBlocks = {}
    this.saveBlocks = save
    if (save) {
      this.savedBlocks = {}
    }
    this.requests = 0
  }

  async fillBlockTime() {
    const latest = await this.getBlockWrapper('latest')
    const first = await this.getBlockWrapper(1)

    this.blockTime = (latest.timestamp - first.timestamp) / Number(latest.number) - 1
    this.firstTimestamp = first.timestamp
  }

  async getDate(date: number, after: boolean = true): Promise<BlockResponse> {
    const dateInSeconds = date / 1000
    const now = Date.now() / 1000

    if (typeof this.firstTimestamp === 'undefined' || typeof this.blockTime === 'undefined') {
      await this.fillBlockTime()
    }

    if (dateInSeconds < this.firstTimestamp!) {
      return {
        block: 1,
        timestamp: dateInSeconds
      }
    }

    if (dateInSeconds >= now || dateInSeconds > this.savedBlocks['latest'].timestamp) {
      return {
        block: toBigNumber(await this.requestManager.eth_blockNumber()).toNumber(),
        timestamp: dateInSeconds
      }
    }

    this.checkedBlocks[dateInSeconds] = []

    const predictedBlock = await this.getBlockWrapper(
      Math.ceil((dateInSeconds - this.firstTimestamp! / this.blockTime!) / 1000)
    )

    return {
      block: await this.findBetter(dateInSeconds, predictedBlock, after),
      timestamp: dateInSeconds
    }
  }

  async findBetter(date: number, predictedBlock: SavedBlock, after: boolean, blockTime: number = this.blockTime!) {
    if (await this.isBetterBlock(date, predictedBlock, after)) {
      return predictedBlock.number
    }

    const difference = date - predictedBlock.timestamp
    let skip = Math.ceil(difference / blockTime)

    if (skip === 0) {
      skip = difference < 0 ? -1 : 1
    }

    const nextPredictedBlock = await this.getBlockWrapper(this.getNextBlock(date, predictedBlock.number, skip))

    blockTime = Math.abs(
      (predictedBlock.timestamp - nextPredictedBlock.timestamp) / (predictedBlock.number - nextPredictedBlock.number)
    )

    return this.findBetter(date, nextPredictedBlock, after, blockTime)
  }

  async isBetterBlock(date: number, predictedBlock: SavedBlock, after: boolean) {
    const blockTime = predictedBlock.timestamp

    if (after) {
      if (blockTime < date) {
        return false
      }

      const previousBlock = await this.getBlockWrapper(predictedBlock.number - 1)

      if (blockTime >= date && previousBlock.timestamp < date) {
        return true
      }
    } else {
      if (blockTime >= date) {
        return false
      }

      const nextBlock = await this.getBlockWrapper(predictedBlock.number + 1)
      if (blockTime < date && nextBlock.timestamp >= date) {
        return true
      }
    }

    return false
  }

  getNextBlock(date: number, currentBlock: number, skip: number) {
    const nextBlock = currentBlock + skip

    if (this.checkedBlocks[date].includes(nextBlock)) {
      return this.getNextBlock(date, currentBlock, skip < 0 ? ++skip : --skip)
    }

    this.checkedBlocks[date].push(nextBlock)

    return nextBlock
  }

  async getBlockWrapper(block: BlockIdentifier): Promise<SavedBlock> {
    if (!this.saveBlocks) {
      const fetchedBlock = await this.requestManager.eth_getBlockByNumber(block, false)
      return {
        number: toBigNumber(fetchedBlock.number).toNumber(),
        timestamp: toBigNumber(fetchedBlock.timestamp).toNumber()
      }
    }

    if (this.savedBlocks[block.toString()]) {
      return this.savedBlocks[block]
    }

    if (typeof block === 'number' && this.savedBlocks['latest'] && this.savedBlocks['latest'].number <= block) {
      return this.savedBlocks['latest']
    }

    const { timestamp } = await this.requestManager.eth_getBlockByNumber(block, false)

    this.savedBlocks[block.toString()] = {
      number: toBigNumber(block === 'latest' ? await this.requestManager.eth_blockNumber() : block).toNumber(),
      timestamp: toBigNumber(timestamp).toNumber()
    }

    this.requests++

    return this.savedBlocks[block.toString()]
  }
}
