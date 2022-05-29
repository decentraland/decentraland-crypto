const { Suite } = require( "benchmark")
const { keccak256 } = require( "ethereum-cryptography/keccak")
const { sha3 } = require( "eth-connect")

const suite = new Suite()

let memory = process.memoryUsage()

function printMemory() {
  const newMemory = process.memoryUsage()

  function toMb(num) {
    return (num / 1024 / 1024).toFixed(2) + "MB"
  }

  console.log(`
  heapTotal: ${toMb(newMemory.heapTotal - memory.heapTotal)}
   heapUsed: ${toMb(newMemory.heapUsed - memory.heapUsed)}
        rss: ${toMb(newMemory.rss - memory.rss)}
arrayBuffers: ${toMb((newMemory).arrayBuffers - (memory ).arrayBuffers)}
  `)

  memory = newMemory
}

const empty = new Uint8Array(10000).fill(1)

suite
.add("ethereum-cryptography/keccak", {
  fn() {
      keccak256(empty)
  },
})
.add("eth-connect/sha3", {
  fn() {
      sha3(empty)
  }
})
.add("ethereum-cryptography/keccak 2", {
  fn() {
      keccak256(empty)
  },
})
.add("eth-connect/sha3 2", {
  fn() {
      sha3(empty)
  }
})
.on("cycle", function (event) {
  console.log(String(event.target))

  console.log("Relative mean error: ±" + event.target.stats.rme.toFixed(2) + "%")
  if (event.target.stats.rme > 5 && !event.target.name.includes("PREWARM")) {
    console.log("❌  FAILED, should be less than 5%")
    process.exitCode = 1
  }

  printMemory()
})
.on("complete", function (event) {
  printMemory()
})
.run({ async: true })

/**
ethereum-cryptography/keccak x 2,565 ops/sec ±0.11% (100 runs sampled)
Relative mean error: ±0.11%

   heapTotal: 18.45MB
    heapUsed: 7.62MB
         rss: 23.86MB
arrayBuffers: -0.02MB

eth-connect/sha3 x 8,806 ops/sec ±0.27% (101 runs sampled)
Relative mean error: ±0.27%

   heapTotal: -18.31MB
    heapUsed: -7.17MB
         rss: -15.72MB
arrayBuffers: -0.05MB
*/