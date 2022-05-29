module.exports = {
  globals: {
    "ts-jest": {
      tsconfig: "test/tsconfig.json",
    },
  },
  moduleFileExtensions: ["ts", "js"],
  transform: {
    "^.+\\.(ts|tsx)$": "ts-jest",
  },
  coveragePathIgnorePatterns: [
    "/node_modules/",
    "/test/",
    "/src/protocol/index_pb.js",
  ],
  coverageDirectory: "coverage",
  verbose: true,
  testMatch: ["**/*.spec.(ts)"],
  testEnvironment: "node",
}
