require('@nomicfoundation/hardhat-ethers')
require('@nomicfoundation/hardhat-verify')

// Deployer key comes from the environment; never commit it.
const PK = process.env.DEPLOYER_PRIVATE_KEY

/** @type {import('hardhat/config').HardhatUserConfig} */
module.exports = {
  solidity: {
    version: '0.8.28',
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  mocha: { timeout: 600000 }, // fork tests pull state from a public RPC
  networks: {
    hardhat: {},
    base: {
      url: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
      chainId: 8453,
      accounts: PK ? [PK] : [],
    },
  },
  // Sourcify verification for Base (no API key needed)
  sourcify: { enabled: true },
}
