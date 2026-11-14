// Deploy MergeToPayEscrow (implementation + ERC1967 proxy) to Base. Simulates every send first.
//   DEPLOYER_PRIVATE_KEY=0x.. ESCROW_OWNER=0x.. VK_HASH=0x.. VERSION_HASH=0x.. DOMAIN_ID=2 ATTESTOR=0x.. \
//     npx hardhat run scripts/deploy-escrow.js --network base
// Then (Sourcify, no API key):
//   npx hardhat verify:sourcify --network base --address <impl>  --contract contracts/MergeToPayEscrow.sol:MergeToPayEscrow
//   npx hardhat verify:sourcify --network base --address <proxy> --contract @openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy
const hre = require('hardhat')

const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' // Base USDC (Circle)
const ZKV = '0xCb47A3C3B9Eb2E549a3F2EA4729De28CafbB2b69'  // zkVerify aggregation proxy on Base

function env(name, fallback) {
  const v = process.env[name] ?? fallback
  if (v === undefined || v === '') throw new Error(`set ${name}`)
  return v
}

async function main() {
  const { ethers } = hre
  const net = await ethers.provider.getNetwork()
  if (net.chainId !== 8453n) throw new Error(`expected Base (8453), got chainId ${net.chainId}; use --network base`)
  const [deployer] = await ethers.getSigners()
  if (!deployer) throw new Error('set DEPLOYER_PRIVATE_KEY in the environment')

  const owner = ethers.getAddress(env('ESCROW_OWNER', deployer.address))
  const vkHash = env('VK_HASH')
  const versionHash = env('VERSION_HASH')
  const domainId = BigInt(env('DOMAIN_ID'))
  const attestor = ethers.getAddress(env('ATTESTOR'))
  const bal = await ethers.provider.getBalance(deployer.address)
  console.log('network   :', hre.network.name, '(chainId 8453)')
  console.log('deployer  :', deployer.address, ethers.formatEther(bal), 'ETH')
  console.log('owner     :', owner)
  console.log('vkHash    :', vkHash)
  console.log('version   :', versionHash)
  console.log('domainId  :', domainId.toString())
  console.log('attestor  :', attestor)
  if (bal === 0n) throw new Error('deployer has 0 ETH on Base')

  // 1. implementation: simulate (eth_call + estimateGas), then send
  const Impl = await ethers.getContractFactory('MergeToPayEscrow')
  const implTx = await Impl.getDeployTransaction()
  await ethers.provider.call({ ...implTx, from: deployer.address })
  const implGas = await ethers.provider.estimateGas({ ...implTx, from: deployer.address })
  console.log('\nimpl simulate ok, gas', implGas.toString())
  const impl = await Impl.deploy()
  await impl.waitForDeployment()
  const implAddr = await impl.getAddress()
  console.log('implementation:', implAddr)

  // 2. proxy + initialize in one tx: simulate, then send
  const initData = Impl.interface.encodeFunctionData('initialize', [owner, USDC, ZKV, vkHash, versionHash, domainId, attestor])
  const Proxy = await ethers.getContractFactory('ERC1967Proxy')
  const proxyTx = await Proxy.getDeployTransaction(implAddr, initData)
  await ethers.provider.call({ ...proxyTx, from: deployer.address })
  const proxyGas = await ethers.provider.estimateGas({ ...proxyTx, from: deployer.address })
  console.log('proxy simulate ok, gas', proxyGas.toString())
  const proxy = await Proxy.deploy(implAddr, initData)
  await proxy.waitForDeployment()
  const proxyAddr = await proxy.getAddress()

  const escrow = await ethers.getContractAt('MergeToPayEscrow', proxyAddr)
  console.log('\nMergeToPayEscrow proxy:', proxyAddr)
  console.log('owner on chain        :', await escrow.owner())
  console.log('attestor on chain     :', await escrow.attestor())
  console.log('initData (for verify) :', initData)
  console.log('basescan              : https://basescan.org/address/' + proxyAddr)
}

main().catch((e) => { console.error(e.message || e); process.exit(1) })
