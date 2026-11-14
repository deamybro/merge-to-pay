// Fund (or top up) a USDC bounty on a GitHub issue. Simulates approve and fund before sending.
//   DEPLOYER_PRIVATE_KEY=0x.. ESCROW=0x.. REPO=owner/name ISSUE=7 AMOUNT=25 EXPIRY_DAYS=30 MIN_PR=123 \
//     npx hardhat run scripts/fund-bounty.js --network base
// AMOUNT is in USDC (6 decimals). MIN_PR = the repo's next PR/issue number right now (GitHub: highest number + 1).
// For a top-up of an existing bounty, EXPIRY_DAYS and MIN_PR may be omitted (0 = accept the existing terms).
const hre = require('hardhat')

const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
const USDC_ABI = ['function balanceOf(address) view returns (uint256)', 'function allowance(address,address) view returns (uint256)', 'function approve(address,uint256) returns (bool)']

function env(name, fallback) {
  const v = process.env[name] ?? fallback
  if (v === undefined || v === '') throw new Error(`set ${name}`)
  return v
}

async function main() {
  const { ethers } = hre
  const net = await ethers.provider.getNetwork()
  if (net.chainId !== 8453n) throw new Error(`expected Base (8453), got chainId ${net.chainId}; use --network base`)
  const [funder] = await ethers.getSigners()
  if (!funder) throw new Error('set DEPLOYER_PRIVATE_KEY in the environment')

  const escrowAddr = ethers.getAddress(env('ESCROW'))
  const repo = env('REPO')
  const issue = BigInt(env('ISSUE'))
  const amount = ethers.parseUnits(env('AMOUNT'), 6)
  const expiryDays = Number(env('EXPIRY_DAYS', '0'))
  const minPr = BigInt(env('MIN_PR', '0'))
  const expiry = expiryDays ? BigInt(Math.floor(Date.now() / 1000) + expiryDays * 86400) : 0n

  const escrow = await ethers.getContractAt('MergeToPayEscrow', escrowAddr)
  const usdc = new ethers.Contract(USDC, USDC_ABI, funder)
  const id = await escrow.bountyId(await escrow.repoKey(repo), issue) // reverts here if repo is malformed
  const existing = await escrow.bounties(id)
  console.log('funder   :', funder.address, ethers.formatUnits(await usdc.balanceOf(funder.address), 6), 'USDC')
  console.log('escrow   :', escrowAddr)
  console.log('bounty   :', id, `${repo}#${issue}`)
  console.log('existing :', ethers.formatUnits(existing.amount, 6), 'USDC, expiry', existing.expiry.toString(), 'minPr', existing.minPr.toString(), 'paid', existing.paid)
  console.log('adding   :', ethers.formatUnits(amount, 6), 'USDC, expiry', expiry.toString(), 'minPr', minPr.toString())
  if (existing.amount === 0n && (expiry === 0n || minPr === 0n)) console.log('WARNING: first funder sets the terms; EXPIRY_DAYS and MIN_PR should both be set')

  if ((await usdc.allowance(funder.address, escrowAddr)) < amount) {
    await usdc.approve.staticCall(escrowAddr, amount)
    const tx = await usdc.approve(escrowAddr, amount)
    console.log('approve  :', tx.hash); await tx.wait()
  }
  await escrow.fund.staticCall(repo, issue, amount, expiry, minPr) // simulate; reverts with the custom error if it would fail
  const gas = await escrow.fund.estimateGas(repo, issue, amount, expiry, minPr)
  console.log('fund simulate ok, gas', gas.toString())
  const tx = await escrow.fund(repo, issue, amount, expiry, minPr)
  console.log('fund     :', tx.hash); await tx.wait()
  const after = await escrow.bounties(id)
  console.log('bounty now:', ethers.formatUnits(after.amount, 6), 'USDC, expiry', after.expiry.toString(), 'minPr', after.minPr.toString())
}

main().catch((e) => { console.error(e.message || e); process.exit(1) })
