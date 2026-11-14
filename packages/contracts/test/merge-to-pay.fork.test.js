// MergeToPayEscrow on a Base mainnet fork: real USDC, real zkVerify aggregation proxy.
//   BASE_RPC_URL=https://base-rpc.publicnode.com npx hardhat test test/merge-to-pay.fork.test.js
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const { ethers, network } = require('hardhat')

const RPC = process.env.BASE_RPC_URL || 'https://base-rpc.publicnode.com'
const BLOCK = 53215554 // 2026-10-29, after aggregation (2, 141183) was posted
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
const ZKV = '0xCb47A3C3B9Eb2E549a3F2EA4729De28CafbB2b69'
const WHALE = '0x20FE51A9229EEf2cF8Ad9E89d91CAb9312cF3b7A' // EOA, ~313k USDC at BLOCK
const ZKV_AGG_SLOT = 251 // proofsAggregations base slot in ZkVerifyAggregation (checked below against the real root)
const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n
const DAY = 86400n

// A real published aggregation (zkVerify domain 2 -> Base), read from zkVerify via aggregate_statementPath:
// receipt block 0x6365c3…7f9f, root posted on Base in block <= BLOCK.
const REAL = {
  domainId: 2n,
  aggregationId: 141183n,
  root: '0x52b0e95bade772376e691831e30f316b053dbb7761b2935200b516496d971512',
  leaf: '0x2943fe20da93aa01cd99c17fa91dd2896b6d596a33d1c86d54acefe5e4259d36',
  merklePath: ['0xa500943411394b4681bb6b2131338adb19e0a313e60aa836a93453cc78381f08'],
  leafCount: 2n,
  index: 1n,
}

const VK_HASH = ethers.id('test-vk')
const VERSION_HASH = ethers.sha256(ethers.toUtf8Bytes('ultrahonk:v3.0'))
const REPO = 'penguinpecker/verity'
const ISSUE = 7n
const USDC_ABI = ['function balanceOf(address) view returns (uint256)', 'function transfer(address,uint256) returns (bool)', 'function approve(address,uint256) returns (bool)']
const ZKV_ABI = ['function verifyProofAggregation(uint256,uint256,bytes32,bytes32[],uint256,uint256) view returns (bool)', 'function proofsAggregations(uint256,uint256) view returns (bytes32)']

const repoKeyJs = (repo) => BigInt(ethers.keccak256(ethers.toUtf8Bytes(repo))) >> 8n
const coder = ethers.AbiCoder.defaultAbiCoder()
const leafOf = (vkHash, versionHash, pubs) =>
  ethers.keccak256(ethers.concat([ethers.id('ultrahonk'), vkHash, versionHash, ethers.keccak256(coder.encode(Array(7).fill('uint256'), pubs))]))
const aggSlot = (domainId, aggId) =>
  ethers.keccak256(coder.encode(['uint256', 'bytes32'], [aggId, ethers.keccak256(coder.encode(['uint256', 'uint256'], [domainId, ZKV_AGG_SLOT]))]))
const reverts = (p, name) => assert.rejects(p, (e) => { assert.match(e.message, new RegExp(name)); return true })
const fork = (blockNumber) => network.provider.send('hardhat_reset', [{ forking: { jsonRpcUrl: RPC, blockNumber } }])
const now = async () => BigInt((await ethers.provider.getBlock('latest')).timestamp)
const warp = (secs) => network.provider.send('evm_increaseTime', [Number(secs)]).then(() => network.provider.send('evm_mine'))

async function deployEscrow(owner, { vkHash = VK_HASH, versionHash = VERSION_HASH, domainId = REAL.domainId, attestor }) {
  const impl = await (await ethers.getContractFactory('MergeToPayEscrow')).deploy()
  const init = impl.interface.encodeFunctionData('initialize', [owner.address, USDC, ZKV, vkHash, versionHash, domainId, attestor])
  const proxy = await (await ethers.getContractFactory('ERC1967Proxy')).deploy(await impl.getAddress(), init)
  return { impl, escrow: await ethers.getContractAt('MergeToPayEscrow', await proxy.getAddress()) }
}

async function fundUsdc(usdc, to, amount) {
  await network.provider.send('hardhat_setBalance', [WHALE, '0x1000000000000000000'])
  const whale = await ethers.getImpersonatedSigner(WHALE)
  await usdc.connect(whale).transfer(to, amount)
}

describe('MergeToPayEscrow (Base fork)', function () {
  let owner, a, b, stranger, attestor, usdc, zkv, escrow, impl, id, snap
  const AMOUNT = 100_000000n // 100 USDC
  let expiry, minPr, pubs

  before(async function () {
    await fork(BLOCK)
    ;[owner, a, b, stranger, attestor] = await ethers.getSigners()
    usdc = new ethers.Contract(USDC, USDC_ABI, owner)
    zkv = new ethers.Contract(ZKV, ZKV_ABI, owner)
    ;({ impl, escrow } = await deployEscrow(owner, { attestor: attestor.address }))
    await fundUsdc(usdc, a.address, 1_000_000000n)
    await fundUsdc(usdc, b.address, 1_000_000000n)
    for (const s of [a, b]) await usdc.connect(s).approve(await escrow.getAddress(), ethers.MaxUint256)
    expiry = (await now()) + 30n * DAY
    minPr = 42n
    id = await escrow.bountyId(repoKeyJs(REPO), ISSUE)
    // [attestor, repoKey, pr, merged, issue, payee, ts]
    pubs = [BigInt(attestor.address), repoKeyJs(REPO), 50n, 1n, ISSUE, BigInt(stranger.address), await now()]
  })

  beforeEach(async () => { snap = await network.provider.send('evm_snapshot') })
  afterEach(async () => { await network.provider.send('evm_revert', [snap]) })

  it('deploys through an ERC1967 proxy with the given params', async () => {
    assert.equal(await escrow.owner(), owner.address)
    assert.equal(await escrow.usdc(), USDC)
    assert.equal(await escrow.zkv(), ZKV)
    assert.equal(await escrow.vkHash(), VK_HASH)
    assert.equal(await escrow.versionHash(), VERSION_HASH)
    assert.equal(await escrow.domainId(), REAL.domainId)
    assert.equal(await escrow.attestor(), attestor.address)
    assert.notEqual(await escrow.getAddress(), await impl.getAddress())
    await reverts(impl.initialize(owner.address, USDC, ZKV, VK_HASH, VERSION_HASH, 2n, attestor.address), 'InvalidInitialization')
  })

  it('repoKey: matches keccak>>8 and rejects bad charset / shape / length', async () => {
    assert.equal(await escrow.repoKey(REPO), repoKeyJs(REPO))
    const ok140 = 'a'.repeat(39) + '/' + 'b'.repeat(100)
    assert.equal(await escrow.repoKey(ok140), repoKeyJs(ok140))
    for (const bad of ['Penguinpecker/verity', 'noslash', '/verity', 'verity/', 'a/b/c', 'a b/c', 'a/bé', '', ok140 + 'c'])
      await reverts(escrow.repoKey(bad), 'BadRepo')
  })

  it('fund: first funder sets terms, later funders are additive and must match or pass 0', async () => {
    await escrow.connect(a).fund(REPO, ISSUE, AMOUNT, expiry, minPr)
    await escrow.connect(b).fund(REPO, ISSUE, 50_000000n, 0, 0)
    await escrow.connect(b).fund(REPO, ISSUE, 1_000000n, expiry, minPr)
    const bt = await escrow.bounties(id)
    assert.deepEqual([bt.amount, bt.expiry, bt.minPr, bt.paid], [151_000000n, expiry, minPr, false])
    assert.equal(await escrow.funded(id, a.address), AMOUNT)
    assert.equal(await escrow.funded(id, b.address), 51_000000n)
    assert.equal(await usdc.balanceOf(await escrow.getAddress()), 151_000000n)
    await reverts(escrow.connect(b).fund(REPO, ISSUE, 1n, expiry + 1n, 0), 'TermsMismatch')
    await reverts(escrow.connect(b).fund(REPO, ISSUE, 1n, 0, minPr + 1n), 'TermsMismatch')
    await reverts(escrow.connect(b).fund(REPO, ISSUE, 0, 0, 0), 'ZeroAmount')
    await reverts(escrow.connect(a).fund(REPO, 8n, 1n, (await now()) - 1n, 0), 'Expired')
  })

  it('refund: blocked until expiry + 7 days, then per funder', async () => {
    await escrow.connect(a).fund(REPO, ISSUE, AMOUNT, expiry, minPr)
    await escrow.connect(b).fund(REPO, ISSUE, 50_000000n, 0, 0)
    await reverts(escrow.connect(a).refund(id), 'NotRefundable')
    await warp(expiry - (await now()) + 6n * DAY)
    await reverts(escrow.connect(a).refund(id), 'NotRefundable') // expired, still inside grace
    await warp(1n * DAY + 1n)
    const before = await usdc.balanceOf(a.address)
    await escrow.connect(a).refund(id)
    assert.equal((await usdc.balanceOf(a.address)) - before, AMOUNT)
    assert.equal((await escrow.bounties(id)).amount, 50_000000n)
    await reverts(escrow.connect(a).refund(id), 'NothingToRefund')
    await reverts(escrow.connect(stranger).refund(id), 'NothingToRefund')
    await escrow.connect(b).refund(id)
    assert.equal((await escrow.bounties(id)).amount, 0n)
  })

  describe('release guards', () => {
    const rel = (p, agg = 1n) => escrow.connect(stranger).release(p, agg, [], 1n, 0n)
    beforeEach(() => escrow.connect(a).fund(REPO, ISSUE, AMOUNT, expiry, minPr))

    it('M1: every pubs[i] < r, attestor and payee < 2^160', async () => {
      for (let i = 0; i < 7; i++) await reverts(rel(pubs.with(i, R)), 'OutOfRange')
      await reverts(rel(pubs.with(0, 1n << 160n)), 'OutOfRange')
      await reverts(rel(pubs.with(5, 1n << 160n)), 'OutOfRange')
      await reverts(rel(pubs.with(5, BigInt(stranger.address) + (1n << 160n))), 'OutOfRange')
    })
    it('wrong attestor', () => reverts(rel(pubs.with(0, BigInt(stranger.address))), 'BadAttestor'))
    it('merged = 0', () => reverts(rel(pubs.with(3, 0n)), 'NotMerged'))
    it('payee = 0', () => reverts(rel(pubs.with(5, 0n)), 'ZeroPayee'))
    it('no bounty for that issue', () => reverts(rel(pubs.with(4, 999n)), 'NoBounty'))
    it('pr < minPr', () => reverts(rel(pubs.with(2, minPr - 1n)), 'PrTooOld'))
    it('expired bounty', async () => {
      await warp(expiry - (await now()) + 1n)
      await reverts(rel(pubs), 'Expired')
    })
    it('unknown aggregation / bad path -> NotVerified (real zkVerify call)', () => reverts(rel(pubs, 10n ** 12n), 'NotVerified'))
    it('setAttestor(0) pauses release', async () => {
      await escrow.setAttestor(ethers.ZeroAddress)
      await reverts(rel(pubs.with(0, 0n)), 'BadAttestor')
      await reverts(rel(pubs), 'BadAttestor')
      await reverts(escrow.connect(stranger).setAttestor(stranger.address), 'OwnableUnauthorizedAccount')
    })
  })

  it('real aggregation on Base: exact verifyProofAggregation call shape is true, false when a byte changes', async () => {
    assert.equal(await zkv.proofsAggregations(REAL.domainId, REAL.aggregationId), REAL.root)
    assert.equal(await ethers.provider.getStorage(ZKV, aggSlot(REAL.domainId, REAL.aggregationId)), REAL.root, 'ZKV_AGG_SLOT is wrong')
    const ok = await zkv.verifyProofAggregation(REAL.domainId, REAL.aggregationId, REAL.leaf, REAL.merklePath, REAL.leafCount, REAL.index)
    assert.equal(ok, true)
    const flip = (h, i = 5) => h.slice(0, 2 + i) + (h[2 + i] === '0' ? '1' : '0') + h.slice(3 + i)
    assert.equal(await zkv.verifyProofAggregation(REAL.domainId, REAL.aggregationId, flip(REAL.leaf), REAL.merklePath, REAL.leafCount, REAL.index), false)
    assert.equal(await zkv.verifyProofAggregation(REAL.domainId, REAL.aggregationId, REAL.leaf, [flip(REAL.merklePath[0])], REAL.leafCount, REAL.index), false)
    assert.equal(await zkv.verifyProofAggregation(REAL.domainId, REAL.aggregationId, REAL.leaf, REAL.merklePath, REAL.leafCount, 0n), false)
    assert.equal(await zkv.verifyProofAggregation(REAL.domainId, REAL.aggregationId + 1n, REAL.leaf, REAL.merklePath, REAL.leafCount, REAL.index), false)
  })

  it('release pays the payee, then prUsed and double pay revert (root planted on the real zkVerify proxy)', async () => {
    // No aggregation of OUR leaf exists yet, so plant a 2-leaf root for it with hardhat_setStorageAt.
    // The real ZkVerifyAggregation.verifyProofAggregation / Merkle code still does the verification.
    await escrow.connect(a).fund(REPO, ISSUE, AMOUNT, expiry, minPr)
    await escrow.connect(a).fund(REPO, ISSUE + 1n, AMOUNT, expiry, minPr)
    const leaf = leafOf(VK_HASH, VERSION_HASH, pubs)
    const sibling = ethers.id('other-project-leaf')
    const root = ethers.keccak256(ethers.concat([sibling, ethers.keccak256(leaf)])) // index 1 of 2
    const aggId = 10n ** 12n
    await network.provider.send('hardhat_setStorageAt', [ZKV, aggSlot(REAL.domainId, aggId), root])
    assert.equal(await zkv.proofsAggregations(REAL.domainId, aggId), root)

    await reverts(escrow.connect(stranger).release(pubs, aggId, [sibling], 2n, 0n), 'NotVerified') // wrong index
    const before = await usdc.balanceOf(stranger.address)
    const tx = await escrow.connect(stranger).release(pubs, aggId, [sibling], 2n, 1n)
    const rc = await tx.wait()
    console.log('      release gas used:', rc.gasUsed.toString())
    assert.equal((await usdc.balanceOf(stranger.address)) - before, AMOUNT)
    assert.equal((await escrow.bounties(id)).paid, true)
    assert.equal(await escrow.prUsed(ethers.keccak256(coder.encode(['uint256', 'uint256'], [pubs[1], pubs[2]]))), true)
    assert.ok(rc.logs.some((l) => l.fragment?.name === 'Paid'))

    await reverts(escrow.connect(stranger).release(pubs, aggId, [sibling], 2n, 1n), 'AlreadyPaid')
    await reverts(escrow.connect(stranger).release(pubs.with(4, ISSUE + 1n), aggId, [sibling], 2n, 1n), 'PrAlreadyUsed')
    await reverts(escrow.connect(a).refund(id), 'NotRefundable')
    await reverts(escrow.connect(a).fund(REPO, ISSUE, 1n, 0, 0), 'AlreadyPaid')
  })

  it('upgrade by a non-owner reverts; owner can upgrade and set verifier params', async () => {
    const impl2 = await (await ethers.getContractFactory('MergeToPayEscrow')).deploy()
    await reverts(escrow.connect(stranger).upgradeToAndCall(await impl2.getAddress(), '0x'), 'OwnableUnauthorizedAccount')
    await reverts(escrow.connect(stranger).setVerifierParams(VK_HASH, VERSION_HASH, 3n), 'OwnableUnauthorizedAccount')
    await escrow.upgradeToAndCall(await impl2.getAddress(), '0x')
    await escrow.setVerifierParams(ethers.id('vk2'), ethers.id('v2'), 3n)
    assert.equal(await escrow.domainId(), 3n)
    assert.equal(await escrow.owner(), owner.address)
  })
})

// Own describe + own fork: a present fixture must not reset the chain under the tests above.
describe('MergeToPayEscrow real aggregation fixture (Base fork)', function () {
  const AMOUNT = 100_000000n
  it('real release from test/fixtures/aggregation.json', async function () {
    const file = path.join(__dirname, 'fixtures', 'aggregation.json')
    if (!fs.existsSync(file)) {
      console.log('      SKIP: no test/fixtures/aggregation.json yet (needs a real Kurier run: pubs, repo, aggregationId, merklePath, leafCount, index, vkHash, versionHash, domainId, blockNumber)')
      return this.skip()
    }
    const f = JSON.parse(fs.readFileSync(file, 'utf8'))
    const fp = f.pubs.map(BigInt)
    await fork(f.blockNumber)
    const [own, funder] = await ethers.getSigners()
    const { escrow: e } = await deployEscrow(own, { vkHash: f.vkHash, versionHash: f.versionHash, domainId: BigInt(f.domainId), attestor: ethers.getAddress(ethers.toBeHex(fp[0], 20)) })
    assert.equal(await e.repoKey(f.repo), fp[1], 'fixture.repo must hash to pubs[1]')
    const u = new ethers.Contract(USDC, USDC_ABI, funder)
    await fundUsdc(u, funder.address, AMOUNT)
    await u.approve(await e.getAddress(), AMOUNT)
    await e.connect(funder).fund(f.repo, fp[4], AMOUNT, (await now()) + 30n * DAY, fp[2])
    const payee = ethers.getAddress(ethers.toBeHex(fp[5], 20))
    const before = await u.balanceOf(payee)
    const rc = await (await e.release(fp, BigInt(f.aggregationId), f.merklePath, BigInt(f.leafCount), BigInt(f.index))).wait()
    console.log('      real release gas used:', rc.gasUsed.toString())
    assert.equal((await u.balanceOf(payee)) - before, AMOUNT)
  })
})
