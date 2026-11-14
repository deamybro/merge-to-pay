// Policy: every reason code, driven by the real attestor fixtures (public inputs via witness()) plus
// escrow reads injected as plain objects. The payout-line shape uses a throwaway signer (no real
// payout-line fixture exists yet); the escrow seam is a unit seam, not a data source.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Wallet, keccak256, toUtf8Bytes } from 'ethers'
import { parameters, assemble } from '../src/spec.mjs'
import { witness, signedMessage } from '../src/witness.mjs'
import { decide, classify, apply } from '../src/run.mjs'
import { leafCandidates, matchStatement, isFinalized, isSettled, isPublished, isFailed, hex32 } from '../src/kurier.mjs'
import * as store from '../src/store.mjs'

const dir = new URL('./fixtures/', import.meta.url)
const load = (n) => JSON.parse(readFileSync(new URL(`nodejs-node-${n}.proof.json`, dir), 'utf8'))
const issue = (n) => JSON.parse(readFileSync(new URL(`nodejs-node-${n}.issue.json`, dir), 'utf8'))
const facts = (pubs) => ({ merged: pubs[3] === 1n, issue: pubs[4], pr: pubs[2] })
const NOW = 1_800_000_000
const open = { amount: 10_000_000n, expiry: BigInt(NOW + 86400), minPr: 49_000n, paid: false, prUsed: false }

test('real claims: merged without a line -> NO_PAYOUT_LINE; open PRs -> NOT_MERGED', () => {
  assert.deepEqual(decide(facts(witness(load(49999)).pubs), open, NOW), ['DECLINE', 'NO_PAYOUT_LINE'])
  for (const n of [67092, 66854]) assert.deepEqual(decide(facts(witness(load(n)).pubs), open, NOW), ['DECLINE', 'NOT_MERGED'])
})

// Payout-line shape over the real 49999 slots, signed by a throwaway key (shape only).
const fx = load(49999)
const signer = Wallet.createRandom()
const slots = { repo: 'nodejs/node', pr: 49999, mergedAt: '"2023-10-03T18:19:51Z"', issue: '12', payee: '0xAbCdEf0123456789abcdef0123456789ABCDEF01', providerHash: JSON.parse(fx.claim.context).providerHash }
const claim = { provider: 'http', parameters: parameters(slots), owner: fx.claim.owner, timestampS: fx.claim.timestampS, epoch: 1,
  context: JSON.stringify({ extractedParameters: { issue: slots.issue, mergedAt: slots.mergedAt, payee: slots.payee }, providerHash: slots.providerHash }) }
claim.identifier = keccak256(toUtf8Bytes(assemble(slots)))
const paid = witness({ claim, signatures: { claimSignature: signer.signMessageSync(signedMessage(claim)), attestorAddress: signer.address } })
const f = facts(paid.pubs)

test('payout-line claim: every escrow reason code', () => {
  assert.equal(f.issue, 12n)
  assert.deepEqual(decide(f, undefined, NOW), ['ELIGIBLE', 'NO_ESCROW_CONFIGURED'])
  assert.deepEqual(decide(f, { ...open, amount: 0n }, NOW), ['DECLINE', 'NO_BOUNTY'])
  assert.deepEqual(decide(f, { ...open, paid: true }, NOW), ['DECLINE', 'BOUNTY_PAID'])
  assert.deepEqual(decide(f, { ...open, prUsed: true }, NOW), ['DECLINE', 'PR_USED'])
  assert.deepEqual(decide(f, { ...open, expiry: BigInt(NOW - 1) }, NOW), ['DECLINE', 'EXPIRED'])
  assert.deepEqual(decide(f, { ...open, expiry: BigInt(NOW) }, NOW), ['PAY', 'BOUNTY_OPEN'], 'expiry is inclusive')
  assert.deepEqual(decide(f, { ...open, minPr: 50_000n }, NOW), ['DECLINE', 'BELOW_MIN_PR'])
  assert.deepEqual(decide(f, { ...open, minPr: 49_999n }, NOW), ['PAY', 'BOUNTY_OPEN'], 'minPr is inclusive')
  assert.deepEqual(decide(f, open, NOW), ['PAY', 'BOUNTY_OPEN'])
  // order: paid beats used beats expired beats minPr
  assert.deepEqual(decide(f, { ...open, paid: true, prUsed: true, expiry: 0n, minPr: 1n << 40n }, NOW), ['DECLINE', 'BOUNTY_PAID'])
})

test('classify on the real issue JSON: NOT_A_PR, merge age, payout line (MERGE_TOO_OLD gate)', () => {
  const merged = issue(49999)
  assert.deepEqual(classify(merged, Date.parse('2023-10-03T19:00:00Z')), { pr: true, mergedAt: '2023-10-03T18:19:51Z', hasLine: false, tooOld: false })
  assert.equal(classify(merged).tooOld, false, 'no payout line: age does not matter')
  const lined = { ...merged, body: 'verity-payout: #12 0xAbCdEf0123456789abcdef0123456789ABCDEF01\n\n' + merged.body }
  assert.equal(classify(lined).tooOld, true, 'line present and merged in 2023: too old')
  assert.equal(classify(lined, Date.parse('2023-10-03T18:19:51Z') + 3600_000).tooOld, false, 'exactly MAX_MERGE_AGE_S is still fresh')
  assert.equal(classify(lined, Date.parse('2023-10-03T18:19:51Z') + 3601_000).tooOld, true)
  const openPr = issue(67092)
  assert.deepEqual(classify(openPr), { pr: true, mergedAt: null, hasLine: false, tooOld: false })
  const { pull_request, ...plainIssue } = merged
  assert.deepEqual(classify(plainIssue), { pr: false })
})

test('zkVerify statement math equals the pallet test vector (Legacy rule) and the 7-input layout', () => {
  const v = JSON.parse(readFileSync(new URL('zkverify-ultrahonk-vector.json', dir), 'utf8'))
  const legacy = leafCandidates(v.rawVk, v.pubs, null).find((c) => c.name === 'Legacy')
  assert.equal(legacy.vkHash, v.expectedLegacyVkHash)
  assert.equal(legacy.leaf, v.expectedStatement)
  assert.equal(matchStatement(v.rawVk, v.pubs, null, v.expectedStatement).name, 'Legacy')
  assert.equal(matchStatement(v.rawVk, v.pubs, null, '0x' + '00'.repeat(32)), undefined)
  const withKurier = leafCandidates(v.rawVk, v.pubs, v.expectedLegacyVkHash)
  assert.equal(withKurier.length, 6)
  assert.equal(withKurier.filter((c) => c.leaf === v.expectedStatement).length, 2, 'Legacy rule and kurierVkHash+Legacy coincide')
  assert.equal(hex32(paid.pubs[5]), '0x000000000000000000000000abcdef0123456789abcdef0123456789abcdef01')
})

test('Kurier lifecycle predicates and record folding', () => {
  const j = (status, extra = {}) => ({ status, ...extra })
  assert.equal(isFinalized(j('IncludedInBlock')), false)
  assert.equal(isSettled(j('Submitted')), false)
  for (const s of ['Finalized', 'AggregationPending', 'Aggregated']) { assert.equal(isFinalized(j(s)), true); assert.equal(isSettled(j(s)), true) }
  assert.equal(isFailed(j('Failed')), true)
  assert.equal(isSettled(j('Failed')), true)
  assert.equal(isPublished(j('Aggregated')), false)
  assert.equal(isPublished(j('Aggregated', { aggregationPublished: { destinationChainId: 8453, destinationTxHash: '0xab' } })), true)
  const rec = { zkverify: { jobId: 'x', status: 'Queued', txHash: null, explorer: null, statement: null, vkHash: '0x1', publicInputs: [] }, aggregation: { chainId: 8453, status: 'pending', aggregationId: null } }
  apply(rec, j('Finalized', { txHash: '0xt', txExplorerUrl: 'https://zkverify.subscan.io/extrinsic/0xt' }))
  assert.equal(rec.zkverify.txHash, '0xt')
  apply(rec, j('Aggregated', { aggregationId: 7, statement: '0xs', aggregationDetails: { leaf: '0xs', merkleProof: [] } }))
  assert.equal(rec.zkverify.txHash, '0xt', 'absent fields keep earlier values')
  assert.deepEqual([rec.aggregation.status, rec.aggregation.aggregationId, rec.zkverify.statement], ['aggregated', 7, '0xs'])
  apply(rec, j('Aggregated', { aggregationPublished: { destinationChainId: 8453, destinationTxHash: '0xbase' } }))
  assert.deepEqual([rec.aggregation.status, rec.aggregation.txHash], ['published', '0xbase'])
})

test('store: atomic JSON records and the daily cap', () => {
  process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'm2p-store-'))
  process.env.DAILY_CAP = '2'
  assert.equal(store.read('prs', 'none'), undefined)
  const key = store.prKey({ repo: 'nodejs/node', pr: 49999 })
  assert.equal(key, 'nodejs__node__49999')
  store.write('prs', key, { decision: 'DECLINE' })
  assert.deepEqual(store.read('prs', key), { decision: 'DECLINE' })
  store.remove('prs', key)
  assert.equal(store.read('prs', key), undefined)
  assert.equal(store.takeDailySlot(), true)
  assert.equal(store.takeDailySlot(), true)
  assert.equal(store.takeDailySlot(), false)
  assert.equal(store.dailyCount(), 2)
})

test('releaseArgs: only an aggregated or published, unpaid PAY record with a merkle proof is payable', async () => {
  const { releaseArgs } = await import('../src/settle.mjs')
  const rec = {
    decision: 'PAY', zkverify: { publicInputs: ['0x01', '0x02', '0x03', '0x01', '0x05', '0x06', '0x07'] },
    aggregation: { status: 'published', aggregationId: 9, details: { merkleProof: ['0xaa'], numberOfLeaves: 4, leafIndex: 2 } },
    payout: { escrow: '0x0000000000000000000000000000000000000001', txHash: null },
  }
  assert.deepEqual(releaseArgs(rec), [[1n, 2n, 3n, 1n, 5n, 6n, 7n], 9n, ['0xaa'], 4n, 2n])
  assert.equal(releaseArgs({ ...rec, decision: 'ELIGIBLE' }), null)
  assert.deepEqual(releaseArgs({ ...rec, aggregation: { ...rec.aggregation, status: 'aggregated' } })[1], 9n)
  assert.equal(releaseArgs({ ...rec, aggregation: { ...rec.aggregation, status: 'pending' } }), null)
  assert.equal(releaseArgs({ ...rec, aggregation: { ...rec.aggregation, details: { leaf: '0xs' } } }), null)
  assert.equal(releaseArgs({ ...rec, payout: { ...rec.payout, txHash: '0xpaid' } }), null)
  assert.equal(releaseArgs({ ...rec, payout: { escrow: null } }), null)
})
