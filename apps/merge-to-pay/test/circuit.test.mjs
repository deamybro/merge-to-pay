// github_pr circuit against the real fixtures (signed by Reclaim's public attestor; the attestor is a
// public input, so that signer is fine here). Native bb prove --zk / verify through scripts/prove-circuit.mjs.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, rmSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { Wallet, keccak256, toUtf8Bytes } from 'ethers'
import { keccakP, keccak_256 } from '@noble/hashes/sha3'
import { u32 } from '@noble/hashes/utils'
import { REGEX, assemble, parameters } from '../src/spec.mjs'
import { witness, signedMessage, toToml, pubsBytes } from '../src/witness.mjs'
import { render, midstate, RATE } from '../scripts/gen-circuit.mjs'
import { execute, prove, verify, NARGO, CIRCUIT_DIR } from '../scripts/prove-circuit.mjs'

const dir = new URL('./fixtures/', import.meta.url)
const load = (n) => JSON.parse(readFileSync(new URL(`nodejs-node-${n}.proof.json`, dir), 'utf8'))
const fixtures = { 49999: load(49999), 67092: load(67092), 66854: load(66854) }
const claimString = (c) => `${c.provider}\n${c.parameters}\n${c.context}`
const rejects = (inputs, re) => assert.rejects(execute(inputs), re)
const proofs = {}

test('template.nr on disk is what gen-circuit.mjs derives from spec.mjs', () => {
  assert.equal(readFileSync(join(CIRCUIT_DIR, 'src/template.nr'), 'utf8'), render())
})

test('MIDSTATE: resuming the sponge from the generated midstate reproduces keccak256(claim) of every fixture', () => {
  for (const { claim } of Object.values(fixtures)) {
    const bytes = Buffer.from(claimString(claim))
    const st = new Uint8Array(200)
    const dv = new DataView(st.buffer)
    midstate(bytes, 3).forEach((v, l) => dv.setBigUint64(l * 8, v, true))
    const rest = bytes.subarray(3 * RATE)
    const padded = Buffer.alloc(Math.ceil((rest.length + 1) / RATE) * RATE)
    rest.copy(padded)
    padded[rest.length] = 1
    padded[padded.length - 1] |= 0x80
    for (let b = 0; b < padded.length / RATE; b++) {
      for (let i = 0; i < RATE; i++) st[i] ^= padded[b * RATE + i]
      keccakP(u32(st), 24)
    }
    assert.equal(Buffer.from(st.subarray(0, 32)).toString('hex'), Buffer.from(keccak_256(bytes)).toString('hex'))
    assert.equal(keccak256(bytes), claim.identifier)
  }
})

for (const [n, fx] of Object.entries(fixtures)) {
  test(`positive: ${fx.ref} proves and verifies natively (zk, keccak) with the expected public inputs`, async (t) => {
    const { inputs, pubs } = witness(fx)
    const expected = [BigInt(fx.attestor), BigInt(keccak256(toUtf8Bytes('nodejs/node'))) >> 8n, BigInt(n), n === '49999' ? 1n : 0n, 0n, 0n, BigInt(fx.claim.timestampS)]
    assert.deepEqual(pubs, expected)
    const { witness: w, returnValue } = await execute(inputs)
    assert.deepEqual(returnValue, expected, 'circuit outputs == expected public inputs')
    const p = prove(w)
    assert.deepEqual(p.pubs, pubsBytes(pubs), 'bb public_inputs file == 7 x 32-byte big-endian')
    const v = verify(p.dir)
    assert.ok(v.ok, v.out)
    t.diagnostic(`${fx.ref}: prove ${(p.ms / 1000).toFixed(1)} s, peak RSS ${p.rssMiB?.toFixed(0)} MiB, verify ${v.ms.toFixed(0)} ms`)
    proofs[n] = { dir: p.dir, inputs, pubs }
  })
}

test('negative: one context byte changed is caught in JS and, forced through, by the circuit', async () => {
  const fx = fixtures[49999]
  const context = fx.claim.context.replace('providerHash":"0xe', 'providerHash":"0xf')
  assert.notEqual(context, fx.claim.context)
  assert.throws(() => witness({ ...fx, claim: { ...fx.claim, context } }), /keccak256\(claim\) != identifier/)
  const { inputs } = witness(fx)
  const provider_hash = inputs.provider_hash.slice()
  provider_hash[0] = 'f'.charCodeAt(0)
  await rejects({ ...inputs, provider_hash }, /bad signature/)
})

test('negative: a wrong attestor, payee, pr, merged or ts public input fails bb verify', async () => {
  const p = proofs[49999]
  assert.ok(p, 'positive test must have run')
  for (const [name, i, bad] of [['attestor', 0, 1n], ['payee', 5, 1n], ['pr', 2, 49998n], ['merged', 3, 0n], ['ts', 6, p.pubs[6] + 1n]]) {
    const pubs = p.pubs.slice()
    pubs[i] = bad
    writeFileSync(join(p.dir, 'public_inputs'), pubsBytes(pubs))
    assert.equal(verify(p.dir).ok, false, `wrong ${name} must not verify`)
  }
  writeFileSync(join(p.dir, 'public_inputs'), pubsBytes(p.pubs))
  assert.equal(verify(p.dir).ok, true)
})

test('negative: uppercase repo is rejected', async () => {
  const { inputs } = witness(fixtures[49999])
  const repo = inputs.repo.slice()
  repo[0] = 'N'.charCodeAt(0)
  await rejects({ ...inputs, repo }, /repo char/)
})

test('negative: a claim made with a different regex is not this template', () => {
  const fx = fixtures[49999]
  const other = REGEX.replace('{20}', '{19}')
  const parameters = fx.claim.parameters.replaceAll(JSON.stringify(REGEX).slice(1, -1), JSON.stringify(other).slice(1, -1))
  assert.notEqual(parameters, fx.claim.parameters)
  assert.throws(() => witness({ ...fx, claim: { ...fx.claim, parameters } }), /parameters differ from spec/)
})

test('negative: truncated or flipped signature', async () => {
  const { inputs } = witness(fixtures[67092])
  await rejects({ ...inputs, sig: inputs.sig.slice(0, 63) }, /./)
  const sig = inputs.sig.slice()
  sig[40] ^= 1
  await rejects({ ...inputs, sig }, /bad signature/)
})

test('negative: ts with 9 digits, or a non-digit', async () => {
  const { inputs } = witness(fixtures[66854])
  await rejects({ ...inputs, ts: inputs.ts.slice(0, 9) }, /./)
  const ts = inputs.ts.slice()
  ts[3] = 'x'.charCodeAt(0)
  await rejects({ ...inputs, ts }, /not a digit/)
})

test('negative: non-hex payee (payout shape forced onto a real claim)', async () => {
  const { inputs } = witness(fixtures[49999])
  await rejects({ ...inputs, payout: true, issue_len: '1', issue: [49, 0, 0, 0, 0, 0, 0, 0, 0], payee: Array(40).fill('g'.charCodeAt(0)) }, /not hex/)
})

test('synthetic-signer (shape only): payout-line context carries issue and payee through nargo execute', () => {
  // No real attestor claim with a payout line exists yet. A throwaway in-memory key signs a claim
  // of the payout shape so the context layout can be exercised; it proves nothing about GitHub.
  const fx = fixtures[49999]
  const signer = Wallet.createRandom()
  const slots = { repo: 'nodejs/node', pr: 49999, mergedAt: '"2023-10-03T18:19:51Z"', issue: '12', payee: '0xAbCdEf0123456789abcdef0123456789ABCDEF01', providerHash: JSON.parse(fx.claim.context).providerHash }
  const context = JSON.stringify({ extractedParameters: { issue: slots.issue, mergedAt: slots.mergedAt, payee: slots.payee }, providerHash: slots.providerHash })
  const claim = { provider: 'http', parameters: parameters(slots), owner: fx.claim.owner, timestampS: fx.claim.timestampS, context, epoch: 1 }
  assert.equal(claimString(claim), assemble(slots))
  claim.identifier = keccak256(toUtf8Bytes(claimString(claim)))
  const sign = (c) => signer.signMessageSync(signedMessage(c))
  const { inputs, pubs } = witness({ claim, signatures: { claimSignature: sign(claim), attestorAddress: signer.address } })
  assert.equal(pubs[4], 12n)
  assert.equal(pubs[5], BigInt(slots.payee))
  const prover = join(CIRCUIT_DIR, 'Prover.toml') // nargo beta.6 ignores --prover-name; default name, removed below
  writeFileSync(prover, toToml(inputs))
  try {
    const out = execFileSync(NARGO, ['execute', '--silence-warnings', 'synthetic'], { cwd: CIRCUIT_DIR, encoding: 'utf8' })
    const got = [...out.matchAll(/Field\((\d+)\)/g)].map((m) => BigInt(m[1]))
    assert.deepEqual(got, [BigInt(signer.address), ...pubs.slice(1)])
    // same shape, different regex in the signed claim: the compiled template rejects it
    const other = { ...claim, parameters: claim.parameters.replaceAll('{20}', '{19}') }
    other.identifier = keccak256(toUtf8Bytes(claimString(other)))
    const forced = { ...inputs, sig: Array.from(Buffer.from(sign(other).slice(2, 130), 'hex')) }
    writeFileSync(prover, toToml(forced))
    assert.throws(() => execFileSync(NARGO, ['execute', '--silence-warnings', 'synthetic'], { cwd: CIRCUIT_DIR, stdio: 'pipe' }), /bad signature/)
  } finally {
    rmSync(prover, { force: true })
    rmSync(join(CIRCUIT_DIR, 'target/synthetic.gz'), { force: true })
  }
})

test('synthetic-signer (shape only): shortest and longest claims take the 2-block and 4-block keccak paths', async () => {
  // The real fixtures are all 699-byte claims (3 dynamic blocks, 1-block repo). These two shapes reach
  // the other block counts; the throwaway key only shows the in-circuit hash matches JS keccak.
  const fx = fixtures[49999]
  const signer = Wallet.createRandom()
  const providerHash = JSON.parse(fx.claim.context).providerHash
  for (const [slots, blocks] of [
    [{ repo: 'a/b', pr: 1, mergedAt: 'null', providerHash }, 2],
    [{ repo: `${'a'.repeat(39)}/${'b'.repeat(100)}`, pr: 999999999, mergedAt: '"2023-10-03T18:19:51Z"', issue: '999999999', payee: '0x0123456789abcdef0123456789abcdef01234567', providerHash }, 4],
  ]) {
    const { issue, mergedAt, payee } = slots
    const context = JSON.stringify({ extractedParameters: issue ? { issue, mergedAt, payee } : { mergedAt }, providerHash })
    const claim = { provider: 'http', parameters: parameters(slots), owner: fx.claim.owner, timestampS: fx.claim.timestampS, context, epoch: 1 }
    const full = claimString(claim)
    assert.equal(full, assemble(slots))
    assert.equal(Math.ceil((Buffer.byteLength(full) - 3 * RATE + 1) / RATE), blocks)
    claim.identifier = keccak256(toUtf8Bytes(full))
    const { inputs, pubs } = witness({ claim, signatures: { claimSignature: signer.signMessageSync(signedMessage(claim)), attestorAddress: signer.address } })
    const { returnValue } = await execute(inputs)
    assert.deepEqual(returnValue, pubs)
    assert.equal(pubs[1], BigInt(keccak256(toUtf8Bytes(slots.repo))) >> 8n)
  }
})
