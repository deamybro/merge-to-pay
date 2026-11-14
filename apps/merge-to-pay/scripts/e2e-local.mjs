// Real local run, dev only: zkTLS on Reclaim's public attestor (no auth), witness, native bb prove + verify.
// Stops BEFORE Kurier and prints timings. Usage: node scripts/e2e-local.mjs [o/r#N] (default nodejs/node#49999)
import { parsePr } from '../src/spec.mjs'
import { zktls, decide } from '../src/run.mjs'
import { proveClaim } from '../src/prover.mjs'
import { leafCandidates, hex32 } from '../src/kurier.mjs'

const slots = parsePr(process.argv[2] || 'nodejs/node#49999')
const ATTESTOR = 'wss://attestor.reclaimprotocol.org:444/ws'
const s = (ms) => `${(ms / 1000).toFixed(1)} s`

let t = performance.now()
const proof = await zktls(slots, { attestorUrl: ATTESTOR, onStep: (st) => st?.name && process.stderr.write(` .${st.name}`) })
const zk = performance.now() - t
console.log(`\nzkTLS ${slots.repo}#${slots.pr}: ${s(zk)}, attestor ${proof.attestor}, data ${JSON.stringify(proof.data)}`)

t = performance.now()
const p = await proveClaim(proof)
console.log(`witness ${p.ms.witness.toFixed(0)} ms, bb prove --zk ${s(p.ms.prove)}, bb verify ${p.ms.verify.toFixed(0)} ms (circuit total ${s(performance.now() - t)})`)
console.log(`proof ${(p.proofHex.length - 2) / 2} B, vk ${(p.vkHex.length - 2) / 2} B`)
console.log('public inputs', p.pubs.map(hex32))
const [, , pr, merged, issue] = p.pubs
console.log('decision (no escrow)', decide({ merged: merged === 1n, issue, pr }, undefined))
console.log('leaf candidates (which one Kurier uses is pinned from the first real statement):')
for (const c of leafCandidates(p.vkHex, p.pubs, null)) console.log(`  ${c.name.padEnd(7)} vkHash ${c.vkHash} leaf ${c.leaf}`)
console.log(`total ${s(zk + p.ms.witness + p.ms.prove + p.ms.verify)}; stopped before Kurier submit`)
