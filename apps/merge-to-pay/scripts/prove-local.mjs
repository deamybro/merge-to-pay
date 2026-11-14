// Prove one real GitHub PR through the SDK and save the attestor's response as a fixture.
// Usage: VERITY_ATTESTOR_URL=wss://... node scripts/prove-local.mjs <o/r#N | PR URL> <out.json>
// Optional: GITHUB_TOKEN (sent as a secret header, never part of the signed claim).
import { writeFileSync } from 'node:fs'
import { VerityClient, verifyProof } from '@verity/sdk'
import { parsePr, request } from '../src/spec.mjs'

const [ref, outPath] = process.argv.slice(2)
if (!ref || !outPath) throw new Error('usage: prove-local.mjs <pr ref> <out.json>')

const slots = parsePr(ref)
const verity = new VerityClient()
const t0 = Date.now()
try {
  const token = process.env.GITHUB_TOKEN
  const proof = await verity.prove({
    ...request(slots),
    secretParams: token ? { headers: { Authorization: `Bearer ${token}` } } : undefined,
    onStep: (s) => process.stderr.write(` .${s?.name || ''}`),
  })
  const ok = await verifyProof(proof)
  console.error(`\nproved ${slots.repo}#${slots.pr} in ${((Date.now() - t0) / 1000).toFixed(1)}s, signer ${proof.attestor}, verify ${ok}`)
  console.error('data', JSON.stringify(proof.data))
  const hex = (k, v) => (v instanceof Uint8Array ? '0x' + Buffer.from(v).toString('hex') : v)
  writeFileSync(outPath, JSON.stringify({ ref, slots, attestorUrl: verity.attestorUrl, data: proof.data, attestor: proof.attestor,
    claim: proof.claim, signatures: proof.signatures, raw: proof.raw }, hex, 2))
  await verity.close()
  process.exit(ok ? 0 : 1)
} catch (e) {
  console.error('\nFAILED:', e?.message || e)
  await verity.close()
  process.exit(1)
}
