// Circuit proof for a signed claim: witness via noir_js, then NATIVE bb (BB_BIN) prove --zk + verify,
// in a per-run tmp dir, with the CRS at BB_CRS. One proof at a time (withLock): a fresh run is ~1 GB.
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { hexlify } from 'ethers'
import { witness } from './witness.mjs'

const NOIR_HOME = process.env.NOIR_HOME || join(homedir(), '.cache/verity-noir')
const BB = () => process.env.BB_BIN || process.env.BB || join(NOIR_HOME, 'tools/bb/bb')
const CRS = () => process.env.BB_CRS || join(NOIR_HOME, 'crs/.bb-crs')
const ARTIFACT = new URL('../circuit/target/github_pr.json', import.meta.url).pathname
const FLAGS = () => ['--scheme', 'ultra_honk', '--oracle_hash', 'keccak', '--zk', '-c', CRS()]
const run = promisify(execFile)
const hex = (b) => '0x' + Buffer.from(b).toString('hex')

let noir
async function execute(inputs) {
  if (!noir) {
    const mod = await import('@noir-lang/noir_js').catch(() => import(pathToFileURL(join(NOIR_HOME, 'node_modules/@noir-lang/noir_js/lib/index.mjs')).href))
    noir = new mod.Noir(JSON.parse(readFileSync(ARTIFACT, 'utf8')))
  }
  return noir.execute(inputs)
}

/** {claim, signatures} -> { proofHex, vkHex, pubs (7 bigint), ms: {witness, prove, verify} }. Throws if bb verify fails. */
export async function proveClaim({ claim, signatures }) {
  const { inputs, pubs } = witness({ claim, signatures: { ...signatures, claimSignature: hexlify(signatures.claimSignature) } }) // live SDK proofs carry bytes, fixtures hex
  const ms = {}
  let t = performance.now()
  const { witness: w, returnValue } = await execute(inputs)
  ms.witness = performance.now() - t
  if (returnValue.some((v, i) => BigInt(v) !== pubs[i])) throw new Error('circuit outputs differ from the expected public inputs')
  mkdirSync(CRS(), { recursive: true }) // bb refuses a missing --crs_path, and downloads the points it needs into it
  const dir = mkdtempSync(join(tmpdir(), 'm2p-'))
  try {
    writeFileSync(join(dir, 'witness.gz'), w)
    t = performance.now()
    await run(BB(), ['prove', ...FLAGS(), '--write_vk', '-b', ARTIFACT, '-w', join(dir, 'witness.gz'), '-o', dir], { maxBuffer: 1 << 24 })
    ms.prove = performance.now() - t
    t = performance.now()
    await run(BB(), ['verify', ...FLAGS(), '-k', join(dir, 'vk'), '-p', join(dir, 'proof'), '-i', join(dir, 'public_inputs')])
    ms.verify = performance.now() - t
    return { proofHex: hex(readFileSync(join(dir, 'proof'))), vkHex: hex(readFileSync(join(dir, 'vk'))), pubs, ms }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// ponytail: in-process mutex, one fresh run per machine; a queue across machines if ever scaled past one.
export class BusyError extends Error { constructor() { super('busy: another proof is running, retry in 60 s'); this.kind = 'busy' } }
let tail = Promise.resolve()
export let busy = false

/** Run fn under the single prover lock; reject with BusyError after waitMs (PROVER_WAIT_MS, default 60 s) in the queue. */
export function withLock(fn, waitMs = Number(process.env.PROVER_WAIT_MS || 60_000)) {
  return new Promise((resolve, reject) => {
    let gaveUp = false
    const timer = setTimeout(() => { gaveUp = true; reject(new BusyError()) }, waitMs)
    tail = tail.then(async () => {
      clearTimeout(timer)
      if (gaveUp) return
      busy = true
      try { resolve(await fn()) } catch (e) { reject(e) } finally { busy = false }
    })
  })
}
