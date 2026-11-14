// Witness with noir_js, then NATIVE bb: prove (ultra_honk, keccak oracle, --zk) and verify, with timing.
// Usage: node scripts/prove-circuit.mjs test/fixtures/nodejs-node-49999.proof.json [outDir]
// Env: NOIR_HOME (default ~/.cache/verity-noir) with tools/nargo/nargo (1.0.0-beta.6), tools/bb/bb (0.84.0),
//      crs/.bb-crs; or override NARGO, BB, BB_CRS, NOIR_JS one by one. noir_js comes from npm.
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir, homedir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { witness } from '../src/witness.mjs'

const HOME = process.env.NOIR_HOME || join(homedir(), '.cache/verity-noir')
export const NARGO = process.env.NARGO || join(HOME, 'tools/nargo/nargo')
export const BB = process.env.BB || join(HOME, 'tools/bb/bb')
export const CRS = process.env.BB_CRS || join(HOME, 'crs/.bb-crs')
const NOIR_JS = process.env.NOIR_JS
export const CIRCUIT_DIR = new URL('../circuit/', import.meta.url).pathname
const ARTIFACT = join(CIRCUIT_DIR, 'target/github_pr.json')
const BB_FLAGS = ['--scheme', 'ultra_honk', '--oracle_hash', 'keccak', '--zk', '-c', CRS]

const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts })
  return { ok: r.status === 0, out: `${r.stdout}${r.stderr}` }
}

export function compile() {
  if (existsSync(ARTIFACT)) return
  const r = run(NARGO, ['compile', '--silence-warnings'], { cwd: CIRCUIT_DIR })
  if (!r.ok) throw new Error(`nargo compile failed:\n${r.out}`)
}

/** noir_js execution: returns the gz witness bytes and the circuit's 7 return values (bigint). */
export async function execute(inputs) {
  compile()
  const { Noir } = await import(NOIR_JS ? pathToFileURL(NOIR_JS).href : '@noir-lang/noir_js')
  const circuit = JSON.parse(readFileSync(ARTIFACT, 'utf8'))
  const { witness: w, returnValue } = await new Noir(circuit).execute(inputs)
  return { witness: w, returnValue: returnValue.map((x) => BigInt(x)) }
}

/** Native `bb prove --zk` with the keccak oracle. Writes proof, public_inputs, vk into dir. */
export function prove(witnessBytes, dir = mkdtempSync(join(tmpdir(), 'github_pr-'))) {
  mkdirSync(dir, { recursive: true })
  const wpath = join(dir, 'witness.gz')
  writeFileSync(wpath, witnessBytes)
  const t0 = performance.now()
  const time = existsSync('/usr/bin/time') ? ['/usr/bin/time', ['-l', BB]] : [BB, []]
  const r = run(time[0], [...time[1], 'prove', ...BB_FLAGS, '--write_vk', '-b', ARTIFACT, '-w', wpath, '-o', dir])
  if (!r.ok) throw new Error(`bb prove failed:\n${r.out}`)
  const rss = /(\d+)\s+maximum resident set size/.exec(r.out) || /Maximum resident set size \(kbytes\): (\d+)/.exec(r.out)
  const ms = performance.now() - t0
  const pubs = readFileSync(join(dir, 'public_inputs'))
  return { dir, ms, rssMiB: rss ? Number(rss[1]) / (r.out.includes('kbytes') ? 1024 : 1024 * 1024) : null, pubs }
}

export function verify(dir) {
  const t0 = performance.now()
  const r = run(BB, ['verify', ...BB_FLAGS, '-k', join(dir, 'vk'), '-p', join(dir, 'proof'), '-i', join(dir, 'public_inputs')])
  return { ok: r.ok, ms: performance.now() - t0, out: r.out }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [fixture, outDir] = process.argv.slice(2)
  if (!fixture) throw new Error('usage: prove-circuit.mjs <fixture.proof.json> [outDir]')
  const { inputs, pubs } = witness(JSON.parse(readFileSync(fixture, 'utf8')))
  let t = performance.now()
  const { witness: w, returnValue } = await execute(inputs)
  console.log(`witness: ${(performance.now() - t).toFixed(0)} ms, ${w.length} B`)
  if (returnValue.some((v, i) => v !== pubs[i])) throw new Error(`circuit outputs ${returnValue} != expected ${pubs}`)
  const p = prove(w, outDir)
  console.log(`prove (native bb, zk, keccak): ${(p.ms / 1000).toFixed(1)} s, peak RSS ${p.rssMiB?.toFixed(0)} MiB, proof ${readFileSync(join(p.dir, 'proof')).length} B, pubs ${p.pubs.length} B -> ${p.dir}`)
  const v = verify(p.dir)
  console.log(`verify: ${v.ok} in ${v.ms.toFixed(0)} ms`)
  console.log(`public inputs: ${pubs.map((x) => '0x' + x.toString(16)).join(' ')}`)
  process.exit(v.ok ? 0 : 1)
}
