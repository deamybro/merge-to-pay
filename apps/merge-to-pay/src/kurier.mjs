// Kurier (zkVerify relayer) client. The API key is part of every URL, so nothing here logs a URL
// or a raw error body: every string that leaves this module passes through scrub().
// leafCandidates() is the zkVerify statement math ported from the G0 runner (scratch noir/g0/run.mjs).
import { keccak256, sha256, getBytes } from 'ethers'

const BASE = 'https://api.kurier.xyz/api/v1'
const OPTIONS = { variant: 'ZK' } // proofs are `bb prove --zk`; Kurier rejects ultrahonk calls without a variant
const key = () => {
  const k = process.env.KURIER_API_KEY
  if (!k) throw new KurierError('KURIER_API_KEY not set', 'config')
  return k
}
const scrub = (s) => (process.env.KURIER_API_KEY ? String(s).split(process.env.KURIER_API_KEY).join('[KEY]') : String(s))

export class KurierError extends Error {
  constructor(msg, kind = 'kurier', status) { super(scrub(msg)); this.kind = kind; this.status = status }
}

async function api(method, path, body) {
  let r
  try {
    r = await fetch(`${BASE}/${path}`, { method, headers: { 'content-type': 'application/json' }, body: body && JSON.stringify(body), signal: AbortSignal.timeout(20_000) })
  } catch (e) { throw new KurierError(`network: ${e.message}`, 'network') }
  const text = await r.text()
  let json
  try { json = JSON.parse(text) } catch { json = { raw: text.slice(0, 200) } }
  return { status: r.status, json: JSON.parse(scrub(JSON.stringify(json))) }
}

/** POST /register-vk. Returns the vkHash; a 400 "already registered" carries it in meta.vkHash. */
export async function registerVk(vkHex) {
  const { status, json } = await api('POST', `register-vk/${key()}`, { proofType: 'ultrahonk', proofOptions: OPTIONS, vk: vkHex })
  const vkHash = json.vkHash ?? json.meta?.vkHash
  if (!vkHash) throw new KurierError(`register-vk HTTP ${status}: ${json.code ?? ''} ${json.message ?? ''}`, 'kurier', status)
  return vkHash
}

/** POST /submit-proof. pubs: 7 bigint. chainId only when the caller wants aggregation. Returns the jobId. */
export async function submitProof({ proofHex, pubs, vkHash, chainId }) {
  const body = { proofType: 'ultrahonk', proofOptions: OPTIONS, vkRegistered: true, proofData: { proof: proofHex, publicSignals: pubs.map(hex32), vk: vkHash } }
  if (chainId) body.chainId = chainId
  const { status, json } = await api('POST', `submit-proof/${key()}`, body)
  if (!json.jobId) throw new KurierError(`submit-proof HTTP ${status}: ${json.code ?? ''} ${json.message ?? ''}`, 'kurier', status)
  return { jobId: json.jobId, optimisticVerify: json.optimisticVerify }
}

/** GET /job-status. Returns the scrubbed JSON ({status, txHash, txExplorerUrl, statement, aggregationId, aggregationDetails, aggregationPublished, errorDetails}). */
export async function jobStatus(jobId) {
  if (!/^[A-Za-z0-9-]{1,80}$/.test(jobId)) throw new KurierError('bad jobId', 'input', 400)
  const { status, json } = await api('GET', `job-status/${key()}/${jobId}`)
  if (status !== 200) throw new KurierError(`job-status HTTP ${status}: ${json.message ?? json.raw ?? ''}`, 'kurier', status)
  return json
}

// Lifecycle: Queued → Valid → Submitted → IncludedInBlock → Finalized [→ AggregationPending → Aggregated];
// aggregationPublished.destinationTxHash is a field, not a status. Any step can end in Failed.
export const ORDER = ['Queued', 'Valid', 'Submitted', 'IncludedInBlock', 'Finalized', 'AggregationPending', 'Aggregated']
export const isFailed = (j) => j.status === 'Failed'
export const isFinalized = (j) => ORDER.indexOf(j.status) >= ORDER.indexOf('Finalized')
export const isPublished = (j) => Boolean(j.aggregationPublished?.destinationTxHash)
/** True when a job's record should be updated: a terminal or post-finality status. */
export const isSettled = (j) => isFailed(j) || isFinalized(j)

export const hex32 = (p) => '0x' + BigInt(p).toString(16).padStart(64, '0')

// --- zkVerify statement (leaf) math, ported from G0 ---
const H = (b) => getBytes(keccak256(b))
const S = (b) => getBytes(sha256(b))
const cat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)))
const CTX = H(Buffer.from('ultrahonk')) // pallet hash_context_data()
export const VERSION = {
  Legacy: S(new Uint8Array(0)), // pallet NO_VERSION_HASH == sha256("") (proved by the G0 self-test vector)
  V0_84: S(Buffer.from('ultrahonk:v0.84')),
  V3_0: S(Buffer.from('ultrahonk:v3.0')),
}
// compute_statement_hash: keccak(keccak(ctx) ‖ vkHash ‖ versionHash ‖ keccak(pubs_bytes))
export const leaf = (vkHash, versionHash, pubsBytes) => H(cat(CTX, vkHash, versionHash, H(pubsBytes)))
// Ultrahonk::vk_hash: Legacy = sha256(raw vk); V0_84 / V3_0 = keccak(SCALE enum index byte ‖ raw vk)
export const vkHashes = (vk) => ({ Legacy: S(vk), V0_84: H(cat([0], vk)), V3_0: H(cat([1], vk)) })
const pubsBytes = (pubs) => cat(...pubs.map((p) => getBytes(hex32(p))))
const hx = (b) => '0x' + Buffer.from(b).toString('hex')

/** Every (vkHash, versionHash) rule the pallet might apply; the one whose leaf equals Kurier's statement is the real one. */
export function leafCandidates(vkBytes, pubs, kurierVkHash) {
  const pb = pubsBytes(pubs)
  const vh = vkHashes(getBytes(vkBytes))
  const out = Object.keys(VERSION).map((v) => ({ name: `${v}`, vkHash: hx(vh[v]), leaf: hx(leaf(vh[v], VERSION[v], pb)) }))
  if (kurierVkHash) for (const [v, vhash] of Object.entries(VERSION)) out.push({ name: `kurierVkHash+${v}`, vkHash: kurierVkHash, leaf: hx(leaf(getBytes(kurierVkHash), vhash, pb)) })
  return out
}

/** The candidate matching a statement, or undefined. */
export const matchStatement = (vkBytes, pubs, kurierVkHash, statement) =>
  statement && leafCandidates(vkBytes, pubs, kurierVkHash).find((c) => c.leaf === statement.toLowerCase())
