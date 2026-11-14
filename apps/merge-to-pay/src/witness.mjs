// Circuit inputs for github_pr from a signed claim (a test fixture or a live SDK proof).
// Re-checks in JS that keccak(claim) == identifier and ecrecover == attestor before emitting anything.
import { SigningKey, hashMessage, keccak256, toUtf8Bytes, getBytes, recoverAddress } from 'ethers'
import { URL_PREFIX, parameters, assemble } from './spec.mjs'

const bytes = (s) => Array.from(Buffer.from(s, 'utf8'))
const pad = (arr, n) => arr.concat(Array(n - arr.length).fill(0))

/** `${identifier}\n${owner}\n${timestampS}\n1`: the 122-byte message the attestor signs (EIP-191). */
export const signedMessage = (claim) => `${claim.identifier}\n${claim.owner.toLowerCase()}\n${claim.timestampS}\n${claim.epoch}`

/** Slots of a claim, checked byte-for-byte against the template. Throws on any mismatch. */
export function slots({ claim }) {
  const url = JSON.parse(claim.parameters).url
  const m = /^(.+)\/issues\/([0-9]+)$/.exec(url.slice(URL_PREFIX.length))
  if (!url.startsWith(URL_PREFIX) || !m) throw new Error(`url is not the template: ${url}`)
  const [repo, pr] = [m[1], Number(m[2])]
  if (claim.provider !== 'http' || claim.parameters !== parameters({ repo, pr })) throw new Error('parameters differ from spec.mjs')
  const ctx = JSON.parse(claim.context)
  const { mergedAt, issue, payee } = ctx.extractedParameters
  const full = assemble({ repo, pr, mergedAt, issue, payee, providerHash: ctx.providerHash })
  if (full !== `${claim.provider}\n${claim.parameters}\n${claim.context}`) throw new Error('claim does not assemble from the template')
  if (keccak256(toUtf8Bytes(full)) !== claim.identifier) throw new Error('keccak256(claim) != identifier')
  if (claim.epoch !== 1 || !/^[0-9]{10}$/.test(String(claim.timestampS))) throw new Error('epoch must be 1 and timestampS 10 digits')
  return { repo, pr, mergedAt, issue, payee, providerHash: ctx.providerHash }
}

/** noir_js input map + the 7 expected public inputs (as bigint), or throws. */
export function witness({ claim, signatures }) {
  const s = slots({ claim })
  const digest = hashMessage(signedMessage(claim))
  const sig = getBytes(signatures.claimSignature)
  if (sig.length !== 65) throw new Error('claimSignature must be 65 bytes')
  const attestor = recoverAddress(digest, signatures.claimSignature).toLowerCase()
  if (attestor !== signatures.attestorAddress.toLowerCase()) throw new Error(`ecrecover ${attestor} != attestor ${signatures.attestorAddress}`)
  const pub = getBytes(SigningKey.recoverPublicKey(digest, signatures.claimSignature)) // 0x04 || X || Y
  const merged = s.mergedAt !== 'null'
  const payout = s.issue !== undefined
  const inputs = {
    repo: pad(bytes(s.repo), 140),
    repo_len: String(s.repo.length),
    pr: pad(bytes(String(s.pr)), 9),
    pr_len: String(String(s.pr).length),
    merged,
    merged_at: merged ? bytes(s.mergedAt.slice(1, -1)) : Array(20).fill(0),
    payout,
    issue: payout ? pad(bytes(s.issue), 9) : Array(9).fill(0),
    issue_len: payout ? String(s.issue.length) : '0',
    payee: payout ? bytes(s.payee.slice(2)) : Array(40).fill(0),
    provider_hash: bytes(s.providerHash.slice(2)),
    owner: bytes(claim.owner.toLowerCase().slice(2)),
    ts: bytes(String(claim.timestampS)),
    pub_x: Array.from(pub.slice(1, 33)),
    pub_y: Array.from(pub.slice(33, 65)),
    sig: Array.from(sig.slice(0, 64)),
  }
  const pubs = [
    BigInt(attestor),
    BigInt(keccak256(toUtf8Bytes(s.repo))) >> 8n,
    BigInt(s.pr),
    merged ? 1n : 0n,
    payout ? BigInt(s.issue) : 0n,
    payout ? BigInt(s.payee) : 0n,
    BigInt(claim.timestampS),
  ]
  return { inputs, pubs }
}

/** Prover.toml text for `nargo execute`. */
export const toToml = (inputs) => Object.entries(inputs)
  .map(([k, v]) => `${k} = ${Array.isArray(v) ? `[${v.join(', ')}]` : typeof v === 'string' ? `"${v}"` : v}`)
  .join('\n') + '\n'

/** 32-byte big-endian concatenation, the layout of bb's public_inputs file and zkVerify's pubs_bytes. */
export const pubsBytes = (pubs) => Buffer.concat(pubs.map((p) => Buffer.from(p.toString(16).padStart(64, '0'), 'hex')))
