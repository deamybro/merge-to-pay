// Merge-to-Pay zkTLS spec — the single source of truth for the request the attestor signs.
// gen-template.mjs (and from it the Noir circuit) derive every constant byte from here.
// Regex meaning assumes the contiguous matching path: requires attestor clients >= 3.2.0.
import canonicalize from 'canonicalize'

export const PROVIDER = 'http'
export const URL_PREFIX = 'https://api.github.com/repos/'
// User-Agent is set here (not left to attestor-core's default) so the template never drifts.
export const HEADERS = {
  'Accept-Encoding': 'identity',
  'User-Agent': 'reclaim/0.0.1',
  'X-GitHub-Api-Version': '2022-11-28',
}

// Anchored on the only "merged_at" key in the issue view of a PR, contiguous through `},"body":`
// and an optional leading payout line. Attestors run it case-insensitively over text where
// redacted bytes are '*', so it must contain no '.' and no negated class (either could match '*').
export const REGEX = String.raw`"merged_at":(?<mergedAt>null|"[0-9TZ:-]{20}")\},"body":"?(?:verity-payout: #(?<issue>[1-9][0-9]{0,8}) (?<payee>0x[0-9a-fA-F]{40}))?`
if (/\.|\[\^/.test(REGEX)) throw new Error('REGEX must not contain "." or a negated class')

// Lowercase only (GitHub paths are case-insensitive; the circuit enforces lowercase).
// owner <= 39, name <= 100, so the repo string is at most 140 bytes.
const REPO_RE = /^[a-z0-9._-]{1,39}\/[a-z0-9._-]{1,100}$/
const PR_RE = /^[1-9][0-9]{0,8}$/
const REF_RE = /^(?:https:\/\/github\.com\/([^/]+)\/([^/]+)\/pull\/([0-9]+)\/?|([^/#]+)\/([^/#]+)#([0-9]+))$/

/** 'https://github.com/o/r/pull/N' or 'o/r#N' -> { repo: 'o/r' (lowercased), pr: N } */
export function parsePr(ref) {
  const m = REF_RE.exec(String(ref).trim())
  if (!m) throw new Error(`not a GitHub PR reference: ${ref}`)
  const [owner, name, num] = m[1] ? [m[1], m[2], m[3]] : [m[4], m[5], m[6]]
  const repo = `${owner}/${name}`.toLowerCase()
  if (!REPO_RE.test(repo)) throw new Error(`bad repo: ${owner}/${name}`)
  if (!PR_RE.test(num)) throw new Error(`bad PR number: ${num}`)
  return { repo, pr: Number(num) }
}

function assertSlots({ repo, pr }) {
  if (!REPO_RE.test(repo)) throw new Error(`repo must be lowercase [a-z0-9._-], owner/name: ${repo}`)
  if (!PR_RE.test(String(pr))) throw new Error(`bad PR number: ${pr}`)
}

/** The exact prove() arguments for VerityClient. */
export function request({ repo, pr }) {
  assertSlots({ repo, pr })
  return {
    url: `${URL_PREFIX}${repo}/issues/${pr}`,
    method: 'GET',
    headers: HEADERS,
    matches: [{ type: 'regex', value: REGEX }],
    redactions: [{ regex: REGEX }],
  }
}

/** The claim `parameters` string the attestor signs (canonical JSON, sorted keys). */
export function parameters({ repo, pr }) {
  const { url, method, headers, matches, redactions } = request({ repo, pr })
  return canonicalize({ url, method, headers, responseMatches: matches, responseRedactions: redactions })
}

// Claim bytes = HEAD ‖ repo ‖ ISSUES ‖ prDigits ‖ MID ‖ ctx ‖ TAIL, where ctx is
//   [CTX.issue ‖ issueDigits ‖ CTX.mergedAtAfterIssue | CTX.mergedAt] ‖ mergedAtJson
//   [‖ CTX.payee ‖ payeeHex] ‖ CTX.providerHash ‖ providerHashHex
// mergedAtJson is the JSON-escaped group: `null` (4 bytes) or `\"` + 20 chars + `\"` (24 bytes).
// Unmatched optional groups are absent from the context (attestor-core drops non-string groups).
export function template() {
  const p = parameters({ repo: 'o/r', pr: 1 })
  const i = p.indexOf(`"url":"${URL_PREFIX}`)
  const head = `${PROVIDER}\n${p.slice(0, i + 7 + URL_PREFIX.length)}`
  if (p.slice(i + 7 + URL_PREFIX.length) !== 'o/r/issues/1"}') throw new Error('unexpected parameters layout')
  return {
    head,
    issues: '/issues/',
    mid: '"}\n{"extractedParameters":{',
    ctx: {
      issue: '"issue":"',
      mergedAtAfterIssue: '","mergedAt":"',
      mergedAt: '"mergedAt":"',
      payee: '","payee":"',
      providerHash: '"},"providerHash":"',
    },
    tail: '"}',
    regex: REGEX,
  }
}

/** Rebuild the full signed claim string from its slots (what the circuit does in-circuit). */
export function assemble({ repo, pr, mergedAt, issue, payee, providerHash }) {
  assertSlots({ repo, pr })
  const t = template()
  const m = JSON.stringify(mergedAt).slice(1, -1) // `null` or `\"…\"`, the quotes around it are in the pieces
  const ctx = issue !== undefined
    ? `${t.ctx.issue}${issue}${t.ctx.mergedAtAfterIssue}${m}${t.ctx.payee}${payee}`
    : `${t.ctx.mergedAt}${m}`
  return `${t.head}${repo}${t.issues}${pr}${t.mid}${ctx}${t.ctx.providerHash}${providerHash}${t.tail}`
}
