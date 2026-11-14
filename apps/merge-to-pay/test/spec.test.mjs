// Spec checks against real fixtures: raw GitHub issue JSON + the real attestor responses
// (test/fixtures/*, proven through Reclaim's public attestor; dev fixtures only).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import canonicalize from 'canonicalize'
import { keccak256, toUtf8Bytes, verifyMessage } from 'ethers'
import { REGEX, parsePr, request, parameters, template, assemble } from '../src/spec.mjs'

const dir = new URL('./fixtures/', import.meta.url)
const names = readdirSync(dir).filter((f) => f.endsWith('.proof.json')).map((f) => f.replace('.proof.json', ''))
const fixtures = names.map((n) => ({
  name: n,
  proof: JSON.parse(readFileSync(new URL(`${n}.proof.json`, dir), 'utf8')),
  issue: readFileSync(new URL(`${n}.issue.json`, dir), 'utf8'),
}))
assert.equal(fixtures.length, 3)

const claimString = (c) => `${c.provider}\n${c.parameters}\n${c.context}`
const signData = (c) => `${c.identifier}\n${c.owner.toLowerCase()}\n${c.timestampS}\n${c.epoch}`
const hasPayoutLine = (ctx) => 'issue' in JSON.parse(ctx).extractedParameters

for (const { name, proof, issue } of fixtures) {
  const { claim, signatures, slots } = proof

  test(`${name}: regex groups on the raw issue JSON match the attestor's extractedParameters`, () => {
    assert.equal(issue.split('"merged_at":').length - 1, 1, 'exactly one "merged_at" anchor')
    const m = new RegExp(REGEX, 'si').exec(issue) // same flags as attestor-core's RegExp path
    assert.ok(m, 'regex matches')
    const groups = Object.fromEntries(Object.entries(m.groups).filter(([, v]) => typeof v === 'string'))
    assert.deepEqual(groups, JSON.parse(claim.context).extractedParameters)
    assert.equal(groups.mergedAt, JSON.stringify(JSON.parse(issue).pull_request.merged_at))
    assert.equal(hasPayoutLine(claim.context), false, 'these PRs carry no payout line')
    assert.equal(m.groups.issue, undefined, 'unmatched optional group is undefined, not ""')
  })

  test(`${name}: claim parameters are byte-equal to spec, and the claim assembles from the template`, () => {
    assert.equal(claim.provider, 'http')
    assert.equal(claim.parameters, parameters(slots))
    const ctx = JSON.parse(claim.context)
    assert.equal(assemble({ ...slots, ...ctx.extractedParameters, providerHash: ctx.providerHash }), claimString(claim))
  })

  test(`${name}: keccak256(provider\\nparameters\\ncanonical(context)) == identifier`, () => {
    assert.equal(canonicalize(JSON.parse(claim.context)), claim.context)
    assert.equal(keccak256(toUtf8Bytes(claimString(claim))), claim.identifier)
  })

  test(`${name}: claim signature recovers to the reported attestor`, () => {
    assert.equal(String(claim.timestampS).length, 10)
    assert.equal(claim.epoch, 1)
    assert.equal(verifyMessage(signData(claim), signatures.claimSignature).toLowerCase(), signatures.attestorAddress.toLowerCase())
  })

  test(`${name}: one tampered context byte breaks the identifier and the signature`, () => {
    const context = claim.context.replace('providerHash":"0x', 'providerHash":"0y')
    assert.notEqual(context, claim.context)
    const identifier = keccak256(toUtf8Bytes(claimString({ ...claim, context })))
    assert.notEqual(identifier, claim.identifier)
    assert.notEqual(verifyMessage(signData({ ...claim, identifier }), signatures.claimSignature).toLowerCase(), signatures.attestorAddress.toLowerCase())
  })
}

test('gen-template.mjs output equals template() from spec.mjs', () => {
  const out = JSON.parse(execFileSync(process.execPath, [new URL('../scripts/gen-template.mjs', import.meta.url).pathname]))
  const { lengths, ...pieces } = out
  assert.deepEqual(pieces, template())
  assert.equal(lengths.head, Buffer.byteLength(template().head))
})

test('parser: accepts both PR forms, lowercases owner/repo', () => {
  assert.deepEqual(parsePr('https://github.com/NodeJS/Node/pull/49999'), { repo: 'nodejs/node', pr: 49999 })
  assert.deepEqual(parsePr('https://github.com/nodejs/node/pull/49999/'), { repo: 'nodejs/node', pr: 49999 })
  assert.deepEqual(parsePr('Microsoft/TypeScript#62000'), { repo: 'microsoft/typescript', pr: 62000 })
  assert.equal(request({ repo: 'nodejs/node', pr: 49999 }).url, 'https://api.github.com/repos/nodejs/node/issues/49999')
})

test('parser: rejects uppercase repo slots, bad refs, bad numbers, over-long repos', () => {
  assert.throws(() => request({ repo: 'Microsoft/TypeScript', pr: 1 }), /lowercase/)
  assert.throws(() => parameters({ repo: 'nodejs/Node', pr: 1 }), /lowercase/)
  for (const bad of ['https://github.com/nodejs/node/issues/49999', 'http://github.com/nodejs/node/pull/1', 'nodejs/node', 'nodejs/node#0', 'nodejs/node#01', 'a/b/c#1', 'nodejs/node#1234567890', 'https://github.com/nodejs/node/pull/1?x=1', '']) {
    assert.throws(() => parsePr(bad), undefined, `should reject ${JSON.stringify(bad)}`)
  }
  assert.throws(() => parsePr(`${'a'.repeat(40)}/repo#1`), /bad repo/)
  assert.throws(() => parsePr(`owner/${'a'.repeat(101)}#1`), /bad repo/)
  assert.throws(() => parsePr('ow ner/repo#1'), /bad repo/)
  assert.equal(parsePr(`${'a'.repeat(39)}/${'b'.repeat(100)}#1`).repo.length, 140)
})

test('regex rule: no "." and no negated class (both could match redacted "*" bytes)', () => {
  assert.doesNotMatch(REGEX, /\.|\[\^/)
})
