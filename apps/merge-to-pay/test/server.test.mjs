// Server on a random port with a temp DATA_DIR: routing, body parsing (JSON without Content-Type, raw o/r#N),
// the 422 classify path against real api.github.com, the 503 busy path of the prover mutex, and a stored
// merged result returned without re-proving. No attestor, bb or Kurier is reached from here.
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), 'm2p-srv-'))
process.env.PROVER_WAIT_MS = '300'
delete process.env.KURIER_API_KEY
const { createApp, refOf } = await import('../src/server.mjs')
const { withLock } = await import('../src/prover.mjs')
const store = await import('../src/store.mjs')
const { witness } = await import('../src/witness.mjs')
const { hex32 } = await import('../src/kurier.mjs')

const app = createApp()
let base
before(() => new Promise((r) => app.listen(0, '127.0.0.1', () => { base = `http://127.0.0.1:${app.address().port}`; r() })))
after(() => app.close())

const post = async (body, { headers = {}, path = '/api/agent' } = {}) => {
  const r = await fetch(base + path, { method: 'POST', body, headers })
  const text = await r.text()
  return { status: r.status, text, json: r.headers.get('content-type')?.includes('application/json') ? JSON.parse(text) : null }
}
const get = async (path) => { const r = await fetch(base + path); return { status: r.status, json: await r.json() } }

test('refOf: JSON object, JSON string, raw text', () => {
  assert.equal(refOf('{"pr":"nodejs/node#1"}'), 'nodejs/node#1')
  assert.equal(refOf(' "nodejs/node#1" '), 'nodejs/node#1')
  assert.equal(refOf('nodejs/node#1\n'), 'nodejs/node#1')
  assert.equal(refOf('https://github.com/nodejs/node/pull/1'), 'https://github.com/nodejs/node/pull/1')
})

test('GET /health, GET /api/agent, 404', async () => {
  const h = await get('/health')
  assert.equal(h.status, 200)
  assert.deepEqual(h.json, { ok: true, busy: false, daily: { used: 0, cap: 50 } })
  const c = await get('/api/agent')
  assert.equal(c.status, 200)
  assert.equal(c.json.chainId, 8453)
  assert.match(c.json.statement, /zkVerify/)
  assert.equal((await get('/nope')).status, 404)
})

test('bad reference -> 400, nothing proven', async () => {
  const r = await post('nodejs/node', {})
  assert.equal(r.status, 400)
  assert.equal(r.json.reason, 'BAD_REF')
})

test('422 classify path against real api.github.com: nodejs/node#49998 is an issue, not a PR', async () => {
  // raw o/r#N, no Content-Type
  const raw = await post('nodejs/node#49998')
  assert.equal(raw.status, 422, raw.text)
  assert.deepEqual([raw.json.decision, raw.json.reason], ['ERROR', 'NOT_A_PR'])
  // JSON body with a form Content-Type (what `curl -d` sends)
  const form = await post('{"pr":"https://github.com/nodejs/node/pull/49998"}', { headers: { 'content-type': 'application/x-www-form-urlencoded' } })
  assert.equal(form.status, 422, form.text)
  assert.equal(form.json.reason, 'NOT_A_PR')
  // ndjson: progress lines, then the final line carries the HTTP status
  const nd = await post('nodejs/node#49998', { headers: { accept: 'application/x-ndjson' } })
  const lines = nd.text.trim().split('\n').map((l) => JSON.parse(l))
  assert.equal(lines[0].step, 'classify')
  assert.deepEqual([lines.at(-1).reason, lines.at(-1).httpStatus], ['NOT_A_PR', 422])
  assert.equal((await get('/health')).json.daily.used, 0, 'no fresh run was counted')
})

test('422 NOT_FOUND for a PR number that does not exist', async () => {
  const r = await post('{"pr":"nodejs/node#999999999"}')
  assert.equal(r.status, 422, r.text)
  assert.equal(r.json.reason, 'NOT_FOUND')
})

test('503 busy while another proof holds the mutex; the daily counter is untouched', async () => {
  let release
  const held = withLock(() => new Promise((r) => { release = r }), 60_000)
  const t0 = Date.now()
  const r = await post('nodejs/node#50000') // a real merged PR, not stored: would start a fresh run
  assert.equal(r.status, 503, r.text)
  assert.deepEqual([r.json.decision, r.json.reason], ['ERROR', 'BUSY'])
  assert.ok(Date.now() - t0 < 5000)
  assert.equal((await get('/health')).json.busy, true)
  assert.equal((await get('/health')).json.daily.used, 0)
  release()
  await held
  assert.equal((await get('/health')).json.busy, false)
})

test('a stored merged result is returned without re-proving (C1c), even while the prover is busy', async () => {
  const fx = JSON.parse(readFileSync(new URL('./fixtures/nodejs-node-49999.proof.json', import.meta.url), 'utf8'))
  const { pubs } = witness(fx)
  const rec = { decision: 'DECLINE', reason: 'NO_PAYOUT_LINE', facts: { repo: 'nodejs/node', pr: 49999, merged: true, issue: null, payee: null },
    zktls: { attestor: fx.attestor, claim: fx.claim }, zkverify: { jobId: 'job-1', status: 'Finalized', publicInputs: pubs.map(hex32) } }
  store.write('prs', store.prKey({ repo: 'nodejs/node', pr: 49999 }), rec)
  let release
  const held = withLock(() => new Promise((r) => { release = r }), 60_000)
  const r = await post('https://github.com/NodeJS/node/pull/49999', { headers: { 'content-type': 'application/json' } })
  assert.equal(r.status, 200, r.text)
  assert.deepEqual(r.json, { ...rec, cached: true })
  const nd = await post('nodejs/node#49999', { headers: { accept: 'application/x-ndjson' } })
  assert.equal(JSON.parse(nd.text.trim()).cached, true, 'cached result is one ndjson line')
  release()
  await held
  assert.equal((await get('/health')).json.daily.used, 0)
})

test('expired NOT_MERGED record is ignored; ?retry=1 ignores an unexpired one (M7)', async () => {
  const key = store.prKey({ repo: 'nodejs/node', pr: 49998 })
  store.write('prs', key, { decision: 'DECLINE', reason: 'NOT_MERGED', expiresAt: Date.now() - 1 })
  assert.equal((await post('nodejs/node#49998')).status, 422, 'expired record: goes to classify again')
  store.write('prs', key, { decision: 'DECLINE', reason: 'NOT_MERGED', expiresAt: Date.now() + 600_000 })
  assert.equal((await post('nodejs/node#49998')).json.reason, 'NOT_MERGED', 'fresh record is served')
  assert.equal((await post('nodejs/node#49998', { path: '/api/agent?retry=1' })).status, 422, 'retry skips it')
  store.remove('prs', key)
})

test('GET /api/job: id required; without a Kurier key the re-poll is a 502, not a decision', async () => {
  assert.equal((await get('/api/job')).status, 400)
  const r = await get('/api/job?id=abc')
  assert.equal(r.status, 502)
  assert.equal(r.json.decision, 'ERROR')
  assert.equal((await get('/api/job?id=../x')).status, 400)
})
