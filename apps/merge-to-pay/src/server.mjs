// HTTP surface (node:http, no framework). POST /api/agent, GET /api/agent, GET /api/recent, GET /api/job?id=, GET /health, GET /.
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { run, RunError, jobUpdate, config, settlePending } from './run.mjs'
import * as prover from './prover.mjs'
import * as store from './store.mjs'

const INDEX = new URL('../public/index.html', import.meta.url).pathname
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)) }
const errBody = (e) => (e instanceof RunError ? { decision: 'ERROR', reason: e.reason, message: e.message } : { decision: 'ERROR', reason: 'INTERNAL', message: e.message })
const errStatus = (e) => (e instanceof RunError ? e.status : 500)

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = ''
    req.setEncoding('utf8')
    req.on('data', (c) => { raw += c; if (raw.length > 8192) { reject(new RunError(413, 'BODY_TOO_LARGE', 'body over 8 KB')); req.destroy() } })
    req.on('end', () => resolve(raw))
    req.on('error', reject)
  })
}

/** `{"pr":"…"}`, `"o/r#N"` or a raw `o/r#N` / PR URL, whatever the Content-Type (M6). */
export function refOf(raw) {
  const text = raw.trim()
  try {
    const j = JSON.parse(text)
    if (typeof j === 'string') return j
    if (j && typeof j.pr === 'string') return j.pr
  } catch { /* not JSON: the raw text is the reference */ }
  return text
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://x')
  const route = `${req.method} ${url.pathname}`
  try {
    if (route === 'GET /health') return json(res, 200, { ok: true, busy: prover.busy, daily: { used: store.dailyCount(), cap: store.dailyCap() } })
    if (route === 'GET /') {
      let html
      try { html = readFileSync(INDEX) } catch { return json(res, 404, { error: 'no public/index.html' }) }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      return res.end(html)
    }
    if (route === 'GET /api/agent') return json(res, 200, config())
    if (route === 'GET /api/recent') {
      const recs = store.list('prs').map((k) => store.read('prs', k)).filter(Boolean).sort((a, b) => (b.provedAt || '').localeCompare(a.provedAt || '')).slice(0, 20)
      return json(res, 200, recs.map(({ decision, reason, facts, zkverify, aggregation, payout, provedAt, timings }) =>
        ({ decision, reason, facts, provedAt, timings, zkverify: { jobId: zkverify.jobId, status: zkverify.status, txHash: zkverify.txHash, explorer: zkverify.explorer }, aggregation, payout })))
    }
    if (route === 'GET /api/job') {
      const id = url.searchParams.get('id')
      if (!id) throw new RunError(400, 'BAD_JOB', 'id required')
      return json(res, 200, await jobUpdate(id))
    }
    if (route === 'POST /api/agent') {
      const ref = refOf(await readBody(req))
      const opts = { retry: url.searchParams.get('retry') === '1' }
      if (!/application\/x-ndjson/.test(req.headers.accept || '')) return json(res, 200, await run(ref, opts))
      res.writeHead(200, { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store' })
      const line = (o) => res.write(JSON.stringify(o) + '\n')
      opts.onStep = (step, detail) => line({ step, ...(detail && { detail }), t: Date.now() })
      try { line(await run(ref, opts)) } catch (e) { line({ ...errBody(e), httpStatus: errStatus(e) }) }
      return res.end()
    }
    json(res, 404, { error: 'not found' })
  } catch (e) {
    if (!(e instanceof RunError)) console.error(e)
    if (!res.headersSent) json(res, errStatus(e), errBody(e))
    else res.end()
  }
}

export const createApp = () => createServer(handle)

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const port = Number(process.env.PORT || 8080)
  createApp().listen(port, '0.0.0.0', () => console.log(`merge-to-pay listening on :${port}, DATA_DIR=${process.env.DATA_DIR || '/data'}`))
  // ponytail: one in-process sweep a minute; a queue only if one relayer can't keep up
  if (process.env.ESCROW_ADDRESS && process.env.RELAYER_PRIVATE_KEY) setInterval(() => settlePending().catch((e) => console.error('settle', e)), 60_000)
}
