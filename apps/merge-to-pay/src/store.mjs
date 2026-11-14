// Durable JSON records on the service volume (DATA_DIR, default /data): prs/<repo>__<pr>.json, jobs/<jobId>.json,
// daily/<YYYY-MM-DD>.json. Atomic write-rename, stdlib only. Single process, so no cross-process locking.
import { readFileSync, writeFileSync, renameSync, mkdirSync, unlinkSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const dir = () => process.env.DATA_DIR || '/data'
const safe = (id) => String(id).replace(/[^A-Za-z0-9._-]/g, '_')
const path = (kind, id) => join(dir(), kind, `${safe(id)}.json`)

export const prKey = ({ repo, pr }) => `${repo.replace('/', '__')}__${pr}`

export function read(kind, id) {
  try { return JSON.parse(readFileSync(path(kind, id), 'utf8')) } catch (e) { if (e.code === 'ENOENT') return undefined; throw e }
}

export function write(kind, id, obj) {
  const p = path(kind, id)
  mkdirSync(join(dir(), kind), { recursive: true })
  writeFileSync(`${p}.tmp`, JSON.stringify(obj))
  renameSync(`${p}.tmp`, p)
  return obj
}

export function remove(kind, id) {
  try { unlinkSync(path(kind, id)) } catch (e) { if (e.code !== 'ENOENT') throw e }
}

/** Every stored id of a kind (file names without .json). */
export function list(kind) {
  try { return readdirSync(join(dir(), kind)).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5)) } catch (e) { if (e.code === 'ENOENT') return []; throw e }
}

export const today = () => new Date().toISOString().slice(0, 10)
export const dailyCap = () => Number(process.env.DAILY_CAP || 50)
export const dailyCount = () => read('daily', today())?.count ?? 0

/** Reserve one fresh run for today; false when the cap is reached. */
export function takeDailySlot() {
  const n = dailyCount()
  if (n >= dailyCap()) return false
  write('daily', today(), { count: n + 1 })
  return true
}
