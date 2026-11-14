// Emit the constant claim-template bytes the circuit hard-codes, derived from src/spec.mjs.
// Usage: node scripts/gen-template.mjs  (JSON on stdout)
import { template } from '../src/spec.mjs'

const t = template()
const bytes = (s) => Buffer.byteLength(s)
console.log(JSON.stringify({
  ...t,
  lengths: {
    head: bytes(t.head), issues: bytes(t.issues), mid: bytes(t.mid), tail: bytes(t.tail),
    ctx: Object.fromEntries(Object.entries(t.ctx).map(([k, v]) => [k, bytes(v)])),
  },
}, null, 2))
