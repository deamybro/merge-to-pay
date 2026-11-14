// Sign one attestor auth token offline (M3): the server holds only this token, never the auth key.
// Usage: node scripts/make-auth-token.mjs <auth-private-key-file> <out-token-file>
// Prints only the public key (AUTHENTICATION_PUBLIC_KEY for the attestor) and the expiry.
import { readFileSync, writeFileSync } from 'node:fs'
import { SigningKey } from 'ethers'
import { createAuthRequest, proto } from '@reclaimprotocol/attestor-core'
const { AuthenticationRequest } = proto

export const USER = { id: 'verity-merge-to-pay', hostWhitelist: ['api.github.com'], expiresAt: Math.floor(Date.UTC(2026, 11, 31, 23, 59, 59) / 1000) }

/** base64(proto AuthenticationRequest) <-> the authRequest object VerityClient passes to the attestor. */
export const encodeAuthToken = (req) => Buffer.from(AuthenticationRequest.encode(req).finish()).toString('base64')
export const decodeAuthToken = (b64) => AuthenticationRequest.decode(Buffer.from(b64, 'base64'))

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [keyFile, outFile] = process.argv.slice(2)
  if (!keyFile || !outFile) throw new Error('usage: make-auth-token.mjs <key-file> <out-file>')
  const key = readFileSync(keyFile, 'utf8').trim().split('=').pop() // bare hex, or NAME=hex
  const req = await createAuthRequest(USER, key)
  const token = encodeAuthToken(req)
  if (decodeAuthToken(token).data.id !== USER.id) throw new Error('token round-trip failed')
  writeFileSync(outFile, token + '\n', { mode: 0o600 })
  console.log(`AUTHENTICATION_PUBLIC_KEY=${SigningKey.computePublicKey(key, true)}`)
  console.log(`expires ${new Date(USER.expiresAt * 1000).toISOString()}; token written to ${outFile} (0600)`)
}
