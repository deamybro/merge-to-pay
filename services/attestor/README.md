# Verity attestor

The witness that opens the TLS connection to a data source, verifies the client's
zero-knowledge proof of the response, and signs the resulting claim with its key.
Verifiers trust proofs signed by this attestor's address.

Built from [`reclaimprotocol/attestor-core`](https://github.com/reclaimprotocol/attestor-core)
pinned to commit `dd43dc8` plus `min-client-version.patch` (refuses clients older than
3.2.0), run under our own signing key. Set `AUTHENTICATION_PUBLIC_KEY` to accept only
clients holding a signed auth request.

## Run locally

```bash
git clone https://github.com/reclaimprotocol/attestor-core.git
cd attestor-core && git checkout dd43dc882b88dcfe75d27a1c1a991315574823ab
git apply ../services/attestor/min-client-version.patch
npm install --ignore-scripts
npm rebuild re2             # builds the native re2 addon (optional; falls back to RegExp)
PRIVATE_KEY=$(node -e "console.log(require('ethers').Wallet.createRandom().privateKey)")
PORT=8001 PRIVATE_KEY=$PRIVATE_KEY node --experimental-strip-types src/scripts/start-server.ts
```

The server listens on `ws://localhost:8001/ws`. Point the SDK at it via
`VERITY_ATTESTOR_URL=ws://localhost:8001/ws`.

Or with Docker:

```bash
docker build -t verity-attestor services/attestor
docker run -e PRIVATE_KEY=0x... -e PORT=8001 -p 8001:8001 verity-attestor
```

## Deploy on Railway

Deploy this folder as its own service (it has a Dockerfile and `railway.json`):

```bash
cd services/attestor
railway up --service attestor
```

Set `PRIVATE_KEY` (the signing key — generate it locally, never commit it),
`AUTHENTICATION_PUBLIC_KEY` (from `apps/merge-to-pay/scripts/make-auth-token.mjs`) and
`PORT=8001` as service variables, then give the service a public domain. Clients
connect at `wss://<domain>/ws`.

Record the attestor's **address** (printed on boot as `signerAddress`) — that is the
value verifiers and the on-chain verifier contract must trust.
