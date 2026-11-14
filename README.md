# Merge-to-Pay

**An agent that pays GitHub bounties in USDC on Base, and only after zkVerify has verified a zero-knowledge proof that GitHub itself reported the pull request as merged.**

A maintainer locks USDC against an issue. A contributor opens a PR whose description starts with a payout line. When the maintainer merges it, anyone can hand the PR to the agent. The agent proves what `api.github.com` said, gets the proof verified on zkVerify mainnet, and releases the bounty on Base. No one presses "pay", and no one has to trust the agent: the escrow pays only against a zkVerify aggregation, and only to the address inside the proof.

| | |
|---|---|
| **Live agent** | <https://agent-production-8f9c2448.up.railway.app> (page at `/`, API under `/api`) |
| **Escrow (Base mainnet)** | [`0x28BC4e71Da0994cCbc4F9F472c06E164A67Fce3c`](https://basescan.org/address/0x28BC4e71Da0994cCbc4F9F472c06E164A67Fce3c), UUPS proxy, source verified on Sourcify (exact match) |
| **Attestor (zkTLS witness)** | `wss://attestor-production-c3cae0f4.up.railway.app/ws`, signer `0x7c2bD76BEc433acd4158a72DB39fE5454801f07D` |
| **Circuit vkHash (zkVerify)** | `0x611f230e5bc66119945ede9e09e2a87d89fcdb5aaced9444a8c15c316a48a74f` |
| **First mainnet proof** | [zkVerify tx `0x4f9556…9036`](https://zkverify.subscan.io/extrinsic/0x4f955653b8a4d02c37623bb2d3206a7f76cb64566e688f228e0a3da4327e9036), aggregation `149137` in domain `2`, root posted on Base |

## The problem

Bounties for open-source work need someone to decide "this was merged, pay this person" and then move the money. Today that is a person clicking a button, or a platform holding the funds and acting on a GitHub webhook. A webhook is signed with a secret shared between GitHub and the platform, so nobody else can check it: contributors have to trust the custodian, and the custodian has to trust its own servers.

Merge-to-Pay replaces that trust with a proof anyone can check. **Who it helps:** maintainers who want to post bounties without running payouts, contributors who want to be paid without chasing anyone, and anyone who wants to audit where bounty money went.

## How it works

```
maintainer ── fund(repo, issue, USDC, expiry, minPr) ──▶ MergeToPayEscrow (Base)
contributor ── PR body: "verity-payout: #<issue> 0x<payee>" ── maintainer merges
anyone ── POST /api/agent {"pr":"owner/repo#N"} ──▶ agent
  1 zkTLS     attestor witnesses TLS to api.github.com, GET /repos/{repo}/issues/{pr},
              signs a claim over "merged_at" and the leading payout line
  2 circuit   Noir (UltraHonk, keccak oracle, --zk) checks the attestor's ECDSA signature over
              that exact claim and outputs 7 public inputs
  3 zkVerify  Kurier submits the proof to zkVerify mainnet; it is verified, finalized, aggregated
  4 Base      the aggregation root is published on Base (zkVerify proxy 0xCb47…2b69)
  5 pay       the agent calls escrow.release(pubs, aggregationId, merklePath, …); the escrow
              recomputes the leaf, checks it against zkVerify, and pays the payee from the proof
```

The 7 public inputs are `[attestor, repoKey, pr, merged, issue, payee, timestamp]`, where `repoKey = keccak256(lowercase "owner/repo") >> 8`. The escrow refuses to pay unless:

- the attestor is the configured one;
- `merged == 1` and the payee is non-zero;
- a funded, unexpired, unpaid bounty exists for `(repoKey, issue)`;
- `pr >= minPr`, so PRs that existed before the bounty can't claim it;
- that PR has never been paid;
- zkVerify's aggregation on Base contains this exact statement.

`release()` is permissionless, and front-running it only pays the rightful payee sooner.

## What zkVerify makes checkable

> An attestor witnessed a TLS session with api.github.com in which `GET /repos/{repo}/issues/{pr}` returned `"merged_at"` and the leading `verity-payout: #<issue> 0x<payee>` line of the body. The `github_pr` circuit checks the attestor signature over that claim and exposes 7 public inputs. zkVerify verifies the UltraHonk proof; the Base escrow pays only against a zkVerify aggregation.

Every decision the agent makes, including `DECLINE` (not merged, no payout line, no bounty, expired, already paid), is backed by the same proof and submitted to zkVerify. Anyone can re-check a payout from public data alone: the Base transaction, the zkVerify aggregation, and the verification key hash above.

## Use it

**Contributor:** start the PR description with

```
verity-payout: #12 0xYourBaseAddress
```

**Anyone, after the merge** (within `MAX_MERGE_AGE_S`, 1 hour on the live agent):

```bash
curl -s -X POST https://agent-production-8f9c2448.up.railway.app/api/agent \
  -H 'content-type: application/json' -d '{"pr":"owner/repo#34"}'
# streamed steps instead:   -H 'accept: application/x-ndjson'
```

The response is the decision (`PAY`, `ELIGIBLE`, `DECLINE` or `ERROR`) with a reason code, the proven facts, the zkTLS claim and signature, the zkVerify job, transaction and statement, and the aggregation and payout status. A merged PR is proven once and its record is returned on every later request. The payout is sent by the agent's sweep as soon as the aggregation is on Base.

| Endpoint | |
|---|---|
| `POST /api/agent` | Run (or return the stored result for) one PR: `{"pr":"o/r#N"}`, a raw `o/r#N`, or a PR URL |
| `GET /api/agent` | Live config: attestor, escrow, relayer, vkHash, limits, the statement above |
| `GET /api/recent` | The last 20 decisions with their zkVerify and Base links |
| `GET /api/job?id=` | Re-poll one Kurier job and update its record |
| `GET /health` | Liveness, prover busy flag, daily usage |

**Maintainer, funding a bounty:**

```bash
cd packages/contracts
DEPLOYER_PRIVATE_KEY=0x… ESCROW=0x28BC4e71Da0994cCbc4F9F472c06E164A67Fce3c \
REPO=owner/repo ISSUE=12 AMOUNT=25 EXPIRY_DAYS=30 MIN_PR=<next PR number> \
  npx hardhat run scripts/fund-bounty.js --network base
```

Refunds open per funder 7 days after expiry if the bounty was never paid.

## Key decisions

- **zkTLS instead of webhooks or the GitHub API alone.** The proof shows that GitHub's real HTTPS response said "merged", without trusting the agent's word. Only `merged_at` and the payout line are revealed. An optional GitHub token travels as a secret header and is never part of the signed claim.
- **Our own attestor.** It's built from `reclaimprotocol/attestor-core` pinned to `dd43dc8`, with one patch that refuses clients older than 3.2.0, and it accepts only clients holding our signed auth request. Its address is a public input, and the escrow checks it.
- **A Noir circuit over the signed claim.** An attestor signature is ECDSA, which zkVerify can't verify directly. The circuit rebuilds the exact signed bytes, hashes them with keccak and checks secp256k1, so zkVerify verifies a standard UltraHonk proof. Proving with native `bb` takes about 2 s.
- **zkVerify via Kurier, settled on Base.** zkVerify does the verification once, cheaply; the escrow just checks a Merkle path into an aggregation root that zkVerify's own contract stores on Base. The leaf rule (vkHash, version hash) and domain `2` were pinned from a real mainnet job, not assumed.
- **The agent pays, but can't steal.** The relayer wallet only pays gas. The amount and the payee come from the escrow and the proof, and every release is simulated before it is sent.
- **Upgradeable escrow.** A UUPS proxy whose owner can rotate the attestor (or pause by setting it to zero) and update the verifier parameters if zkVerify changes them.

## Limits

- **Trust in one attestor.** A dishonest attestor could sign a false GitHub response. Mitigations: it is ours and pinned, it requires authenticated clients, and the escrow owner can rotate it. Several independent attestors would remove this.
- **The PR author can edit the payout line after the merge.** Mitigations: the agent proves a merged PR only once and refuses merges older than one hour, `minPr` blocks pre-existing PRs, and each PR can be paid once.
- **GitHub's JSON shape is part of the circuit.** If `api.github.com` changes how it orders or encodes these fields, the circuit needs a new version.
- **One agent instance**, with a daily cap on fresh proofs (`DAILY_CAP`, 50) to bound zkVerify costs.

## Repository

```
apps/merge-to-pay      the agent: node:http server, zkTLS, circuit prover, Kurier client, payout sweep, public page
  circuit/             Noir circuit github_pr (compiled artifact in target/)
packages/contracts     MergeToPayEscrow + deploy/fund scripts + Base-fork tests (real USDC, real zkVerify proxy)
packages/sdk           @verity/sdk: zkTLS prove/verify against a Verity attestor
services/attestor      attestor Dockerfile + patch
```

```bash
npm ci && npm test                       # 49 agent tests (circuit tests need nargo 1.0.0-beta.6 + bb 0.84.0 in ~/.cache/verity-noir)
cd packages/contracts && npx hardhat test test/merge-to-pay.fork.test.js   # 16 escrow tests on a Base fork
```

**Deploy:** both services run on Railway from Dockerfiles. The agent builds from the repo root with `RAILWAY_DOCKERFILE_PATH=apps/merge-to-pay/Dockerfile`, and the attestor from `services/attestor`. The agent needs:

- **Settings:** `VERITY_ATTESTOR_URL`, `ATTESTOR_ADDRESS`, `VK_HASH`, `ESCROW_ADDRESS`, `BASE_RPC_URL`
- **Secrets:** `ATTESTOR_AUTH_TOKEN`, `KURIER_API_KEY`, `RELAYER_PRIVATE_KEY`
- **Storage:** a volume at `/data`

Secrets are generated locally and set as service variables. None are in this repository.

MIT licensed. Built for the zkVerify Agent Games 2026 (Wildcard).
