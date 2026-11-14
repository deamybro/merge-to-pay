// The agent pays: once a PAY record's proof is aggregated and published on Base, it calls escrow.release()
// from its relayer wallet. release() is permissionless and the payee is fixed by the proof, so the relayer
// only spends gas. Every send is simulated first; a reverting release never costs gas.
import { createPublicClient, createWalletClient, http, parseAbi } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { base } from 'viem/chains'

const ABI = parseAbi(['function release(uint256[7] pubs, uint256 aggregationId, bytes32[] merklePath, uint256 leafCount, uint256 index)'])

/** release() arguments from a stored record, or null while it is not payable (not PAY, not aggregated, or paid). */
export function releaseArgs(rec) {
  if (rec?.decision !== 'PAY' || rec.payout?.txHash || !rec.payout?.escrow) return null
  const a = rec.aggregation, d = a?.details
  // 'aggregated' is enough: Kurier may never flag the Base publish, and the simulated release() reverts NotVerified until the root lands
  if (!['aggregated', 'published'].includes(a?.status) || a.aggregationId == null || !Array.isArray(d?.merkleProof)) return null
  return [rec.zkverify.publicInputs.map(BigInt), BigInt(a.aggregationId), d.merkleProof, BigInt(d.numberOfLeaves), BigInt(d.leafIndex)]
}

export const relayer = () => (process.env.RELAYER_PRIVATE_KEY ? privateKeyToAccount(process.env.RELAYER_PRIVATE_KEY).address : null)

/** Send release() for a payable record. Resolves to the tx hash; throws with the revert reason. */
export async function release(rec) {
  const args = releaseArgs(rec)
  if (!args) throw new Error('record is not payable yet')
  if (!process.env.RELAYER_PRIVATE_KEY) throw new Error('RELAYER_PRIVATE_KEY not set')
  const account = privateKeyToAccount(process.env.RELAYER_PRIVATE_KEY)
  const transport = http(process.env.BASE_RPC_URL)
  const pub = createPublicClient({ chain: base, transport })
  const { request } = await pub.simulateContract({ account, address: rec.payout.escrow, abi: ABI, functionName: 'release', args })
  const hash = await createWalletClient({ account, chain: base, transport }).writeContract(request)
  const receipt = await pub.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new Error(`release reverted on chain: ${hash}`)
  return hash
}
