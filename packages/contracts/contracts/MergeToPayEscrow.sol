// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// zkVerify aggregation contract (Base: 0xCb47A3C3B9Eb2E549a3F2EA4729De28CafbB2b69).
interface IZkVerifyAggregation {
	function verifyProofAggregation(
		uint256 _domainId, uint256 _aggregationId, bytes32 _leaf,
		bytes32[] calldata _merklePath, uint256 _leafCount, uint256 _index
	) external view returns (bool);
}

/// @title MergeToPayEscrow
/// @notice USDC bounties on GitHub issues, released to the payee named in a merged PR once zkVerify
/// has aggregated the UltraHonk proof of the zkTLS claim. pubs = [attestor, repoKey, pr, merged, issue, payee, ts].
contract MergeToPayEscrow is Initializable, UUPSUpgradeable, OwnableUpgradeable {
	using SafeERC20 for IERC20;

	struct Bounty { uint256 amount; uint64 expiry; uint64 minPr; bool paid; }

	uint256 private constant BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
	bytes32 private constant CTX = keccak256("ultrahonk"); // pallet hash_context_data()
	uint64 public constant GRACE = 7 days;                  // refund opens at expiry + GRACE (M2)

	IERC20 public usdc;
	IZkVerifyAggregation public zkv;
	bytes32 public vkHash;
	bytes32 public versionHash;
	uint256 public domainId;
	address public attestor; // address(0) pauses release
	mapping(bytes32 => Bounty) public bounties;
	mapping(bytes32 => mapping(address => uint256)) public funded; // bountyId => funder => amount
	mapping(bytes32 => bool) public prUsed;                        // keccak(abi.encode(repoKey, pr))

	event Funded(bytes32 indexed id, address indexed funder, uint256 amount, uint64 expiry, uint64 minPr);
	event Paid(bytes32 indexed id, address indexed payee, uint256 amount, uint256 pr, uint256 aggregationId);
	event Refunded(bytes32 indexed id, address indexed funder, uint256 amount);
	event AttestorSet(address attestor);
	event VerifierParamsSet(bytes32 vkHash, bytes32 versionHash, uint256 domainId);

	error BadRepo();
	error ZeroAmount();
	error TermsMismatch();
	error OutOfRange();
	error BadAttestor();
	error NotMerged();
	error ZeroPayee();
	error NoBounty();
	error AlreadyPaid();
	error Expired();
	error PrTooOld();
	error PrAlreadyUsed();
	error NotVerified();
	error NotRefundable();
	error NothingToRefund();

	constructor() { _disableInitializers(); }

	function initialize(
		address owner_, address usdc_, address zkv_, bytes32 vkHash_, bytes32 versionHash_, uint256 domainId_, address attestor_
	) external initializer {
		__Ownable_init(owner_);
		usdc = IERC20(usdc_);
		zkv = IZkVerifyAggregation(zkv_);
		vkHash = vkHash_; versionHash = versionHash_; domainId = domainId_;
		attestor = attestor_;
	}

	// --- pure helpers (same as the circuit) ---

	/// lowercase `owner/name`, charset [a-z0-9._-], at most 140 bytes
	function repoKey(string calldata repo) public pure returns (uint256) {
		bytes calldata s = bytes(repo);
		if (s.length == 0 || s.length > 140) revert BadRepo();
		uint256 slashes;
		for (uint256 i; i < s.length; i++) {
			bytes1 c = s[i];
			if (c == "/") { if (i == 0 || i == s.length - 1) revert BadRepo(); slashes++; }
			else if (!((c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "." || c == "_" || c == "-")) revert BadRepo();
		}
		if (slashes != 1) revert BadRepo();
		return uint256(keccak256(s)) >> 8;
	}

	function bountyId(uint256 key, uint256 issue) public pure returns (bytes32) {
		return keccak256(abi.encode(key, issue));
	}

	// --- money ---

	/// Additive. The first funder sets expiry and minPr; later funders pass the same values or 0 to accept them.
	/// minPr = the repo's next PR/issue number at funding time; release needs pr >= minPr (C1a).
	function fund(string calldata repo, uint256 issue, uint256 amount, uint64 expiry, uint64 minPr) external {
		if (amount == 0) revert ZeroAmount();
		bytes32 id = bountyId(repoKey(repo), issue);
		Bounty storage b = bounties[id];
		if (b.paid) revert AlreadyPaid();
		if (b.amount == 0) { b.expiry = expiry; b.minPr = minPr; }
		else if ((expiry != 0 && expiry != b.expiry) || (minPr != 0 && minPr != b.minPr)) revert TermsMismatch();
		if (block.timestamp > b.expiry) revert Expired();
		b.amount += amount;
		funded[id][msg.sender] += amount;
		usdc.safeTransferFrom(msg.sender, address(this), amount);
		emit Funded(id, msg.sender, amount, b.expiry, b.minPr);
	}

	/// Anyone may call. The payee is fixed by the proof, so front-running is harmless.
	function release(uint256[7] calldata pubs, uint256 aggregationId, bytes32[] calldata merklePath, uint256 leafCount, uint256 index) external {
		for (uint256 i; i < 7; i++) if (pubs[i] >= BN254_R) revert OutOfRange();   // M1
		if (pubs[0] >> 160 != 0 || pubs[5] >> 160 != 0) revert OutOfRange();
		if (attestor == address(0) || pubs[0] != uint256(uint160(attestor))) revert BadAttestor();
		if (pubs[3] != 1) revert NotMerged();
		if (pubs[5] == 0) revert ZeroPayee();
		bytes32 id = bountyId(pubs[1], pubs[4]);
		Bounty storage b = bounties[id];
		if (b.amount == 0) revert NoBounty();
		if (b.paid) revert AlreadyPaid();
		if (block.timestamp > b.expiry) revert Expired();
		if (pubs[2] < b.minPr) revert PrTooOld();
		bytes32 prKey = keccak256(abi.encode(pubs[1], pubs[2]));
		if (prUsed[prKey]) revert PrAlreadyUsed();
		// pallet_verifiers::compute_statement_hash: keccak(keccak("ultrahonk") ‖ vkHash ‖ versionHash ‖ keccak(pubs_bytes))
		bytes32 leaf = keccak256(abi.encodePacked(CTX, vkHash, versionHash, keccak256(abi.encodePacked(pubs))));
		if (!zkv.verifyProofAggregation(domainId, aggregationId, leaf, merklePath, leafCount, index)) revert NotVerified();
		b.paid = true;
		prUsed[prKey] = true;
		address payee = address(uint160(pubs[5]));
		usdc.safeTransfer(payee, b.amount);
		emit Paid(id, payee, b.amount, pubs[2], aggregationId);
	}

	/// Per funder, only after expiry + GRACE and only while unpaid.
	function refund(bytes32 id) external {
		Bounty storage b = bounties[id];
		if (b.paid || block.timestamp <= uint256(b.expiry) + GRACE) revert NotRefundable();
		uint256 amount = funded[id][msg.sender];
		if (amount == 0) revert NothingToRefund();
		funded[id][msg.sender] = 0;
		b.amount -= amount;
		usdc.safeTransfer(msg.sender, amount);
		emit Refunded(id, msg.sender, amount);
	}

	// --- owner ---

	function setAttestor(address attestor_) external onlyOwner { attestor = attestor_; emit AttestorSet(attestor_); }

	function setVerifierParams(bytes32 vkHash_, bytes32 versionHash_, uint256 domainId_) external onlyOwner {
		vkHash = vkHash_; versionHash = versionHash_; domainId = domainId_;
		emit VerifierParamsSet(vkHash_, versionHash_, domainId_);
	}

	function _authorizeUpgrade(address) internal override onlyOwner {}
}
