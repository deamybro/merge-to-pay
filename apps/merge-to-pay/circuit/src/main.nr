// github_pr: "attestor A signed a Merge-to-Pay claim for repo/pr with merged flag, optional payout".
// The claim is BUILT from the compiled template (template.nr, generated from spec.mjs) plus
// character-restricted slots, never parsed from a prover blob. See DESIGN.md section 4.1.
//
// Claim = HEAD(525, 3 blocks pre-absorbed) || repo || "/issues/" || pr || MID ||
//         ["issue":"I",] "mergedAt":"<null | \"20 chars\">" [,"payee":"0x<40 hex>"] "},"providerHash":"0x<64 hex>"}
// Public outputs: [attestor, repoKey, pr, merged, issue, payee, ts].
mod keccak;
mod template;
use keccak::{absorb, hash, lanes4, squeeze};
use template::{CTX_ISSUE, CTX_MERGED_AT, CTX_PAYEE, CTX_PROVIDER_HASH, HEAD_REST, ISSUES, MID, MIDSTATE, TAIL};

global REPO_MAX: u32 = 140; // owner 39 + "/" + name 100
global DIGITS: u32 = 9; // [1-9][0-9]{0,8}
global W4: u32 = 11 + 42 + 19 + 66 + 2 + 1; // payee part, providerHash part, tail, keccak pad 0x01
global W3: u32 = 12 + 24 + W4; // "mergedAt":" , escaped timestamp or null
global W2: u32 = 9 + DIGITS + 2 + W3; // "issue":"I",
global W1: u32 = 8 + DIGITS + 27 + W2; // /issues/N"}\n{"extractedParameters":{
global W0: u32 = REPO_MAX + W1;
global BUF: u32 = 4 * 136; // 117 + W0 = 498 dynamic bytes at most
global D_MAX: u32 = 117 + W0 - 1;

// Byte-class tables, read with a u8 index (no bounds check needed on 256 entries).
global CLS: [Field; 256] = comptime { cls() }; // repo: 0 bad, 1 [a-z0-9._-], 2 '/'
global DIG: [Field; 256] = comptime { dig() }; // '0'..'9' -> 0..9, else 10
global HEXL: [Field; 256] = comptime { hexv(false) }; // lowercase hex -> 0..15, else 16
global HEXA: [Field; 256] = comptime { hexv(true) }; // any-case hex -> 0..15, else 16
global TSC: [Field; 256] = comptime { tsc() }; // [0-9TZ:-] -> 1, else 0
global HEX_HI: [u8; 256] = comptime { hexchar(true) }; // byte -> lowercase hex char of its high nibble
global HEX_LO: [u8; 256] = comptime { hexchar(false) };

comptime fn cls() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 0..256 {
        if ((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57)) | (c == 46) | (c == 95) | (c == 45) { t[c] = 1; }
        if c == 47 { t[c] = 2; }
    }
    t
}
comptime fn dig() -> [Field; 256] {
    let mut t = [10; 256];
    for c in 48..58 { t[c] = (c - 48) as Field; }
    t
}
comptime fn hexv(any_case: bool) -> [Field; 256] {
    let mut t = [16; 256];
    for c in 48..58 { t[c] = (c - 48) as Field; }
    for c in 97..103 { t[c] = (c - 87) as Field; }
    if any_case { for c in 65..71 { t[c] = (c - 55) as Field; } }
    t
}
comptime fn tsc() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 48..58 { t[c] = 1; }
    for c in [84, 90, 58, 45] { t[c] = 1; }
    t
}
comptime fn hexchar(hi: bool) -> [u8; 256] {
    let mut t = [0; 256];
    for c in 0..256 {
        let n = if hi { c / 16 } else { c % 16 };
        t[c] = (if n < 10 { 48 + n } else { 87 + n }) as u8;
    }
    t
}

/// lt[j] = (len > j); also forces 0 <= len <= N.
fn mask<let N: u32>(len: Field) -> [Field; N] {
    let mut lt: [Field; N] = [0; N];
    let mut cur: Field = 1;
    let mut seen: Field = 0;
    for j in 0..N + 1 {
        let e: Field = if len == (j as Field) { 1 } else { 0 };
        seen += e;
        if j < N {
            cur = cur * (1 - e);
            lt[j] = cur;
        }
    }
    assert(seen == 1, "length out of range");
    lt
}

/// Shift left by s < 2^B, zero-filling: out[j] = w[j + s].
fn shl<let W: u32, let B: u32>(w: [Field; W], s: Field) -> [Field; W] {
    let bits: [u1; B] = s.to_le_bits();
    let mut x = w;
    for k in 0..B {
        let sh: u32 = 1 << (k as u8);
        let mut y: [Field; W] = [0; W];
        for j in 0..W {
            let hi = if j + sh < W { x[j + sh] } else { 0 };
            y[j] = if bits[k] == 1 { hi } else { x[j] };
        }
        x = y;
    }
    x
}

fn mux<let W: u32>(c: bool, a: [Field; W], b: [Field; W]) -> [Field; W] {
    let mut o: [Field; W] = [0; W];
    for j in 0..W {
        o[j] = if c { a[j] } else { b[j] };
    }
    o
}

fn put<let N: u32, let W: u32>(dst: &mut [Field; W], at: u32, src: [u8; N]) {
    for i in 0..N {
        dst[at + i] = src[i] as Field;
    }
}

/// Decimal digits with mask lt: checks each in-range byte is a digit, returns the value.
fn decimal<let N: u32>(d: [u8; N], lt: [Field; N]) -> Field {
    let mut v: Field = 0;
    for j in 0..N {
        let x = DIG[d[j] as u32];
        let bad: Field = if x == 10 { 1 } else { 0 };
        assert(lt[j] * bad == 0, "not a digit");
        v += lt[j] * (9 * v + x);
    }
    v
}

/// Hex string value; `on` gates the character check (payee is only checked when there is a payout line).
fn hex<let N: u32>(h: [u8; N], table: [Field; 256], on: Field) -> Field {
    let mut v: Field = 0;
    for j in 0..N {
        let x = table[h[j] as u32];
        let bad: Field = if x == 16 { 1 } else { 0 };
        assert(on * bad == 0, "not hex");
        v = v * 16 + x;
    }
    v
}

fn main(
    repo: [u8; REPO_MAX],
    repo_len: Field,
    pr: [u8; DIGITS],
    pr_len: Field,
    merged: bool,
    merged_at: [u8; 20],
    payout: bool,
    issue: [u8; DIGITS],
    issue_len: Field,
    payee: [u8; 40],
    provider_hash: [u8; 64],
    owner: [u8; 40],
    ts: [u8; 10],
    pub_x: [u8; 32],
    pub_y: [u8; 32],
    sig: [u8; 64],
) -> pub [Field; 7] {
    let pay = payout as Field;

    // --- repo: [a-z0-9._-]+/[a-z0-9._-]+, 3..=140 bytes ---
    let lt_r: [Field; REPO_MAX] = mask(repo_len);
    assert(lt_r[2] == 1, "repo too short");
    let mut rb: [Field; REPO_MAX] = [0; REPO_MAX];
    let mut slashes: Field = 0;
    let mut slash_last: Field = 0;
    for j in 0..REPO_MAX {
        let v = CLS[repo[j] as u32];
        assert(lt_r[j] * (v - 1) * (v - 2) == 0, "repo char");
        let slash = v * (v - 1) / 2;
        slashes += slash * lt_r[j];
        let next = if j + 1 < REPO_MAX { lt_r[j + 1] } else { 0 };
        slash_last += slash * (lt_r[j] - next);
        rb[j] = lt_r[j] * (repo[j] as Field);
    }
    assert(slashes == 1, "repo needs one slash");
    assert((CLS[repo[0] as u32] == 1) & (slash_last == 0), "slash at an end");

    // repoKey = keccak256(repo) >> 8, repo up to 140 bytes = 1 or 2 blocks
    let mut rbuf: [Field; 272] = [0; 272];
    for j in 0..REPO_MAX + 1 {
        // 0x01 pad at index repo_len
        let eq = (if j == 0 { 1 } else { lt_r[j - 1] }) - (if j < REPO_MAX { lt_r[j] } else { 0 });
        rbuf[j] = (if j < REPO_MAX { rb[j] } else { 0 }) + eq;
    }
    let two_blocks = lt_r[135]; // len > 135
    rbuf[135] += 0x80 * (1 - two_blocks);
    rbuf[271] += 0x80 * two_blocks;
    let mut blk: [Field; 136] = [0; 136];
    for i in 0..136 { blk[i] = rbuf[i]; }
    let rs1 = absorb([0; 25], blk);
    for i in 0..136 { blk[i] = rbuf[136 + i]; }
    let rs2 = absorb(rs1, blk);
    let l1 = lanes4(rs1);
    let l2 = lanes4(rs2);
    let mut rl: [Field; 4] = [0; 4];
    for l in 0..4 { rl[l] = l1[l] + two_blocks * (l2[l] - l1[l]); }
    let rh = squeeze(rl);
    let mut repo_key: Field = 0;
    for i in 0..31 { repo_key = repo_key * 256 + rh[i] as Field; }

    // --- pr / issue digits ---
    let lt_p: [Field; DIGITS] = mask(pr_len);
    assert((lt_p[0] == 1) & (DIG[pr[0] as u32] != 0), "pr: 1-9 digits, no leading zero");
    let pr_val = decimal(pr, lt_p);
    let lt_i0: [Field; DIGITS] = mask(issue_len);
    let mut lt_i: [Field; DIGITS] = [0; DIGITS];
    for j in 0..DIGITS { lt_i[j] = pay * lt_i0[j]; }
    assert(pay * (1 - lt_i0[0]) == 0, "issue: at least one digit");
    assert(pay * (if DIG[issue[0] as u32] == 0 { 1 } else { 0 }) == 0, "issue: leading zero");
    let issue_val = decimal(issue, lt_i);

    // --- hex slots ---
    let payee_val = hex(payee, HEXA, pay);
    let _ = hex(provider_hash, HEXL, 1);
    let _ = hex(owner, HEXL, 1); // owner stays private; only its lowercase-hex shape matters
    for j in 0..20 { assert((merged as Field) * (1 - TSC[merged_at[j] as u32]) == 0, "mergedAt char"); }
    let lt_ts: [Field; 10] = [1; 10];
    let ts_val = decimal(ts, lt_ts);

    // --- assemble the dynamic part of the claim, right to left ---
    // X4 = [","payee":"0x<40>] "},"providerHash":"0x<64>"} 0x01
    let mut x4a: [Field; W4] = [0; W4];
    let mut x4b: [Field; W4] = [0; W4];
    let mut tail87: [Field; 88] = [0; 88];
    put(&mut tail87, 0, CTX_PROVIDER_HASH);
    put(&mut tail87, 19, [48, 120]);
    put(&mut tail87, 21, provider_hash);
    put(&mut tail87, 85, TAIL);
    tail87[87] = 1;
    put(&mut x4a, 0, CTX_PAYEE);
    put(&mut x4a, 11, [48, 120]);
    put(&mut x4a, 13, payee);
    for i in 0..88 { x4a[53 + i] = tail87[i]; x4b[i] = tail87[i]; }
    let x4 = mux(payout, x4a, x4b);
    // X3 = "mergedAt":" (\"<20>\" | null) X4
    let mut x3a: [Field; W3] = [0; W3];
    let mut x3b: [Field; W3] = [0; W3];
    put(&mut x3a, 0, CTX_MERGED_AT);
    put(&mut x3a, 12, [92, 34]);
    put(&mut x3a, 14, merged_at);
    put(&mut x3a, 34, [92, 34]);
    put(&mut x3b, 0, CTX_MERGED_AT);
    put(&mut x3b, 12, [110, 117, 108, 108]);
    for i in 0..W4 { x3a[36 + i] = x4[i]; x3b[16 + i] = x4[i]; }
    let x3 = mux(merged, x3a, x3b);
    // X2 = ["issue":"<I>",] X3
    let mut w2: [Field; DIGITS + 2 + W3] = [0; DIGITS + 2 + W3];
    put(&mut w2, DIGITS, [34, 44]);
    for i in 0..W3 { w2[DIGITS + 2 + i] = x3[i]; }
    let s_i = (DIGITS as Field) - issue_len;
    let sh2 = shl::<DIGITS + 2 + W3, 4>(w2, s_i);
    let mut x2a: [Field; W2] = [0; W2];
    let mut x2b: [Field; W2] = [0; W2];
    put(&mut x2a, 0, CTX_ISSUE);
    for i in 0..DIGITS + 2 + W3 { x2a[9 + i] = sh2[i]; }
    for j in 0..DIGITS { x2a[9 + j] += lt_i[j] * (issue[j] as Field); }
    for i in 0..W3 { x2b[i] = x3[i]; }
    let x2 = mux(payout, x2a, x2b);
    // X1 = /issues/<pr> MID X2
    let mut w1: [Field; DIGITS + 27 + W2] = [0; DIGITS + 27 + W2];
    put(&mut w1, DIGITS, MID);
    for i in 0..W2 { w1[DIGITS + 27 + i] = x2[i]; }
    let s_p = (DIGITS as Field) - pr_len;
    let sh1 = shl::<DIGITS + 27 + W2, 4>(w1, s_p);
    let mut x1: [Field; W1] = [0; W1];
    put(&mut x1, 0, ISSUES);
    for i in 0..DIGITS + 27 + W2 { x1[8 + i] = sh1[i]; }
    for j in 0..DIGITS { x1[8 + j] += lt_p[j] * (pr[j] as Field); }
    // X0 = repo X1
    let mut w0: [Field; W0] = [0; W0];
    for i in 0..W1 { w0[REPO_MAX + i] = x1[i]; }
    let s_r = (REPO_MAX as Field) - repo_len;
    let sh0 = shl::<W0, 8>(w0, s_r);
    let mut buf: [Field; BUF] = [0; BUF];
    put(&mut buf, 0, HEAD_REST);
    for j in 0..REPO_MAX { buf[117 + j] = rb[j] + sh0[j]; }
    for j in REPO_MAX..W0 { buf[117 + j] = sh0[j]; }

    // dynamic length (bytes before the 0x01 pad) and the 0x80 at the end of the last block
    let m = merged as Field;
    let d = (D_MAX as Field) - s_r - s_p - (pay * s_i + (1 - pay) * 20) - (1 - m) * 20 - (1 - pay) * 53;
    let du = d as u32;
    let is2 = du < 272;
    let is4 = du >= 408;
    let is3 = !is2 & !is4;
    buf[271] += 0x80 * (is2 as Field);
    buf[407] += 0x80 * (is3 as Field);
    buf[543] += 0x80 * (is4 as Field);
    let mut st = MIDSTATE;
    let mut c2: [Field; 4] = [0; 4];
    let mut c3: [Field; 4] = [0; 4];
    for b in 0..4 {
        for i in 0..136 { blk[i] = buf[b * 136 + i]; }
        st = absorb(st, blk);
        if b == 1 { c2 = lanes4(st); }
        if b == 2 { c3 = lanes4(st); }
    }
    let c4 = lanes4(st);
    let mut cl: [Field; 4] = [0; 4];
    for l in 0..4 { cl[l] = if is2 { c2[l] } else { if is3 { c3[l] } else { c4[l] } }; }
    let id = squeeze(cl);

    // --- EIP-191 message: "\x19Ethereum Signed Message:\n122" 0x<id hex>\n0x<owner>\n<ts>\n1 ---
    let mut msg: [Field; 151] = [0; 151];
    put(&mut msg, 0, [25, 69, 116, 104, 101, 114, 101, 117, 109, 32, 83, 105, 103, 110, 101, 100, 32, 77, 101, 115, 115, 97, 103, 101, 58, 10, 49, 50, 50]);
    put(&mut msg, 29, [48, 120]);
    for i in 0..32 {
        msg[31 + 2 * i] = HEX_HI[id[i] as u32] as Field;
        msg[32 + 2 * i] = HEX_LO[id[i] as u32] as Field;
    }
    put(&mut msg, 95, [10, 48, 120]);
    put(&mut msg, 98, owner);
    msg[138] = 10;
    put(&mut msg, 139, ts);
    put(&mut msg, 149, [10, 49]);
    let h = hash::<151, 2>(msg);
    assert(std::ecdsa_secp256k1::verify_signature(pub_x, pub_y, sig, h), "bad signature");

    // attestor = address(keccak256(X || Y))
    let mut pk: [Field; 64] = [0; 64];
    put(&mut pk, 0, pub_x);
    put(&mut pk, 32, pub_y);
    let ah = hash::<64, 1>(pk);
    let mut attestor: Field = 0;
    for i in 12..32 { attestor = attestor * 256 + ah[i] as Field; }

    [attestor, repo_key, pr_val, m, pay * issue_val, pay * payee_val, ts_val]
}
