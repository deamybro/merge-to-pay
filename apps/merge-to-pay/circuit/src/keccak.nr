// Keccak-256 sponge pieces over the std keccakf1600 black box (std::hash::keccak256 is gone in beta.6).
// Bytes travel as Fields (every byte is a range-checked u8, a constant, or a mux of those) and are
// packed into u64 lanes through an unconstrained hint that is pinned by an equality check.
pub global RATE: u32 = 136;

unconstrained fn to_u64(v: Field) -> u64 {
    v as u64
}

unconstrained fn to_bytes8(v: Field) -> [u8; 8] {
    let mut o = [0; 8];
    let mut x = v as u64;
    for k in 0..8 {
        o[k] = (x & 0xff) as u8;
        x = x >> 8;
    }
    o
}

/// XOR one 136-byte block into the state and permute.
pub fn absorb(st: [u64; 25], block: [Field; 136]) -> [u64; 25] {
    let mut s = st;
    for l in 0..17 {
        let mut v: Field = 0;
        for k in 0..8 {
            v = v * 256 + block[l * 8 + 7 - k];
        }
        // Safety: pinned by the equality below.
        let u = unsafe { to_u64(v) };
        assert(u as Field == v);
        s[l] = s[l] ^ u;
    }
    std::hash::keccakf1600(s)
}

/// First 32 bytes of a state whose first four lanes are given as Fields.
pub fn squeeze(lanes: [Field; 4]) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for l in 0..4 {
        // Safety: bytes are range-checked u8s and pinned by the equality below.
        let bs = unsafe { to_bytes8(lanes[l]) };
        let mut v: Field = 0;
        for k in 0..8 {
            v = v * 256 + bs[7 - k] as Field;
            out[l * 8 + k] = bs[k];
        }
        assert(v == lanes[l]);
    }
    out
}

pub fn lanes4(st: [u64; 25]) -> [Field; 4] {
    [st[0] as Field, st[1] as Field, st[2] as Field, st[3] as Field]
}

/// keccak256 of a fixed-length message that fits B blocks (N + 1 <= B * 136).
pub fn hash<let N: u32, let B: u32>(msg: [Field; N]) -> [u8; 32] {
    std::static_assert(N + 1 <= B * RATE, "too many bytes for B blocks");
    let mut buf: [Field; B * 136] = [0; B * 136];
    for i in 0..N {
        buf[i] = msg[i];
    }
    buf[N] = 1;
    buf[B * 136 - 1] += 0x80;
    let mut st: [u64; 25] = [0; 25];
    for b in 0..B {
        let mut block: [Field; 136] = [0; 136];
        for i in 0..136 {
            block[i] = buf[b * 136 + i];
        }
        st = absorb(st, block);
    }
    squeeze(lanes4(st))
}
