//! Bulletin board log core (SPEC.md §17): Merkle tree, signed tree heads,
//! equivocation checks, and the signed `polls_open`, `tally_cutoff` and
//! `rejection` records.
//!
//! Inclusion and consistency proofs follow RFC 9162 §2.1.3 and §2.1.4 with the
//! hashes of §17.2. Verification works from the proof alone and never rebuilds
//! the tree.

use crate::cbor::{record_fields, Value};
use crate::error::Error;
use crate::hash::digest;
use crate::manifest::{bytes32, expect_version};
use crate::sign::{sign_record, verify_record, SigningKey, VerifyingKey};

/// Signature domain tag of a signed tree head (§17.3).
const SIG_STH: &str = "eg/v1/sig/sth";
/// Signature domain tag of `polls_open` (§17.7, EA key).
const SIG_POLLS_OPEN: &str = "eg/v1/sig/polls-open";
/// Signature domain tag of `tally_cutoff` (§17.7, EA key).
const SIG_TALLY_CUTOFF: &str = "eg/v1/sig/tally-cutoff";
/// Signature domain tag of `rejection` (§17.6, board key).
const SIG_REJECTION: &str = "eg/v1/sig/rejection";

/// Builds a record map from `(uint key, value)` pairs, in the form
/// [`sign_record`] takes.
fn fields(entries: Vec<(u64, Value)>) -> Vec<(Value, Value)> {
    entries
        .into_iter()
        .map(|(k, v)| (Value::Uint(k), v))
        .collect()
}

/// RecordId(x) = Digest("eg/v1/record-id", x) (§15.5). Names any record,
/// including its signature field.
pub fn record_id(record: &Value) -> [u8; 32] {
    digest("eg/v1/record-id", std::slice::from_ref(record))
}

/// leaf_hash(entry) = Digest("eg/v1/leaf", entry) (§17.2).
pub fn leaf_hash(entry: &Value) -> [u8; 32] {
    digest("eg/v1/leaf", std::slice::from_ref(entry))
}

/// node_hash(L, R) = Digest("eg/v1/node", L, R) (§17.2).
pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    digest("eg/v1/node", &[Value::from(*l), Value::from(*r)])
}

/// MTH({}) = Digest("eg/v1/empty") (§17.2).
pub fn empty_root() -> [u8; 32] {
    digest("eg/v1/empty", &[])
}

/// Largest power of two strictly less than `n` (`n > 1`).
fn largest_pow2_below(n: usize) -> usize {
    1usize << (n - 1).ilog2()
}

/// Merkle tree hash MTH(D[n]) over already-hashed leaves (§17.2, RFC 9162
/// §2.1.1).
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_pow2_below(n);
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// RFC 9162 §2.1.3.1 PATH(m, D[n]). Requires `m < leaves.len()`.
fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n == 1 {
        return Vec::new();
    }
    let k = largest_pow2_below(n);
    if m < k {
        let mut p = path(m, &leaves[..k]);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path(m - k, &leaves[k..]);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// RFC 9162 §2.1.4.1 SUBPROOF(m, D[n], b). Requires `0 < m <= leaves.len()`.
fn subproof(m: usize, leaves: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == n {
        return if b { Vec::new() } else { vec![mth(leaves)] };
    }
    let k = largest_pow2_below(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// In-memory append-only log (§17.1). Stores entries and their leaf hashes.
#[derive(Clone, Debug, Default)]
pub struct Log {
    entries: Vec<Value>,
    leaves: Vec<[u8; 32]>,
}

impl Log {
    pub fn new() -> Log {
        Log::default()
    }

    /// Appends `entry` and returns its index.
    pub fn append(&mut self, entry: Value) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash(&entry));
        self.entries.push(entry);
        index
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn entry(&self, index: u64) -> Option<&Value> {
        self.entries.get(usize::try_from(index).ok()?)
    }

    pub fn entries(&self) -> &[Value] {
        &self.entries
    }

    /// MTH of the first `size` entries. Panics if size > len.
    pub fn root_at(&self, size: u64) -> [u8; 32] {
        assert!(
            size <= self.len(),
            "root_at: size {size} exceeds log length"
        );
        mth(&self.leaves[..size as usize])
    }

    pub fn root(&self) -> [u8; 32] {
        self.root_at(self.len())
    }

    /// RFC 9162 §2.1.3.1 inclusion proof for leaf `index` in the tree of
    /// `size`. None if index >= size or size > len.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Option<Vec<[u8; 32]>> {
        if index >= size || size > self.len() {
            return None;
        }
        Some(path(index as usize, &self.leaves[..size as usize]))
    }

    /// RFC 9162 §2.1.4.1 consistency proof from `old_size` to `new_size`.
    /// None if old_size > new_size or new_size > len. Empty when old == new
    /// or old == 0.
    pub fn consistency_proof(&self, old_size: u64, new_size: u64) -> Option<Vec<[u8; 32]>> {
        if old_size > new_size || new_size > self.len() {
            return None;
        }
        if old_size == 0 || old_size == new_size {
            return Some(Vec::new());
        }
        Some(subproof(
            old_size as usize,
            &self.leaves[..new_size as usize],
            true,
        ))
    }
}

/// Least significant bit of `x` is set.
fn lsb(x: u64) -> bool {
    (x & 1) == 1
}

/// RFC 9162 §2.1.3.2 inclusion verification. Uses only the proof, the leaf
/// hash, the index, the size and the root.
pub fn verify_inclusion(
    leaf: &[u8; 32],
    index: u64,
    size: u64,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if index >= size {
        return false;
    }
    let mut fn_ = index;
    let mut sn = size - 1;
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if lsb(fn_) || fn_ == sn {
            r = node_hash(p, &r);
            if !lsb(fn_) {
                while !lsb(fn_) && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// RFC 9162 §2.1.4.2 consistency verification. Uses only the proof and the
/// two roots. `old_size == 0` is consistent only with an empty proof.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == 0 {
        return proof.is_empty();
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    // Step 1: an exact power of two has its root prepended to the path.
    let mut path = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    // Steps 2-4.
    let mut fn_ = old_size - 1;
    let mut sn = new_size - 1;
    while lsb(fn_) {
        fn_ >>= 1;
        sn >>= 1;
    }
    let mut fr = *first;
    let mut sr = *first;
    // Step 5.
    for c in rest {
        if sn == 0 {
            return false;
        }
        if lsb(fn_) || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if !lsb(fn_) {
                while !lsb(fn_) && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    // Step 6.
    sn == 0 && fr == *old_root && sr == *new_root
}

const STH_TAG_FIELDS: usize = 7;
const STH_SIG_KEY: u64 = 6;

/// Signed tree head (§17.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sth {
    pub manifest_hash: [u8; 32],
    pub size: u64,
    pub root: [u8; 32],
    pub timestamp: u64,
}

impl Sth {
    /// Builds the signed `sth` record with the board key.
    pub fn sign(&self, board_sk: &SigningKey) -> Value {
        sign_record(
            board_sk,
            SIG_STH,
            fields(vec![
                (0, Value::from("sth")),
                (1, Value::Uint(1)),
                (2, Value::from(self.manifest_hash)),
                (3, Value::Uint(self.size)),
                (4, Value::from(self.root)),
                (5, Value::Uint(self.timestamp)),
            ]),
            STH_SIG_KEY,
        )
    }

    /// Decodes a signed `sth` and verifies it with the board key.
    pub fn from_signed(v: &Value, board_pk: &VerifyingKey) -> Result<Sth, Error> {
        let f = record_fields(v, "sth", STH_TAG_FIELDS)?;
        verify_record(board_pk, SIG_STH, v, STH_SIG_KEY)?;
        expect_version(f[1])?;
        Ok(Sth {
            manifest_hash: bytes32(f[2])?,
            size: f[3].as_uint()?,
            root: bytes32(f[4])?,
            timestamp: f[5].as_uint()?,
        })
    }
}

/// Proof of board misbehaviour between two STHs (§17.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Equivocation {
    SameSizeDifferentRoots,
    Inconsistent,
}

/// Checks two STHs against each other (§17.4). `consistency_proof` is the
/// proof from the smaller tree to the larger one. Orders `a` and `b` by size
/// internally. Signatures are not checked here: pass STHs obtained through
/// [`Sth::from_signed`].
pub fn check_sth_pair(a: &Sth, b: &Sth, consistency_proof: &[[u8; 32]]) -> Option<Equivocation> {
    let (old, new) = if a.size <= b.size { (a, b) } else { (b, a) };
    if old.size == new.size {
        return (old.root != new.root).then_some(Equivocation::SameSizeDifferentRoots);
    }
    if verify_consistency(old.size, new.size, &old.root, &new.root, consistency_proof) {
        None
    } else {
        Some(Equivocation::Inconsistent)
    }
}

/// Signed `polls_open` entry (§17.7), signed by the EA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollsOpen {
    pub context_hash: [u8; 32],
    pub registry_id: [u8; 32],
    pub time: u64,
}

impl PollsOpen {
    pub fn sign(&self, ea_sk: &SigningKey) -> Value {
        sign_record(
            ea_sk,
            SIG_POLLS_OPEN,
            fields(vec![
                (0, Value::from("polls_open")),
                (1, Value::Uint(1)),
                (2, Value::from(self.context_hash)),
                (3, Value::from(self.registry_id)),
                (4, Value::Uint(self.time)),
            ]),
            5,
        )
    }

    pub fn from_signed(v: &Value, ea_pk: &VerifyingKey) -> Result<PollsOpen, Error> {
        let f = record_fields(v, "polls_open", 6)?;
        verify_record(ea_pk, SIG_POLLS_OPEN, v, 5)?;
        expect_version(f[1])?;
        Ok(PollsOpen {
            context_hash: bytes32(f[2])?,
            registry_id: bytes32(f[3])?,
            time: f[4].as_uint()?,
        })
    }
}

/// Signed `tally_cutoff` entry (§17.7), signed by the EA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TallyCutoff {
    pub context_hash: [u8; 32],
    pub time: u64,
}

impl TallyCutoff {
    pub fn sign(&self, ea_sk: &SigningKey) -> Value {
        sign_record(
            ea_sk,
            SIG_TALLY_CUTOFF,
            fields(vec![
                (0, Value::from("tally_cutoff")),
                (1, Value::Uint(1)),
                (2, Value::from(self.context_hash)),
                (3, Value::Uint(self.time)),
            ]),
            4,
        )
    }

    pub fn from_signed(v: &Value, ea_pk: &VerifyingKey) -> Result<TallyCutoff, Error> {
        let f = record_fields(v, "tally_cutoff", 5)?;
        verify_record(ea_pk, SIG_TALLY_CUTOFF, v, 4)?;
        expect_version(f[1])?;
        Ok(TallyCutoff {
            context_hash: bytes32(f[2])?,
            time: f[3].as_uint()?,
        })
    }
}

/// Signed `rejection` entry (§17.6), signed by the board key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub package_id: [u8; 32],
    pub reason: String,
}

impl Rejection {
    pub fn sign(&self, board_sk: &SigningKey) -> Value {
        sign_record(
            board_sk,
            SIG_REJECTION,
            fields(vec![
                (0, Value::from("rejection")),
                (1, Value::Uint(1)),
                (2, Value::from(self.package_id)),
                (3, Value::from(self.reason.as_str())),
            ]),
            4,
        )
    }

    pub fn from_signed(v: &Value, board_pk: &VerifyingKey) -> Result<Rejection, Error> {
        let f = record_fields(v, "rejection", 5)?;
        verify_record(board_pk, SIG_REJECTION, v, 4)?;
        expect_version(f[1])?;
        Ok(Rejection {
            package_id: bytes32(f[2])?,
            reason: f[3].as_text()?.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const MAX: u64 = 20;

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    fn entry(i: u64) -> Value {
        Value::Map(vec![
            (Value::Uint(0), Value::from("entry")),
            (Value::Uint(1), Value::Uint(i)),
        ])
    }

    fn log_of(n: u64) -> Log {
        let mut log = Log::new();
        for i in 0..n {
            log.append(entry(i));
        }
        log
    }

    fn pair_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        digest(
            "eg/v1/node",
            &[Value::Bytes(a.to_vec()), Value::Bytes(b.to_vec())],
        )
    }

    fn flip(h: &[u8; 32]) -> [u8; 32] {
        let mut out = *h;
        out[0] ^= 0x01;
        out
    }

    #[test]
    fn empty_root_matches_definition() {
        assert_eq!(empty_root(), digest("eg/v1/empty", &[]));
        assert_eq!(Log::new().root(), empty_root());
        assert!(Log::new().is_empty());
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let e = entry(7);
        let mut log = Log::new();
        assert_eq!(log.append(e.clone()), 0);
        assert_eq!(log.root(), digest("eg/v1/leaf", std::slice::from_ref(&e)));
        assert_eq!(log.root(), leaf_hash(&e));
        assert_eq!(log.len(), 1);
        assert_eq!(log.entry(0), Some(&e));
        assert_eq!(log.entry(1), None);
    }

    #[test]
    fn three_leaf_root_by_hand() {
        let log = log_of(3);
        let l: Vec<[u8; 32]> = (0..3).map(|i| leaf_hash(&entry(i))).collect();
        // MTH(D[3]) = node(node(l0, l1), l2)
        let expected = pair_hash(&pair_hash(&l[0], &l[1]), &l[2]);
        assert_eq!(log.root(), expected);
        assert_eq!(log.root(), node_hash(&node_hash(&l[0], &l[1]), &l[2]));
    }

    #[test]
    fn inclusion_proofs_verify_for_all_sizes_and_indices() {
        let log = log_of(MAX);
        for size in 1..=MAX {
            let root = log.root_at(size);
            for index in 0..size {
                let leaf = leaf_hash(&entry(index));
                let proof = log.inclusion_proof(index, size).unwrap();
                assert!(
                    verify_inclusion(&leaf, index, size, &proof, &root),
                    "size {size} index {index}"
                );

                // Tampered leaf.
                assert!(!verify_inclusion(&flip(&leaf), index, size, &proof, &root));
                // Wrong index.
                if size > 1 {
                    let other = (index + 1) % size;
                    assert!(!verify_inclusion(&leaf, other, size, &proof, &root));
                }
                // Flipped proof byte.
                for j in 0..proof.len() {
                    let mut bad = proof.clone();
                    bad[j] = flip(&bad[j]);
                    assert!(!verify_inclusion(&leaf, index, size, &bad, &root));
                }
                // Truncated proof.
                if !proof.is_empty() {
                    let short = &proof[..proof.len() - 1];
                    assert!(!verify_inclusion(&leaf, index, size, short, &root));
                }
            }
        }
    }

    #[test]
    fn inclusion_wrong_size_can_collide() {
        // RFC 9162 inclusion verification does not bind the tree size on its
        // own: for index 0 of a 3-leaf tree, the size-4 computation reproduces
        // the size-3 root. Callers take the size from the signed STH.
        let log = log_of(3);
        let leaf = leaf_hash(&entry(0));
        let proof = log.inclusion_proof(0, 3).unwrap();
        assert!(verify_inclusion(&leaf, 0, 3, &proof, &log.root()));
        assert!(verify_inclusion(&leaf, 0, 4, &proof, &log.root()));
        assert!(!verify_inclusion(&leaf, 0, 2, &proof, &log.root()));
    }

    #[test]
    fn inclusion_proof_out_of_range_is_none() {
        let log = log_of(5);
        assert!(log.inclusion_proof(5, 5).is_none());
        assert!(log.inclusion_proof(0, 6).is_none());
        assert!(log.inclusion_proof(0, 0).is_none());
    }

    #[test]
    fn consistency_proofs_verify_for_all_pairs() {
        let log = log_of(MAX);
        for n in 1..=MAX {
            for m in 1..=n {
                let old_root = log.root_at(m);
                let new_root = log.root_at(n);
                let proof = log.consistency_proof(m, n).unwrap();
                assert!(
                    verify_consistency(m, n, &old_root, &new_root, &proof),
                    "m {m} n {n}"
                );
                if m == n {
                    assert!(proof.is_empty());
                    continue;
                }
                // Wrong old root.
                assert!(!verify_consistency(
                    m,
                    n,
                    &flip(&old_root),
                    &new_root,
                    &proof
                ));
                // Wrong new root.
                assert!(!verify_consistency(
                    m,
                    n,
                    &old_root,
                    &flip(&new_root),
                    &proof
                ));
                // Tampered proof elements.
                for j in 0..proof.len() {
                    let mut bad = proof.clone();
                    bad[j] = flip(&bad[j]);
                    assert!(
                        !verify_consistency(m, n, &old_root, &new_root, &bad),
                        "m {m} n {n} tampered element {j}"
                    );
                }
            }
        }
    }

    #[test]
    fn consistency_power_of_two_old_sizes() {
        let log = log_of(MAX);
        for m in [1u64, 2, 4, 8, 16] {
            for n in m..=MAX {
                let proof = log.consistency_proof(m, n).unwrap();
                assert!(verify_consistency(
                    m,
                    n,
                    &log.root_at(m),
                    &log.root_at(n),
                    &proof
                ));
            }
        }
    }

    #[test]
    fn consistency_edge_cases() {
        let log = log_of(4);
        let root = log.root();
        assert_eq!(log.consistency_proof(0, 4), Some(Vec::new()));
        assert_eq!(log.consistency_proof(3, 2), None);
        assert_eq!(log.consistency_proof(2, 5), None);
        // Empty old tree: anything is consistent with an empty proof.
        assert!(verify_consistency(0, 4, &empty_root(), &root, &[]));
        assert!(!verify_consistency(0, 4, &empty_root(), &root, &[root]));
        // Equal sizes need equal roots.
        assert!(verify_consistency(4, 4, &root, &root, &[]));
        assert!(!verify_consistency(4, 4, &root, &flip(&root), &[]));
        assert!(!verify_consistency(4, 4, &root, &root, &[root]));
    }

    #[test]
    fn root_at_matches_shorter_log() {
        let long = log_of(MAX);
        for m in 0..=MAX {
            assert_eq!(long.root_at(m), log_of(m).root(), "m {m}");
        }
    }

    #[test]
    #[should_panic]
    fn root_at_beyond_len_panics() {
        log_of(2).root_at(3);
    }

    fn sth(log: &Log, size: u64) -> Sth {
        Sth {
            manifest_hash: [9u8; 32],
            size,
            root: log.root_at(size),
            timestamp: 1_700_000_000 + size,
        }
    }

    #[test]
    fn sth_sign_verify_round_trip() {
        let sk = SigningKey::generate(&mut rng(1));
        let pk = sk.verifying_key();
        let s = sth(&log_of(5), 5);
        let signed = s.sign(&sk);
        assert_eq!(Sth::from_signed(&signed, &pk), Ok(s));
    }

    #[test]
    fn sth_wrong_key_fails() {
        let sk = SigningKey::generate(&mut rng(1));
        let other = SigningKey::generate(&mut rng(2));
        let signed = sth(&log_of(5), 5).sign(&sk);
        assert_eq!(
            Sth::from_signed(&signed, &other.verifying_key()),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn sth_tampered_root_fails() {
        let sk = SigningKey::generate(&mut rng(1));
        let pk = sk.verifying_key();
        let mut s = sth(&log_of(5), 5);
        let signed = s.sign(&sk);
        s.root = flip(&s.root);
        if let Value::Map(mut entries) = signed {
            for (k, v) in entries.iter_mut() {
                if *k == Value::Uint(4) {
                    *v = Value::from(s.root);
                }
            }
            assert_eq!(
                Sth::from_signed(&Value::Map(entries), &pk),
                Err(Error::InvalidSignature)
            );
        } else {
            panic!("sth is not a map");
        }
    }

    #[test]
    fn equivocation_same_size_different_roots() {
        let sk = SigningKey::generate(&mut rng(1));
        let honest = log_of(5);
        let mut forked = Log::new();
        for i in 0..5 {
            forked.append(entry(if i == 2 { 99 } else { i }));
        }
        let a = sth(&honest, 5);
        let b = sth(&forked, 5);
        // Both are validly signed by the board.
        let pk = sk.verifying_key();
        let a = Sth::from_signed(&a.sign(&sk), &pk).unwrap();
        let b = Sth::from_signed(&b.sign(&sk), &pk).unwrap();
        assert_eq!(
            check_sth_pair(&a, &b, &[]),
            Some(Equivocation::SameSizeDifferentRoots)
        );
        assert_eq!(
            check_sth_pair(&b, &a, &[]),
            Some(Equivocation::SameSizeDifferentRoots)
        );
    }

    #[test]
    fn consistent_pair_is_not_equivocation() {
        let log = log_of(8);
        let a = sth(&log, 5);
        let b = sth(&log, 8);
        let proof = log.consistency_proof(5, 8).unwrap();
        assert_eq!(check_sth_pair(&a, &b, &proof), None);
        assert_eq!(check_sth_pair(&b, &a, &proof), None);
        assert_eq!(check_sth_pair(&a, &a, &[]), None);
    }

    #[test]
    fn inconsistent_pair_is_equivocation() {
        // The board shows a 5-entry log, then a 8-entry log where entry 2 was
        // changed. The proof it offers is computed on its own (forked) log.
        let honest = log_of(5);
        let mut forked = Log::new();
        for i in 0..8 {
            forked.append(entry(if i == 2 { 99 } else { i }));
        }
        let a = sth(&honest, 5);
        let b = sth(&forked, 8);
        let proof = forked.consistency_proof(5, 8).unwrap();
        assert_eq!(
            check_sth_pair(&a, &b, &proof),
            Some(Equivocation::Inconsistent)
        );
        assert_eq!(
            check_sth_pair(&b, &a, &proof),
            Some(Equivocation::Inconsistent)
        );
    }

    #[test]
    fn polls_open_round_trip_and_wrong_key() {
        let ea = SigningKey::generate(&mut rng(3));
        let other = SigningKey::generate(&mut rng(4));
        let p = PollsOpen {
            context_hash: [1u8; 32],
            registry_id: [2u8; 32],
            time: 1_700_000_000,
        };
        let signed = p.sign(&ea);
        assert_eq!(PollsOpen::from_signed(&signed, &ea.verifying_key()), Ok(p));
        assert_eq!(
            PollsOpen::from_signed(&signed, &other.verifying_key()),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn tally_cutoff_round_trip_and_wrong_key() {
        let ea = SigningKey::generate(&mut rng(3));
        let other = SigningKey::generate(&mut rng(4));
        let t = TallyCutoff {
            context_hash: [1u8; 32],
            time: 1_700_000_500,
        };
        let signed = t.sign(&ea);
        assert_eq!(
            TallyCutoff::from_signed(&signed, &ea.verifying_key()),
            Ok(t)
        );
        assert_eq!(
            TallyCutoff::from_signed(&signed, &other.verifying_key()),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn rejection_round_trip_and_wrong_key() {
        let board = SigningKey::generate(&mut rng(5));
        let other = SigningKey::generate(&mut rng(6));
        let r = Rejection {
            package_id: [3u8; 32],
            reason: "duplicate session".to_owned(),
        };
        let signed = r.sign(&board);
        assert_eq!(
            Rejection::from_signed(&signed, &board.verifying_key()),
            Ok(r)
        );
        assert_eq!(
            Rejection::from_signed(&signed, &other.verifying_key()),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn record_id_differs_from_leaf_hash() {
        let v = entry(1);
        assert_ne!(record_id(&v), leaf_hash(&v));
        assert_eq!(
            record_id(&v),
            digest("eg/v1/record-id", std::slice::from_ref(&v))
        );
    }
}
