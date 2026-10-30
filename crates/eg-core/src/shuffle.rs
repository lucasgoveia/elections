//! Verifiable re-encryption shuffle for eg/v1 (SPEC.md §19.2, §19.3, Appendix B).
//!
//! A mixer permutes and re-encrypts a list of rows; each row is a tuple of
//! `w` ciphertexts that move together. The Terelius-Wikström proof shows, for
//! a public list `E` and output `Ẽ`, that `Ẽ_i[k] = ReEnc(E_{π(i)}[k]; r̃_{i,k})`
//! for some permutation π, without revealing π or the nonces.
//!
//! Indices are 0-based in code. Where the spec writes a 1-based index `j` or
//! `i` inside a hash or generator label, the code uses `j + 1` or `i + 1`.

use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::cbor::{self, record_fields, Value};
use crate::elgamal::Ciphertext;
use crate::error::Error;
use crate::group::{
    point_from_value, point_to_value, random_scalar, scalar_from_value, scalar_to_value,
    RistrettoPoint, Scalar, B,
};
use crate::hash::{digest, hash_to_scalar};
use crate::sign::{sign_record, verify_record, SigningKey, VerifyingKey};

/// One row: `w` ciphertexts that are shuffled together (SPEC.md §19.1).
pub type Row = Vec<Ciphertext>;

const TAG_SHUFFLE: &str = "eg/v1/shuffle";
const TAG_SHUFFLE_U: &str = "eg/v1/shuffle-u";
const TAG_MIX_LIST: &str = "eg/v1/mix-list";
const SIG_MIX: &str = "eg/v1/sig/mix";
const MIX_FIELDS: usize = 11;
const MIX_SIG_KEY: u64 = 10;
const PROOF_FIELDS: usize = 11;

fn tally(msg: &str) -> Error {
    Error::Tally(msg.to_owned())
}

/// CBOR value of a list: an array of rows, each an array of `[point, point]`
/// ciphertexts (SPEC.md §19.2, `mix_output` field 6 and 7).
pub fn list_to_value(list: &[Row]) -> Value {
    Value::Array(
        list.iter()
            .map(|row| Value::Array(row.iter().map(Ciphertext::to_value).collect()))
            .collect(),
    )
}

/// Decodes a list. Requires at least one row and at least one ciphertext per
/// row, and all rows of the same width. Errors are [`Error::Tally`] for shape
/// problems and the usual codec errors otherwise.
pub fn list_from_value(v: &Value) -> Result<Vec<Row>, Error> {
    let rows = v.as_array()?;
    if rows.is_empty() {
        return Err(tally("shuffle list has no rows"));
    }
    let mut out: Vec<Row> = Vec::with_capacity(rows.len());
    for row in rows {
        let cts = row.as_array()?;
        if cts.is_empty() {
            return Err(tally("shuffle row has no ciphertexts"));
        }
        out.push(
            cts.iter()
                .map(Ciphertext::from_value)
                .collect::<Result<Row, Error>>()?,
        );
    }
    let w = out[0].len();
    if out.iter().any(|r| r.len() != w) {
        return Err(tally("shuffle list is ragged"));
    }
    Ok(out)
}

/// `Digest("eg/v1/mix-list", list)` (SPEC.md §19.2, `mix_output` field 6).
pub fn list_digest(list: &[Row]) -> [u8; 32] {
    digest(TAG_MIX_LIST, &[list_to_value(list)])
}

/// Mixer secret: the permutation and the re-encryption nonces. Wiped on drop;
/// `Debug` does not print its contents.
pub struct ShuffleWitness {
    /// Output row `i` is input row `pi[i]`.
    pi: Vec<usize>,
    /// Nonce `r[i][k]` for output row `i`, component `k`.
    r: Vec<Vec<Scalar>>,
}

impl Drop for ShuffleWitness {
    fn drop(&mut self) {
        self.pi.zeroize();
        self.r.zeroize();
    }
}

impl core::fmt::Debug for ShuffleWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShuffleWitness").finish_non_exhaustive()
    }
}

/// Uniform integer in `0..bound` by rejection sampling on 64-bit draws.
fn uniform_index<R: RngCore>(rng: &mut R, bound: u64) -> u64 {
    debug_assert!(bound >= 1);
    // 2^64 mod bound; draws in 0..=zone map uniformly onto 0..bound.
    let reject = (u64::MAX - bound + 1) % bound;
    let zone = u64::MAX - reject;
    loop {
        let x = rng.next_u64();
        if x <= zone {
            return x % bound;
        }
    }
}

/// §19.2: picks a uniform permutation (Fisher-Yates) and fresh nonces, and
/// returns the re-encrypted list under public key `k`.
///
/// Panics if `input` is empty, ragged, or has a zero-width row (programming
/// errors: lists come from the protocol, not from untrusted input).
pub fn shuffle<R: RngCore + CryptoRng>(
    rng: &mut R,
    k: &RistrettoPoint,
    input: &[Row],
) -> (Vec<Row>, ShuffleWitness) {
    let n = input.len();
    let w = input.first().map_or(0, Vec::len);
    assert!(
        n >= 1 && w >= 1 && has_shape(input, n, w),
        "shuffle input must be N x w with N, w >= 1"
    );

    let mut pi: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = uniform_index(rng, i as u64 + 1) as usize;
        pi.swap(i, j);
    }

    let mut r: Vec<Vec<Scalar>> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut row = Vec::with_capacity(w);
        for _ in 0..w {
            row.push(random_scalar(rng));
        }
        r.push(row);
    }

    let output: Vec<Row> = (0..n)
        .map(|i| {
            (0..w)
                .map(|kk| input[pi[i]][kk].reencrypt(&r[i][kk], k))
                .collect()
        })
        .collect();

    (output, ShuffleWitness { pi, r })
}

/// Terelius-Wikström shuffle proof (SPEC.md §19.3). Field names follow the
/// spec: `c_vec` = c_1..c_N, `c_hat` = ĉ_1..ĉ_N, `s4` = s4[1..w], and so on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShuffleProof {
    pub c_vec: Vec<RistrettoPoint>,
    pub c_hat: Vec<RistrettoPoint>,
    pub c: Scalar,
    pub s1: Scalar,
    pub s2: Scalar,
    pub s3: Scalar,
    pub s4: Vec<Scalar>,
    pub s_hat: Vec<Scalar>,
    pub s_prime: Vec<Scalar>,
}

impl ShuffleProof {
    /// Encodes as the CBOR `shuffle_proof` record (SPEC.md §19.3).
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            kv(0, Value::from("shuffle_proof")),
            kv(1, Value::Uint(1)),
            kv(2, points_value(&self.c_vec)),
            kv(3, points_value(&self.c_hat)),
            kv(4, scalar_to_value(&self.c)),
            kv(5, scalar_to_value(&self.s1)),
            kv(6, scalar_to_value(&self.s2)),
            kv(7, scalar_to_value(&self.s3)),
            kv(8, scalars_value(&self.s4)),
            kv(9, scalars_value(&self.s_hat)),
            kv(10, scalars_value(&self.s_prime)),
        ])
    }

    /// Strict decoding of a `shuffle_proof` record. Rejects wrong tag or
    /// version, empty vectors, and vectors `c_vec`, `c_hat`, `s_hat`, `s_prime`
    /// of unequal length. Lengths are otherwise checked by [`verify_shuffle`].
    pub fn from_value(v: &Value) -> Result<ShuffleProof, Error> {
        let f = record_fields(v, "shuffle_proof", PROOF_FIELDS)?;
        expect_version(f[1])?;
        let c_vec = points_from(f[2])?;
        let c_hat = points_from(f[3])?;
        let s_hat = scalars_from(f[9])?;
        let s_prime = scalars_from(f[10])?;
        let n = c_vec.len();
        if c_hat.len() != n || s_hat.len() != n || s_prime.len() != n {
            return Err(tally("shuffle proof vectors have unequal lengths"));
        }
        Ok(ShuffleProof {
            c_vec,
            c_hat,
            c: scalar_from_value(f[4])?,
            s1: scalar_from_value(f[5])?,
            s2: scalar_from_value(f[6])?,
            s3: scalar_from_value(f[7])?,
            s4: scalars_from(f[8])?,
            s_hat,
            s_prime,
        })
    }
}

/// Public statement of one mix step (SPEC.md §19.3). `k` is the election
/// public key `K`, `input` is `E`, `output` is `Ẽ`. `region` and `step` are
/// part of the context `ctx` and of the generator label.
pub struct ShuffleStatement<'a> {
    pub context_hash: [u8; 32],
    pub contest_index: u64,
    pub region: &'a str,
    pub step: u64,
    pub k: RistrettoPoint,
    pub input: &'a [Row],
    pub output: &'a [Row],
}

/// Generator `Gen(label, i)` with `label = ["shuffle", contest_index, region,
/// step]` (SPEC.md §19.3, §5.2). `group::gen` takes a text label only, so the
/// array label is hashed here: SHA-512(CBOR(["eg/v1/gen", context_hash,
/// label, i])), then `from_uniform_bytes`.
fn shuffle_gen(
    context_hash: &[u8; 32],
    contest_index: u64,
    region: &str,
    step: u64,
    i: u64,
) -> RistrettoPoint {
    let label = Value::Array(vec![
        Value::from("shuffle"),
        Value::Uint(contest_index),
        Value::from(region),
        Value::Uint(step),
    ]);
    let input = cbor::encode(&Value::Array(vec![
        Value::from("eg/v1/gen"),
        Value::from(*context_hash),
        label,
        Value::Uint(i),
    ]));
    let digest: [u8; 64] = Sha512::digest(&input).into();
    RistrettoPoint::from_uniform_bytes(&digest)
}

/// `H_0..H_N`: `H_0` is the chain start, `H_i` (i ≥ 1) the commitment base for
/// output row `i - 1`.
fn generators(st: &ShuffleStatement, n: usize) -> Vec<RistrettoPoint> {
    (0..=(n as u64))
        .map(|i| shuffle_gen(&st.context_hash, st.contest_index, st.region, st.step, i))
        .collect()
}

/// `ctx = ["shuffle", context_hash, contest_index, region, step]`.
fn ctx_value(st: &ShuffleStatement) -> Value {
    Value::Array(vec![
        Value::from("shuffle"),
        Value::from(st.context_hash),
        Value::Uint(st.contest_index),
        Value::from(st.region),
        Value::Uint(st.step),
    ])
}

/// `u_j = HashToScalar("eg/v1/shuffle-u", ctx, E, Ẽ, c_vec, j)` for
/// j = 1..N, returned 0-based.
fn u_challenges(ctx: &Value, e: &Value, o: &Value, c_vec: &[RistrettoPoint]) -> Vec<Scalar> {
    (1..=c_vec.len() as u64)
        .map(|j| {
            hash_to_scalar(
                TAG_SHUFFLE_U,
                &[
                    ctx.clone(),
                    e.clone(),
                    o.clone(),
                    points_value(c_vec),
                    Value::Uint(j),
                ],
            )
        })
        .collect()
}

/// The commitments `T1, T2, T3, T4α, T4β, T̂` hashed into the challenge.
struct Commitments {
    t1: RistrettoPoint,
    t2: RistrettoPoint,
    t3: RistrettoPoint,
    t4a: Vec<RistrettoPoint>,
    t4b: Vec<RistrettoPoint>,
    that: Vec<RistrettoPoint>,
}

/// `c = HashToScalar("eg/v1/shuffle", ctx, E, Ẽ, c_vec, ĉ_vec, T1..T̂)`.
fn challenge(
    ctx: &Value,
    e: &Value,
    o: &Value,
    c_vec: &[RistrettoPoint],
    c_hat: &[RistrettoPoint],
    t: &Commitments,
) -> Scalar {
    hash_to_scalar(
        TAG_SHUFFLE,
        &[
            ctx.clone(),
            e.clone(),
            o.clone(),
            points_value(c_vec),
            points_value(c_hat),
            point_to_value(&t.t1),
            point_to_value(&t.t2),
            point_to_value(&t.t3),
            points_value(&t.t4a),
            points_value(&t.t4b),
            points_value(&t.that),
        ],
    )
}

/// Prover: `ĉ_{i-1}` with `ĉ_0 = H_0`, 0-based `i` in `0..N`.
fn chain_prev(hs: &[RistrettoPoint], c_hat: &[RistrettoPoint], i: usize) -> RistrettoPoint {
    if i == 0 {
        hs[0]
    } else {
        c_hat[i - 1]
    }
}

/// §19.3 prover. The witness must match the statement: `pi` a permutation of
/// `0..N` and `r` of shape N x w. Panics otherwise (programming error).
pub fn prove_shuffle<R: RngCore + CryptoRng>(
    rng: &mut R,
    st: &ShuffleStatement,
    witness: &ShuffleWitness,
) -> ShuffleProof {
    let n = st.input.len();
    let w = st.input.first().map_or(0, Vec::len);
    assert!(
        n >= 1 && w >= 1 && has_shape(st.input, n, w) && has_shape(st.output, n, w),
        "shuffle statement lists must be N x w with N, w >= 1"
    );
    assert_eq!(witness.pi.len(), n, "witness permutation has wrong length");
    assert!(
        witness.r.len() == n && witness.r.iter().all(|row| row.len() == w),
        "witness nonces have wrong shape"
    );
    let mut seen = vec![false; n];
    for &j in &witness.pi {
        assert!(j < n && !seen[j], "witness is not a permutation");
        seen[j] = true;
    }

    let pi = &witness.pi;
    let hs = generators(st, n);
    let ctx = ctx_value(st);
    let e = list_to_value(st.input);
    let o = list_to_value(st.output);

    // Step 1: permutation commitment. c_{π(i)} = ρ_{π(i)}·B + H_i.
    let mut rho: Vec<Scalar> = (0..n).map(|_| random_scalar(rng)).collect();
    let mut c_vec = vec![RistrettoPoint::default(); n];
    for (i, &j) in pi.iter().enumerate() {
        c_vec[j] = rho[j] * B + hs[i + 1];
    }

    // Step 2: challenges u_j and u'_i = u_{π(i)}.
    let u = u_challenges(&ctx, &e, &o, &c_vec);
    let up: Vec<Scalar> = pi.iter().map(|&j| u[j]).collect();

    // Step 3: commitment chain ĉ_i = ρ̂_i·B + u'_i·ĉ_{i-1}.
    let mut rho_hat: Vec<Scalar> = (0..n).map(|_| random_scalar(rng)).collect();
    let mut c_hat: Vec<RistrettoPoint> = Vec::with_capacity(n);
    for i in 0..n {
        let next = rho_hat[i] * B + up[i] * chain_prev(&hs, &c_hat, i);
        c_hat.push(next);
    }

    // Step 4: derived witnesses. v_N = 1, v_i = u'_{i+1}·v_{i+1}.
    let mut v = vec![Scalar::ONE; n];
    for i in (0..n - 1).rev() {
        v[i] = up[i + 1] * v[i + 1];
    }
    let mut rho_bar: Scalar = rho.iter().sum();
    let mut rho_hat_sum: Scalar = (0..n).map(|i| rho_hat[i] * v[i]).sum();
    let mut rho_prime: Scalar = (0..n).map(|j| rho[j] * u[j]).sum();
    let mut r_tilde: Vec<Scalar> = (0..w)
        .map(|kk| (0..n).map(|i| witness.r[i][kk] * up[i]).sum())
        .collect();

    // Step 5: commitments. Constant-time multiplication: the prover handles
    // secrets.
    let mut w1 = random_scalar(rng);
    let mut w2 = random_scalar(rng);
    let mut w3 = random_scalar(rng);
    let mut w4: Vec<Scalar> = (0..w).map(|_| random_scalar(rng)).collect();
    let mut wh: Vec<Scalar> = (0..n).map(|_| random_scalar(rng)).collect();
    let mut wp: Vec<Scalar> = (0..n).map(|_| random_scalar(rng)).collect();

    let t1 = w1 * B;
    let t2 = w2 * B;
    let t3 = w3 * B + msm(&wp, &hs[1..]);
    let t4a: Vec<RistrettoPoint> = (0..w)
        .map(|kk| -w4[kk] * B + msm(&wp, &column(st.output, kk, false)))
        .collect();
    let t4b: Vec<RistrettoPoint> = (0..w)
        .map(|kk| -w4[kk] * st.k + msm(&wp, &column(st.output, kk, true)))
        .collect();
    let that: Vec<RistrettoPoint> = (0..n)
        .map(|i| wh[i] * B + wp[i] * chain_prev(&hs, &c_hat, i))
        .collect();
    let t = Commitments {
        t1,
        t2,
        t3,
        t4a,
        t4b,
        that,
    };

    // Step 6: challenge.
    let c = challenge(&ctx, &e, &o, &c_vec, &c_hat, &t);

    // Step 7: responses.
    let proof = ShuffleProof {
        c_vec,
        c_hat,
        c,
        s1: w1 + c * rho_bar,
        s2: w2 + c * rho_hat_sum,
        s3: w3 + c * rho_prime,
        s4: (0..w).map(|kk| w4[kk] + c * r_tilde[kk]).collect(),
        s_hat: (0..n).map(|i| wh[i] + c * rho_hat[i]).collect(),
        s_prime: (0..n).map(|i| wp[i] + c * up[i]).collect(),
    };

    rho.zeroize();
    rho_hat.zeroize();
    v.zeroize();
    rho_bar.zeroize();
    rho_hat_sum.zeroize();
    rho_prime.zeroize();
    r_tilde.zeroize();
    w1.zeroize();
    w2.zeroize();
    w3.zeroize();
    w4.zeroize();
    wh.zeroize();
    wp.zeroize();

    proof
}

/// §19.3 verifier. Checks the shapes of `input`, `output` and the proof, then
/// recomputes the commitments and the challenge. Uses variable-time
/// multi-scalar multiplication, which handles no secrets.
pub fn verify_shuffle(st: &ShuffleStatement, proof: &ShuffleProof) -> bool {
    let n = st.input.len();
    let w = st.input.first().map_or(0, Vec::len);
    if n == 0 || w == 0 || !has_shape(st.input, n, w) || !has_shape(st.output, n, w) {
        return false;
    }
    if proof.c_vec.len() != n
        || proof.c_hat.len() != n
        || proof.s_hat.len() != n
        || proof.s_prime.len() != n
        || proof.s4.len() != w
    {
        return false;
    }

    let hs = generators(st, n);
    let ctx = ctx_value(st);
    let e = list_to_value(st.input);
    let o = list_to_value(st.output);

    // Step 1 and 2.
    let u = u_challenges(&ctx, &e, &o, &proof.c_vec);
    let prod_u: Scalar = u.iter().product();
    let c_bar = proof.c_vec.iter().sum::<RistrettoPoint>() - hs[1..].iter().sum::<RistrettoPoint>();
    let c_hat_pi = proof.c_hat[n - 1] - prod_u * hs[0];
    let c_prime = vmsm(&u, &proof.c_vec);
    let alpha_p: Vec<RistrettoPoint> = (0..w)
        .map(|kk| vmsm(&u, &column(st.input, kk, false)))
        .collect();
    let beta_p: Vec<RistrettoPoint> = (0..w)
        .map(|kk| vmsm(&u, &column(st.input, kk, true)))
        .collect();

    // Step 3: recomputed commitments.
    let t = Commitments {
        t1: proof.s1 * B - proof.c * c_bar,
        t2: proof.s2 * B - proof.c * c_hat_pi,
        t3: proof.s3 * B + vmsm(&proof.s_prime, &hs[1..]) - proof.c * c_prime,
        t4a: (0..w)
            .map(|kk| {
                -proof.s4[kk] * B + vmsm(&proof.s_prime, &column(st.output, kk, false))
                    - proof.c * alpha_p[kk]
            })
            .collect(),
        t4b: (0..w)
            .map(|kk| {
                -proof.s4[kk] * st.k + vmsm(&proof.s_prime, &column(st.output, kk, true))
                    - proof.c * beta_p[kk]
            })
            .collect(),
        that: (0..n)
            .map(|i| {
                proof.s_hat[i] * B + proof.s_prime[i] * chain_prev(&hs, &proof.c_hat, i)
                    - proof.c * proof.c_hat[i]
            })
            .collect(),
    };

    // Step 4.
    challenge(&ctx, &e, &o, &proof.c_vec, &proof.c_hat, &t) == proof.c
}

/// Signed `mix_output` record (SPEC.md §19.2). `output` is `Ẽ` and `proof` is
/// the shuffle proof of this step. `input_digest` is
/// [`list_digest`] of the input list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixOutput {
    pub context_hash: [u8; 32],
    pub contest_index: u64,
    pub mixer: u64,
    pub step: u64,
    pub input_digest: [u8; 32],
    pub output: Vec<Row>,
    pub proof: ShuffleProof,
    pub region: String,
}

impl MixOutput {
    /// Builds the record signed with the mixer's key (tag `eg/v1/sig/mix`).
    pub fn sign(&self, sk: &SigningKey) -> Value {
        sign_record(
            sk,
            SIG_MIX,
            vec![
                kv(0, Value::from("mix_output")),
                kv(1, Value::Uint(1)),
                kv(2, Value::from(self.context_hash)),
                kv(3, Value::Uint(self.contest_index)),
                kv(4, Value::Uint(self.mixer)),
                kv(5, Value::Uint(self.step)),
                kv(6, Value::from(self.input_digest)),
                kv(7, list_to_value(&self.output)),
                kv(8, self.proof.to_value()),
                kv(9, Value::from(self.region.as_str())),
            ],
            MIX_SIG_KEY,
        )
    }

    /// Decodes and verifies a signed `mix_output` record with the mixer's
    /// public key. The shuffle proof is decoded but not verified here; use
    /// [`verify_shuffle`] with the statement.
    pub fn from_signed(v: &Value, mixer_pk: &VerifyingKey) -> Result<MixOutput, Error> {
        let f = record_fields(v, "mix_output", MIX_FIELDS)?;
        verify_record(mixer_pk, SIG_MIX, v, MIX_SIG_KEY)?;
        expect_version(f[1])?;
        Ok(MixOutput {
            context_hash: digest32(f[2])?,
            contest_index: f[3].as_uint()?,
            mixer: f[4].as_uint()?,
            step: f[5].as_uint()?,
            input_digest: digest32(f[6])?,
            output: list_from_value(f[7])?,
            proof: ShuffleProof::from_value(f[8])?,
            region: f[9].as_text()?.to_owned(),
        })
    }
}

fn kv(key: u64, value: Value) -> (Value, Value) {
    (Value::Uint(key), value)
}

fn has_shape(list: &[Row], n: usize, w: usize) -> bool {
    list.len() == n && list.iter().all(|r| r.len() == w)
}

/// Column `k` of a list: the α (or β if `beta`) components of each row.
fn column(list: &[Row], k: usize, beta: bool) -> Vec<RistrettoPoint> {
    list.iter()
        .map(|row| if beta { row[k].beta } else { row[k].alpha })
        .collect()
}

/// Constant-time multi-scalar multiplication (prover).
fn msm(scalars: &[Scalar], points: &[RistrettoPoint]) -> RistrettoPoint {
    RistrettoPoint::multiscalar_mul(scalars, points)
}

/// Variable-time multi-scalar multiplication (verifier only).
fn vmsm(scalars: &[Scalar], points: &[RistrettoPoint]) -> RistrettoPoint {
    RistrettoPoint::vartime_multiscalar_mul(scalars, points)
}

fn points_value(ps: &[RistrettoPoint]) -> Value {
    Value::Array(ps.iter().map(point_to_value).collect())
}

fn scalars_value(ss: &[Scalar]) -> Value {
    Value::Array(ss.iter().map(scalar_to_value).collect())
}

/// Decodes a non-empty `[+ point]` array.
fn points_from(v: &Value) -> Result<Vec<RistrettoPoint>, Error> {
    let items = v.as_array()?;
    if items.is_empty() {
        return Err(tally("shuffle proof vector is empty"));
    }
    items.iter().map(point_from_value).collect()
}

/// Decodes a non-empty `[+ scalar]` array.
fn scalars_from(v: &Value) -> Result<Vec<Scalar>, Error> {
    let items = v.as_array()?;
    if items.is_empty() {
        return Err(tally("shuffle proof vector is empty"));
    }
    items.iter().map(scalar_from_value).collect()
}

fn expect_version(v: &Value) -> Result<(), Error> {
    if v.as_uint()? == 1 {
        Ok(())
    } else {
        Err(tally("unsupported record version"))
    }
}

fn digest32(v: &Value) -> Result<[u8; 32], Error> {
    v.as_bytes()?
        .try_into()
        .map_err(|_| tally("digest must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::dlog_bounded;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const CTX: [u8; 32] = [0x11; 32];

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn nonzero(rng: &mut ChaCha20Rng) -> Scalar {
        loop {
            let r = random_scalar(rng);
            if r != Scalar::ZERO {
                return r;
            }
        }
    }

    fn encrypt_row(rng: &mut ChaCha20Rng, ms: &[u32], k: &RistrettoPoint) -> Row {
        let mut row = Vec::with_capacity(ms.len());
        for &m in ms {
            row.push(Ciphertext::encrypt(m, &nonzero(rng), k).unwrap());
        }
        row
    }

    fn decrypt_row(row: &Row, s: &Scalar) -> Vec<u64> {
        row.iter()
            .map(|c| dlog_bounded(&c.decrypt_to_point(s), 20).unwrap())
            .collect()
    }

    fn stmt<'a>(k: RistrettoPoint, input: &'a [Row], output: &'a [Row]) -> ShuffleStatement<'a> {
        ShuffleStatement {
            context_hash: CTX,
            contest_index: 3,
            region: "north",
            step: 2,
            k,
            input,
            output,
        }
    }

    struct Run {
        s: Scalar,
        k: RistrettoPoint,
        input: Vec<Row>,
        output: Vec<Row>,
        wit: ShuffleWitness,
        proof: ShuffleProof,
    }

    /// Random input of N rows of width w with plaintexts in 0..10, shuffled and
    /// proved.
    fn run(seed: u8, n: usize, w: usize) -> Run {
        let mut rng = rng(seed);
        let s = random_scalar(&mut rng);
        let k = s * B;
        let mut input = Vec::with_capacity(n);
        for _ in 0..n {
            let ms: Vec<u32> = (0..w).map(|_| rng.next_u32() % 10).collect();
            input.push(encrypt_row(&mut rng, &ms, &k));
        }
        let (output, wit) = shuffle(&mut rng, &k, &input);
        let proof = prove_shuffle(&mut rng, &stmt(k, &input, &output), &wit);
        Run {
            s,
            k,
            input,
            output,
            wit,
            proof,
        }
    }

    fn check(k: RistrettoPoint, input: &[Row], output: &[Row], proof: &ShuffleProof) -> bool {
        verify_shuffle(&stmt(k, input, output), proof)
    }

    fn with_field(v: &Value, key: u64, new: Value) -> Value {
        let Value::Map(entries) = v else {
            panic!("expected a map")
        };
        Value::Map(
            entries
                .iter()
                .map(|(k, val)| {
                    if *k == Value::Uint(key) {
                        (k.clone(), new.clone())
                    } else {
                        (k.clone(), val.clone())
                    }
                })
                .collect(),
        )
    }

    #[test]
    fn shuffle_preserves_rows_and_multiset() {
        let r = run(1, 5, 3);
        let dec_in: Vec<Vec<u64>> = r.input.iter().map(|row| decrypt_row(row, &r.s)).collect();
        let dec_out: Vec<Vec<u64>> = r.output.iter().map(|row| decrypt_row(row, &r.s)).collect();

        // Output row i is input row pi[i], all components together.
        for i in 0..5 {
            assert_eq!(dec_out[i], dec_in[r.wit.pi[i]]);
            assert_ne!(r.output[i][0], r.input[r.wit.pi[i]][0]);
        }
        // pi is a permutation.
        let mut p = r.wit.pi.clone();
        p.sort_unstable();
        assert_eq!(p, (0..5).collect::<Vec<_>>());
        // Same multiset of rows.
        let mut a = dec_in.clone();
        let mut b = dec_out.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }

    #[test]
    fn single_row_shuffle_is_identity_permutation() {
        let r = run(2, 1, 1);
        assert_eq!(r.wit.pi, vec![0]);
        assert!(check(r.k, &r.input, &r.output, &r.proof));
    }

    #[test]
    fn honest_proofs_verify() {
        for (seed, (n, w)) in [(1, 1), (2, 1), (5, 1), (5, 3), (10, 2)]
            .into_iter()
            .enumerate()
        {
            let r = run(10 + seed as u8, n, w);
            assert!(check(r.k, &r.input, &r.output, &r.proof), "N={n} w={w}");
        }
    }

    #[test]
    fn identity_witness_zero_nonces_verifies() {
        // Output equal to input under a trivial witness is a valid shuffle;
        // unlinkability relies on at least one honest mixer, not on this proof.
        let mut rng = rng(3);
        let s = random_scalar(&mut rng);
        let k = s * B;
        let input: Vec<Row> = (0..4)
            .map(|i| encrypt_row(&mut rng, &[i, i + 1], &k))
            .collect();
        let wit = ShuffleWitness {
            pi: (0..4).collect(),
            r: vec![vec![Scalar::ZERO; 2]; 4],
        };
        let output = input.clone();
        let proof = prove_shuffle(&mut rng, &stmt(k, &input, &output), &wit);
        assert!(check(k, &input, &output, &proof));
    }

    #[test]
    fn tampered_output_ciphertext_fails() {
        let r = run(20, 5, 3);
        let mut rng = rng(21);
        let mut out = r.output.clone();
        let orig = decrypt_row(&out[0], &r.s)[0] as u32;
        out[0][0] = Ciphertext::encrypt((orig + 1) % 10, &nonzero(&mut rng), &r.k).unwrap();
        assert!(!check(r.k, &r.input, &out, &r.proof));
    }

    #[test]
    fn swapped_components_within_row_fail() {
        let r = run(22, 5, 3);
        let mut out = r.output.clone();
        out[0].swap(0, 1);
        assert!(!check(r.k, &r.input, &out, &r.proof));
    }

    #[test]
    fn duplicated_and_dropped_rows_fail() {
        let r = run(23, 5, 3);
        let mut out = r.output.clone();
        out[1] = out[0].clone();
        assert!(!check(r.k, &r.input, &out, &r.proof));
    }

    #[test]
    fn tampered_proof_scalars_and_points_fail() {
        let r = run(24, 5, 3);
        assert!(check(r.k, &r.input, &r.output, &r.proof));
        let muts: Vec<fn(&mut ShuffleProof)> = vec![
            |p| p.c += Scalar::ONE,
            |p| p.s1 += Scalar::ONE,
            |p| p.s2 += Scalar::ONE,
            |p| p.s3 += Scalar::ONE,
            |p| p.s4[0] += Scalar::ONE,
            |p| p.s_hat[0] += Scalar::ONE,
            |p| p.s_prime[0] += Scalar::ONE,
            |p| p.c_vec[0] += B,
            |p| p.c_hat[0] += B,
        ];
        for (i, m) in muts.iter().enumerate() {
            let mut p = r.proof.clone();
            m(&mut p);
            assert!(!check(r.k, &r.input, &r.output, &p), "mutation {i}");
        }
    }

    #[test]
    fn wrong_key_fails() {
        let r = run(25, 5, 3);
        assert!(!check(r.k + B, &r.input, &r.output, &r.proof));
    }

    #[test]
    fn wrong_statement_metadata_fails() {
        let r = run(26, 5, 3);
        let base = stmt(r.k, &r.input, &r.output);
        let variants = [
            ShuffleStatement { step: 3, ..base },
            ShuffleStatement {
                region: "south",
                ..stmt(r.k, &r.input, &r.output)
            },
            ShuffleStatement {
                contest_index: 4,
                ..stmt(r.k, &r.input, &r.output)
            },
            ShuffleStatement {
                context_hash: [0x22; 32],
                ..stmt(r.k, &r.input, &r.output)
            },
        ];
        for (i, st) in variants.iter().enumerate() {
            assert!(!verify_shuffle(st, &r.proof), "variant {i}");
        }
    }

    #[test]
    fn shape_mismatch_fails() {
        let r = run(27, 5, 3);
        let short = r.output[..4].to_vec();
        assert!(!check(r.k, &r.input, &short, &r.proof));
        let mut bad_proof = r.proof.clone();
        bad_proof.s4.push(Scalar::ONE);
        assert!(!check(r.k, &r.input, &r.output, &bad_proof));
    }

    #[test]
    fn proof_round_trip() {
        let r = run(30, 5, 3);
        let v = r.proof.to_value();
        assert_eq!(ShuffleProof::from_value(&v), Ok(r.proof.clone()));
        let bytes = cbor::encode(&v);
        let decoded = cbor::decode(&bytes).unwrap();
        assert_eq!(ShuffleProof::from_value(&decoded), Ok(r.proof.clone()));
    }

    #[test]
    fn proof_decoding_is_strict() {
        let r = run(31, 3, 1);
        let v = r.proof.to_value();
        assert!(ShuffleProof::from_value(&with_field(&v, 1, Value::Uint(2))).is_err());
        assert!(ShuffleProof::from_value(&with_field(&v, 8, Value::Array(vec![]))).is_err());
        let mut short = r.proof.clone();
        short.c_hat.pop();
        assert!(ShuffleProof::from_value(&short.to_value()).is_err());
        assert!(ShuffleProof::from_value(&with_field(&v, 4, Value::Uint(0))).is_err());
    }

    #[test]
    fn list_round_trip_and_ragged_rejected() {
        let r = run(32, 4, 2);
        let v = list_to_value(&r.input);
        assert_eq!(list_from_value(&v), Ok(r.input.clone()));

        let ct = Ciphertext::zero().to_value();
        let ragged = Value::Array(vec![
            Value::Array(vec![ct.clone(), ct.clone()]),
            Value::Array(vec![ct.clone()]),
        ]);
        assert!(matches!(list_from_value(&ragged), Err(Error::Tally(_))));
        assert!(matches!(
            list_from_value(&Value::Array(vec![])),
            Err(Error::Tally(_))
        ));
        assert!(matches!(
            list_from_value(&Value::Array(vec![Value::Array(vec![])])),
            Err(Error::Tally(_))
        ));
    }

    #[test]
    fn list_digest_depends_on_content() {
        let r = run(33, 3, 2);
        let mut other = r.input.clone();
        other[0].swap(0, 1);
        assert_eq!(list_digest(&r.input), list_digest(&r.input.clone()));
        assert_ne!(list_digest(&r.input), list_digest(&other));
    }

    #[test]
    fn mix_output_sign_round_trip_and_tamper() {
        let r = run(34, 5, 3);
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        let mo = MixOutput {
            context_hash: CTX,
            contest_index: 3,
            mixer: 2,
            step: 2,
            input_digest: list_digest(&r.input),
            output: r.output.clone(),
            proof: r.proof.clone(),
            region: "north".to_owned(),
        };
        let rec = mo.sign(&sk);
        assert_eq!(MixOutput::from_signed(&rec, &pk), Ok(mo.clone()));

        let tampered = with_field(&rec, 9, Value::from("south"));
        assert_eq!(
            MixOutput::from_signed(&tampered, &pk),
            Err(Error::InvalidSignature)
        );

        let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert_eq!(
            MixOutput::from_signed(&rec, &other),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn uniform_index_in_range() {
        let mut rng = rng(35);
        for bound in [1u64, 2, 3, 7, 1000] {
            for _ in 0..200 {
                assert!(uniform_index(&mut rng, bound) < bound);
            }
        }
    }
}
