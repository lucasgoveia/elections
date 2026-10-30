//! Sigma protocols for eg/v1 (SPEC.md §11): Schnorr, Chaum-Pedersen, and the
//! sum and decryption-share statements built on Chaum-Pedersen.
//!
//! Proofs are in compact form `(c, v)` with strong Fiat-Shamir: the challenge
//! hashes the caller's `ctx` (a CBOR value binding the proof to its position),
//! the statement and the commitments. A proof does not verify under any other
//! `ctx`.

use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

use crate::cbor::{CborError, Value};
use crate::elgamal::Ciphertext;
use crate::error::Error;
use crate::group::{
    point_to_value, random_scalar, scalar_from_value, scalar_to_value, RistrettoPoint, Scalar, B,
};
use crate::hash::hash_to_scalar;

/// Decodes a CBOR `[scalar, scalar]` proof body (SPEC.md §11.1, §11.2).
fn two_scalars(v: &Value) -> Result<(Scalar, Scalar), Error> {
    match v.as_array()? {
        [c, s] => Ok((scalar_from_value(c)?, scalar_from_value(s)?)),
        _ => Err(Error::Cbor(CborError::Schema(
            "proof must be [scalar, scalar]".into(),
        ))),
    }
}

/// Schnorr proof of knowledge of x with X = x·B (SPEC.md §11.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchnorrProof {
    pub c: Scalar,
    pub v: Scalar,
}

impl SchnorrProof {
    /// Proves knowledge of x for X = x·B (computed internally, so the statement
    /// always matches the witness) (SPEC.md §11.1).
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, ctx: &Value, x: &Scalar) -> SchnorrProof {
        let big_x = x * B;
        let mut u = random_scalar(rng);
        let a = u * B;
        let c = hash_to_scalar(
            "eg/v1/schnorr",
            &[ctx.clone(), point_to_value(&big_x), point_to_value(&a)],
        );
        let v = u + c * x;
        u.zeroize();
        SchnorrProof { c, v }
    }

    /// Accepts iff c equals the recomputed challenge over A' = v·B − c·X
    /// (SPEC.md §11.1).
    pub fn verify(&self, ctx: &Value, big_x: &RistrettoPoint) -> bool {
        let a = self.v * B - self.c * big_x;
        self.c
            == hash_to_scalar(
                "eg/v1/schnorr",
                &[ctx.clone(), point_to_value(big_x), point_to_value(&a)],
            )
    }

    /// Encodes as CBOR `[c, v]` (SPEC.md §11.1).
    pub fn to_value(&self) -> Value {
        Value::Array(vec![scalar_to_value(&self.c), scalar_to_value(&self.v)])
    }

    /// Decodes exactly two canonical scalars (SPEC.md §11.1).
    pub fn from_value(v: &Value) -> Result<SchnorrProof, Error> {
        let (c, v) = two_scalars(v)?;
        Ok(SchnorrProof { c, v })
    }
}

/// Chaum-Pedersen proof that X1 = x·G1 and X2 = x·G2 for the same x
/// (SPEC.md §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpProof {
    pub c: Scalar,
    pub v: Scalar,
}

/// Challenge HashToScalar("eg/v1/cp", ctx, G1, X1, G2, X2, A1, A2) (SPEC.md §11.2).
fn cp_challenge(
    ctx: &Value,
    g1: &RistrettoPoint,
    x1: &RistrettoPoint,
    g2: &RistrettoPoint,
    x2: &RistrettoPoint,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
) -> Scalar {
    hash_to_scalar(
        "eg/v1/cp",
        &[
            ctx.clone(),
            point_to_value(g1),
            point_to_value(x1),
            point_to_value(g2),
            point_to_value(x2),
            point_to_value(a1),
            point_to_value(a2),
        ],
    )
}

impl CpProof {
    /// Proves X1 = x·G1 and X2 = x·G2 (X1, X2 computed internally, so the
    /// statement always matches the witness) (SPEC.md §11.2).
    pub fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        ctx: &Value,
        x: &Scalar,
        g1: &RistrettoPoint,
        g2: &RistrettoPoint,
    ) -> CpProof {
        let x1 = x * g1;
        let x2 = x * g2;
        let mut u = random_scalar(rng);
        let a1 = u * g1;
        let a2 = u * g2;
        let c = cp_challenge(ctx, g1, &x1, g2, &x2, &a1, &a2);
        let v = u + c * x;
        u.zeroize();
        CpProof { c, v }
    }

    /// Accepts iff c equals the recomputed challenge over A1' = v·G1 − c·X1 and
    /// A2' = v·G2 − c·X2 (SPEC.md §11.2).
    pub fn verify(
        &self,
        ctx: &Value,
        g1: &RistrettoPoint,
        x1: &RistrettoPoint,
        g2: &RistrettoPoint,
        x2: &RistrettoPoint,
    ) -> bool {
        let a1 = self.v * g1 - self.c * x1;
        let a2 = self.v * g2 - self.c * x2;
        self.c == cp_challenge(ctx, g1, x1, g2, x2, &a1, &a2)
    }

    /// Encodes as CBOR `[c, v]` (SPEC.md §11.2).
    pub fn to_value(&self) -> Value {
        Value::Array(vec![scalar_to_value(&self.c), scalar_to_value(&self.v)])
    }

    /// Decodes exactly two canonical scalars (SPEC.md §11.2).
    pub fn from_value(v: &Value) -> Result<CpProof, Error> {
        let (c, v) = two_scalars(v)?;
        Ok(CpProof { c, v })
    }
}

/// Sum proof (SPEC.md §11.4): proves that `sum = Enc(l; r_sum)` under `k`, given
/// the total nonce `r_sum`. The statement is G1 = B, X1 = r_sum·B, G2 = K,
/// X2 = r_sum·K, which equals (α_Σ, β_Σ − L·B) when the sum is valid.
pub fn prove_sum<R: RngCore + CryptoRng>(
    rng: &mut R,
    ctx: &Value,
    k: &RistrettoPoint,
    r_sum: &Scalar,
) -> CpProof {
    CpProof::prove(rng, ctx, r_sum, &B, k)
}

/// Verifies a sum proof that `sum` encrypts exactly `l` under `k`
/// (SPEC.md §11.4): G1 = B, X1 = α_Σ, G2 = K, X2 = β_Σ − l·B.
pub fn verify_sum(
    proof: &CpProof,
    ctx: &Value,
    k: &RistrettoPoint,
    sum: &Ciphertext,
    l: u64,
) -> bool {
    let x2 = sum.beta - Scalar::from(l) * B;
    proof.verify(ctx, &B, &sum.alpha, k, &x2)
}

/// Decryption share proof (SPEC.md §11.6): trustee j proves M_j = z_j·α with the
/// same z_j as Z_j = z_j·B. Chaum-Pedersen with G1 = B, G2 = α, x = z_j.
pub fn prove_decryption_share<R: RngCore + CryptoRng>(
    rng: &mut R,
    ctx: &Value,
    z_j: &Scalar,
    alpha: &RistrettoPoint,
) -> CpProof {
    CpProof::prove(rng, ctx, z_j, &B, alpha)
}

/// Verifies a decryption share proof that `m_j` = z_j·`alpha` for the trustee
/// whose public share is `z_big_j` = z_j·B (SPEC.md §11.6).
pub fn verify_decryption_share(
    proof: &CpProof,
    ctx: &Value,
    z_big_j: &RistrettoPoint,
    alpha: &RistrettoPoint,
    m_j: &RistrettoPoint,
) -> bool {
    proof.verify(ctx, &B, z_big_j, alpha, m_j)
}

/// Challenge HashToScalar("eg/v1/disj01", ctx, α, β, A0, D0, A1, D1)
/// (SPEC.md §11.3).
fn disj01_challenge(
    ctx: &Value,
    ct: &Ciphertext,
    a0: &RistrettoPoint,
    d0: &RistrettoPoint,
    a1: &RistrettoPoint,
    d1: &RistrettoPoint,
) -> Scalar {
    hash_to_scalar(
        "eg/v1/disj01",
        &[
            ctx.clone(),
            point_to_value(&ct.alpha),
            point_to_value(&ct.beta),
            point_to_value(a0),
            point_to_value(d0),
            point_to_value(a1),
            point_to_value(d1),
        ],
    )
}

/// Disjunctive 0-or-1 proof (SPEC.md §11.3): proves that a ciphertext encrypts
/// 0 or 1 without revealing which. It is a Cramer-Damgård-Schoenmakers OR of two
/// Chaum-Pedersen statements, where branch j asserts (α, β − j·B) = r·(B, K).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disj01Proof {
    pub c0: Scalar,
    pub c1: Scalar,
    pub v0: Scalar,
    pub v1: Scalar,
}

impl Disj01Proof {
    /// Encrypts bit `b` under `k` with nonce `r` and proves that the result
    /// encrypts 0 or 1 (SPEC.md §10.1, §11.3). Returns [`Error::ZeroNonce`] if
    /// `r` is zero. Panics if `b > 1`, which is a programming error.
    pub fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        ctx: &Value,
        k: &RistrettoPoint,
        b: u8,
        r: &Scalar,
    ) -> Result<(Ciphertext, Disj01Proof), Error> {
        assert!(b <= 1, "disj01 proves a bit: b must be 0 or 1");
        let ct = Ciphertext::encrypt(u32::from(b), r, k)?;

        // `choice` is 1 iff b == 1. The prover never branches on b: both branches
        // are computed in full and `conditional_select` picks the real one. An
        // `if` would leak the secret vote through timing and control flow.
        let choice = Choice::from(b);

        // Always draw the same three scalars in the same order.
        let mut u = random_scalar(rng);
        let c_sim = random_scalar(rng);
        let v_sim = random_scalar(rng);

        let real_a = u * B;
        let real_d = u * k;

        let beta_0 = ct.beta;
        let beta_1 = ct.beta - B;
        // The simulated A is the same for both branches, only D depends on j.
        let sim_a = v_sim * B - c_sim * ct.alpha;
        let sim_d_0 = v_sim * k - c_sim * beta_0;
        let sim_d_1 = v_sim * k - c_sim * beta_1;

        // Branch 0 is real iff b == 0, and branch 1 is real iff b == 1.
        let a0 = RistrettoPoint::conditional_select(&real_a, &sim_a, choice);
        let d0 = RistrettoPoint::conditional_select(&real_d, &sim_d_0, choice);
        let a1 = RistrettoPoint::conditional_select(&sim_a, &real_a, choice);
        let d1 = RistrettoPoint::conditional_select(&sim_d_1, &real_d, choice);

        let c = disj01_challenge(ctx, &ct, &a0, &d0, &a1, &d1);
        let c_real = c - c_sim;
        let v_real = u + c_real * r;
        u.zeroize();

        let c0 = Scalar::conditional_select(&c_real, &c_sim, choice);
        let v0 = Scalar::conditional_select(&v_real, &v_sim, choice);
        let c1 = Scalar::conditional_select(&c_sim, &c_real, choice);
        let v1 = Scalar::conditional_select(&v_sim, &v_real, choice);

        Ok((ct, Disj01Proof { c0, c1, v0, v1 }))
    }

    /// Accepts iff c0 + c1 equals the recomputed challenge over the commitments
    /// A_j' = v_j·B − c_j·α and D_j' = v_j·K − c_j·(β − j·B) (SPEC.md §11.3).
    pub fn verify(&self, ctx: &Value, k: &RistrettoPoint, ct: &Ciphertext) -> bool {
        let a0 = self.v0 * B - self.c0 * ct.alpha;
        let d0 = self.v0 * k - self.c0 * ct.beta;
        let a1 = self.v1 * B - self.c1 * ct.alpha;
        let d1 = self.v1 * k - self.c1 * (ct.beta - B);
        self.c0 + self.c1 == disj01_challenge(ctx, ct, &a0, &d0, &a1, &d1)
    }

    /// Encodes as CBOR `[c0, c1, v0, v1]` (SPEC.md §11.3).
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            scalar_to_value(&self.c0),
            scalar_to_value(&self.c1),
            scalar_to_value(&self.v0),
            scalar_to_value(&self.v1),
        ])
    }

    /// Decodes exactly four canonical scalars (SPEC.md §11.3).
    pub fn from_value(v: &Value) -> Result<Disj01Proof, Error> {
        match v.as_array()? {
            [c0, c1, v0, v1] => Ok(Disj01Proof {
                c0: scalar_from_value(c0)?,
                c1: scalar_from_value(c1)?,
                v0: scalar_from_value(v0)?,
                v1: scalar_from_value(v1)?,
            }),
            _ => Err(Error::Cbor(CborError::Schema(
                "disj01 proof must be [scalar, scalar, scalar, scalar]".into(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([11u8; 32])
    }

    fn ctx() -> Value {
        Value::Array(vec![Value::from("test"), Value::from(1u64)])
    }

    fn other_ctx() -> Value {
        Value::Array(vec![Value::from("test"), Value::from(2u64)])
    }

    fn nonzero(rng: &mut ChaCha20Rng) -> Scalar {
        loop {
            let r = random_scalar(rng);
            if r != Scalar::ZERO {
                return r;
            }
        }
    }

    #[test]
    fn schnorr_honest_verifies() {
        let mut rng = rng();
        let x = random_scalar(&mut rng);
        let big_x = x * B;
        let p = SchnorrProof::prove(&mut rng, &ctx(), &x);
        assert!(p.verify(&ctx(), &big_x));
    }

    #[test]
    fn schnorr_rejects() {
        let mut rng = rng();
        let x = random_scalar(&mut rng);
        let big_x = x * B;
        let p = SchnorrProof::prove(&mut rng, &ctx(), &x);

        assert!(!p.verify(&other_ctx(), &big_x));
        assert!(!p.verify(&ctx(), &(random_scalar(&mut rng) * B)));
        assert!(!SchnorrProof {
            c: p.c + Scalar::ONE,
            v: p.v
        }
        .verify(&ctx(), &big_x));
        assert!(!SchnorrProof {
            c: p.c,
            v: p.v + Scalar::ONE
        }
        .verify(&ctx(), &big_x));
    }

    #[test]
    fn schnorr_fresh_randomness() {
        let mut rng = rng();
        let x = random_scalar(&mut rng);
        let big_x = x * B;
        let p1 = SchnorrProof::prove(&mut rng, &ctx(), &x);
        let p2 = SchnorrProof::prove(&mut rng, &ctx(), &x);
        assert_ne!(p1, p2);
        assert!(p1.verify(&ctx(), &big_x));
        assert!(p2.verify(&ctx(), &big_x));
    }

    #[test]
    fn schnorr_round_trip_and_rejects_bad_encoding() {
        let mut rng = rng();
        let x = random_scalar(&mut rng);
        let p = SchnorrProof::prove(&mut rng, &ctx(), &x);
        assert_eq!(SchnorrProof::from_value(&p.to_value()), Ok(p));

        let one = Value::Array(vec![scalar_to_value(&p.c)]);
        assert!(matches!(
            SchnorrProof::from_value(&one),
            Err(Error::Cbor(CborError::Schema(_)))
        ));

        let non_canonical = Value::Array(vec![scalar_to_value(&p.c), Value::Bytes(vec![0xff; 32])]);
        assert_eq!(
            SchnorrProof::from_value(&non_canonical),
            Err(Error::InvalidScalar)
        );
    }

    #[test]
    fn cp_honest_verifies() {
        let mut rng = rng();
        let g2 = random_scalar(&mut rng) * B;
        let x = random_scalar(&mut rng);
        let p = CpProof::prove(&mut rng, &ctx(), &x, &B, &g2);
        assert!(p.verify(&ctx(), &B, &(x * B), &g2, &(x * g2)));
    }

    #[test]
    fn cp_rejects_different_log_and_ctx() {
        let mut rng = rng();
        let g2 = random_scalar(&mut rng) * B;
        let x = random_scalar(&mut rng);
        let y = x + Scalar::ONE;
        let p = CpProof::prove(&mut rng, &ctx(), &x, &B, &g2);

        assert!(!p.verify(&ctx(), &B, &(x * B), &g2, &(y * g2)));
        assert!(!p.verify(&other_ctx(), &B, &(x * B), &g2, &(x * g2)));
        assert!(!CpProof {
            c: p.c,
            v: p.v + Scalar::ONE
        }
        .verify(&ctx(), &B, &(x * B), &g2, &(x * g2)));
    }

    #[test]
    fn cp_round_trip() {
        let mut rng = rng();
        let x = random_scalar(&mut rng);
        let p = CpProof::prove(&mut rng, &ctx(), &x, &B, &B);
        assert_eq!(CpProof::from_value(&p.to_value()), Ok(p));
        assert!(CpProof::from_value(&Value::Array(vec![])).is_err());
    }

    #[test]
    fn sum_proof() {
        let mut rng = rng();
        let s = random_scalar(&mut rng);
        let k = s * B;
        let votes = [0u32, 1, 0];
        let nonces: Vec<Scalar> = votes.iter().map(|_| nonzero(&mut rng)).collect();
        let cts: Vec<Ciphertext> = votes
            .iter()
            .zip(&nonces)
            .map(|(&m, r)| Ciphertext::encrypt(m, r, &k).unwrap())
            .collect();
        let sum: Ciphertext = cts.iter().copied().sum();
        let r_sum: Scalar = nonces.iter().sum();

        let p = prove_sum(&mut rng, &ctx(), &k, &r_sum);
        assert!(verify_sum(&p, &ctx(), &k, &sum, 1));
        assert!(!verify_sum(&p, &ctx(), &k, &sum, 0));
        assert!(!verify_sum(&p, &ctx(), &k, &sum, 2));
    }

    #[test]
    fn sum_proof_rejects_cheating_total() {
        let mut rng = rng();
        let s = random_scalar(&mut rng);
        let k = s * B;
        let votes = [1u32, 1, 0];
        let nonces: Vec<Scalar> = votes.iter().map(|_| nonzero(&mut rng)).collect();
        let sum: Ciphertext = votes
            .iter()
            .zip(&nonces)
            .map(|(&m, r)| Ciphertext::encrypt(m, r, &k).unwrap())
            .sum();
        let r_sum: Scalar = nonces.iter().sum();

        let p = prove_sum(&mut rng, &ctx(), &k, &r_sum);
        assert!(verify_sum(&p, &ctx(), &k, &sum, 2));
        assert!(!verify_sum(&p, &ctx(), &k, &sum, 1));
    }

    #[test]
    fn decryption_share() {
        let mut rng = rng();
        let s = random_scalar(&mut rng);
        let k = s * B;
        let z_j = random_scalar(&mut rng);
        let z_big_j = z_j * B;
        let other_z = random_scalar(&mut rng) * B;
        let ct = Ciphertext::encrypt(1, &nonzero(&mut rng), &k).unwrap();
        let alpha = ct.alpha;
        let m_j = z_j * alpha;

        let p = prove_decryption_share(&mut rng, &ctx(), &z_j, &alpha);
        assert!(verify_decryption_share(&p, &ctx(), &z_big_j, &alpha, &m_j));

        assert!(!verify_decryption_share(
            &p,
            &ctx(),
            &z_big_j,
            &alpha,
            &(m_j + B)
        ));
        let other_alpha = random_scalar(&mut rng) * B;
        assert!(!verify_decryption_share(
            &p,
            &ctx(),
            &z_big_j,
            &other_alpha,
            &(z_j * other_alpha)
        ));
        assert!(!verify_decryption_share(&p, &ctx(), &other_z, &alpha, &m_j));
        assert!(!verify_decryption_share(
            &p,
            &other_ctx(),
            &z_big_j,
            &alpha,
            &m_j
        ));
    }

    #[test]
    fn disj01_bit0_and_bit1_verify() {
        let mut rng = rng();
        let k = random_scalar(&mut rng) * B;
        for b in [0u8, 1] {
            let r = nonzero(&mut rng);
            let (ct, p) = Disj01Proof::prove(&mut rng, &ctx(), &k, b, &r).unwrap();
            assert_eq!(ct, Ciphertext::encrypt(u32::from(b), &r, &k).unwrap());
            assert!(p.verify(&ctx(), &k, &ct));
        }
    }

    #[test]
    fn disj01_rejects_two() {
        let mut rng = rng();
        let k = random_scalar(&mut rng) * B;
        let r = nonzero(&mut rng);
        let ct2 = Ciphertext::encrypt(2, &r, &k).unwrap();
        for b in [0u8, 1] {
            let (_, p) = Disj01Proof::prove(&mut rng, &ctx(), &k, b, &r).unwrap();
            assert!(!p.verify(&ctx(), &k, &ct2));
        }
    }

    #[test]
    fn disj01_bound_to_ciphertext() {
        let mut rng = rng();
        let k = random_scalar(&mut rng) * B;
        let r1 = nonzero(&mut rng);
        let r2 = nonzero(&mut rng);
        let (ct1, p) = Disj01Proof::prove(&mut rng, &ctx(), &k, 1, &r1).unwrap();
        let ct2 = Ciphertext::encrypt(1, &r2, &k).unwrap();
        assert!(p.verify(&ctx(), &k, &ct1));
        assert!(!p.verify(&ctx(), &k, &ct2));
    }

    #[test]
    fn disj01_rejects_other_ctx() {
        let mut rng = rng();
        let k = random_scalar(&mut rng) * B;
        let r = nonzero(&mut rng);
        let (ct, p) = Disj01Proof::prove(&mut rng, &ctx(), &k, 0, &r).unwrap();
        assert!(!p.verify(&other_ctx(), &k, &ct));
    }

    #[test]
    fn disj01_tamper() {
        let mut rng = rng();
        let k = random_scalar(&mut rng) * B;
        let r = nonzero(&mut rng);
        let (ct, p) = Disj01Proof::prove(&mut rng, &ctx(), &k, 1, &r).unwrap();
        assert!(p.verify(&ctx(), &k, &ct));

        assert!(!Disj01Proof {
            c0: p.c0 + Scalar::ONE,
            ..p
        }
        .verify(&ctx(), &k, &ct));
        assert!(!Disj01Proof {
            c1: p.c1 + Scalar::ONE,
            ..p
        }
        .verify(&ctx(), &k, &ct));
        assert!(!Disj01Proof {
            v0: p.v0 + Scalar::ONE,
            ..p
        }
        .verify(&ctx(), &k, &ct));
        assert!(!Disj01Proof {
            v1: p.v1 + Scalar::ONE,
            ..p
        }
        .verify(&ctx(), &k, &ct));
        assert!(!Disj01Proof {
            c0: p.c1,
            v0: p.v1,
            c1: p.c0,
            v1: p.v0,
        }
        .verify(&ctx(), &k, &ct));
    }

    #[test]
    fn disj01_encoding_round_trip() {
        let mut rng = rng();
        let k = random_scalar(&mut rng) * B;
        let r = nonzero(&mut rng);
        let (_, p) = Disj01Proof::prove(&mut rng, &ctx(), &k, 0, &r).unwrap();
        assert_eq!(Disj01Proof::from_value(&p.to_value()), Ok(p));

        let three = Value::Array(vec![
            scalar_to_value(&p.c0),
            scalar_to_value(&p.c1),
            scalar_to_value(&p.v0),
        ]);
        assert!(matches!(
            Disj01Proof::from_value(&three),
            Err(Error::Cbor(CborError::Schema(_)))
        ));
    }

    #[test]
    fn disj01_zero_nonce() {
        let mut rng = rng();
        let k = random_scalar(&mut rng) * B;
        assert_eq!(
            Disj01Proof::prove(&mut rng, &ctx(), &k, 1, &Scalar::ZERO),
            Err(Error::ZeroNonce)
        );
    }

    #[test]
    fn disj01_hides_branch() {
        let mut setup = rng();
        let k = random_scalar(&mut setup) * B;
        let r = nonzero(&mut setup);
        // Identical rng streams for b = 0 and b = 1: the transcript structure
        // must not reveal which branch is real.
        for b in [0u8, 1] {
            let mut stream = rng();
            let (ct, p) = Disj01Proof::prove(&mut stream, &ctx(), &k, b, &r).unwrap();
            for s in [p.c0, p.c1, p.v0, p.v1] {
                assert_ne!(s, Scalar::ZERO);
            }
            let a0 = p.v0 * B - p.c0 * ct.alpha;
            let d0 = p.v0 * k - p.c0 * ct.beta;
            let a1 = p.v1 * B - p.c1 * ct.alpha;
            let d1 = p.v1 * k - p.c1 * (ct.beta - B);
            assert_eq!(
                p.c0 + p.c1,
                disj01_challenge(&ctx(), &ct, &a0, &d0, &a1, &d1)
            );
        }
    }

    #[test]
    #[should_panic]
    fn disj01_panics_on_non_bit() {
        let mut rng = rng();
        let k = random_scalar(&mut rng) * B;
        let r = nonzero(&mut rng);
        let _ = Disj01Proof::prove(&mut rng, &ctx(), &k, 2, &r);
    }
}
