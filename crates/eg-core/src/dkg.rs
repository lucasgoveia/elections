//! Distributed key generation, math only (SPEC.md §8): Pedersen-style DKG over
//! Ristretto255 with Feldman-style coefficient commitments. Records, signatures,
//! complaints and transcripts are out of scope here.

use curve25519_dalek::traits::{Identity, IsIdentity};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::cbor::Value;
use crate::group::{random_scalar, RistrettoPoint, Scalar, B};
use crate::proofs::SchnorrProof;

/// A trustee's secret polynomial P_i (SPEC.md §8.1). Coefficients are wiped on
/// drop; Debug is redacted.
pub struct Polynomial {
    coeffs: Vec<Scalar>,
}

impl Polynomial {
    /// Random polynomial of degree k−1 with every coefficient nonzero (zeros are
    /// resampled) (SPEC.md §8.1). Panics if k == 0.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, k: usize) -> Polynomial {
        assert!(k > 0, "threshold must be at least 1");
        let coeffs = (0..k)
            .map(|_| loop {
                let a = random_scalar(rng);
                if a != Scalar::ZERO {
                    break a;
                }
            })
            .collect();
        Polynomial { coeffs }
    }

    /// Builds from explicit coefficients, for tests and test vectors. Panics if
    /// empty or if any coefficient is zero (SPEC.md §8.1).
    pub fn from_coefficients(coeffs: Vec<Scalar>) -> Polynomial {
        assert!(
            !coeffs.is_empty(),
            "polynomial needs at least one coefficient"
        );
        assert!(
            coeffs.iter().all(|a| *a != Scalar::ZERO),
            "coefficients must be nonzero"
        );
        Polynomial { coeffs }
    }

    /// Number of coefficients, k (SPEC.md §8.1).
    pub fn threshold(&self) -> usize {
        self.coeffs.len()
    }

    /// P(x) mod ℓ by Horner's rule (SPEC.md §8.2).
    pub fn eval(&self, x: u64) -> Scalar {
        let x = Scalar::from(x);
        self.coeffs
            .iter()
            .rev()
            .fold(Scalar::ZERO, |acc, a| acc * x + a)
    }

    /// C_t = a_t·B for t = 0..k−1 (SPEC.md §8.1).
    pub fn commitments(&self) -> Vec<RistrettoPoint> {
        self.coeffs.iter().map(|a| a * B).collect()
    }

    /// Schnorr proofs of knowledge of each coefficient a_t, with ctx
    /// [`coefficient_ctx`]`(manifest_hash, i, t)` (SPEC.md §8.1, §11.1).
    pub fn prove_coefficients<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        manifest_hash: &[u8; 32],
        i: u64,
    ) -> Vec<SchnorrProof> {
        self.coeffs
            .iter()
            .enumerate()
            .map(|(t, a)| {
                let ctx = coefficient_ctx(manifest_hash, i, t as u64);
                SchnorrProof::prove(rng, &ctx, a)
            })
            .collect()
    }
}

impl Drop for Polynomial {
    /// Wipes every coefficient (SPEC.md §8.1).
    fn drop(&mut self) {
        for a in self.coeffs.iter_mut() {
            a.zeroize();
        }
    }
}

impl core::fmt::Debug for Polynomial {
    /// Redacted: prints only the threshold, never the coefficients.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Polynomial")
            .field("k", &self.coeffs.len())
            .finish_non_exhaustive()
    }
}

/// ctx = ["dkg-coef", manifest_hash, i, t] (SPEC.md §8.1).
pub fn coefficient_ctx(manifest_hash: &[u8; 32], i: u64, t: u64) -> Value {
    Value::Array(vec![
        Value::from("dkg-coef"),
        Value::from(*manifest_hash),
        Value::from(i),
        Value::from(t),
    ])
}

/// Checks a round-1 commitment vector from trustee `i` (SPEC.md §8.1): exactly
/// k commitments, none of them the identity, and every proof verifies under its
/// coefficient ctx.
pub fn verify_coefficients(
    commitments: &[RistrettoPoint],
    proofs: &[SchnorrProof],
    k: usize,
    manifest_hash: &[u8; 32],
    i: u64,
) -> bool {
    if k == 0 || commitments.len() != k || proofs.len() != k {
        return false;
    }
    commitments
        .iter()
        .zip(proofs)
        .enumerate()
        .all(|(t, (c, p))| {
            !c.is_identity() && p.verify(&coefficient_ctx(manifest_hash, i, t as u64), c)
        })
}

/// Σ_t (j^t mod ℓ)·C_t: the public image P(j)·B of a committed polynomial
/// (SPEC.md §8.3).
pub fn eval_commitments(commitments: &[RistrettoPoint], j: u64) -> RistrettoPoint {
    let j = Scalar::from(j);
    let mut pow = Scalar::ONE;
    let mut acc = RistrettoPoint::identity();
    for c in commitments {
        acc += pow * c;
        pow *= j;
    }
    acc
}

/// p·B == eval_commitments(commitments, j) (SPEC.md §8.3).
pub fn verify_share(commitments: &[RistrettoPoint], j: u64, share: &Scalar) -> bool {
    share * B == eval_commitments(commitments, j)
}

/// z_j = P_j(j) + Σ received shares mod ℓ (SPEC.md §8.3). `received` are the
/// shares p_{i→j} from every other trustee. The result is secret.
///
/// Panics if j == 0: index 0 would combine the constant terms into the joint
/// secret key s, which must never exist.
pub fn secret_share(own: &Polynomial, j: u64, received: &[Scalar]) -> Scalar {
    assert!(j >= 1, "trustee indices are 1-based");
    received.iter().fold(own.eval(j), |acc, p| acc + p)
}

/// K = Σ_i C_{i,0} (SPEC.md §8.5). `all` holds each trustee's commitment vector,
/// trustee 1 first. Returns None if `all` is empty, any vector is empty, or K is
/// the identity.
pub fn joint_public_key(all: &[Vec<RistrettoPoint>]) -> Option<RistrettoPoint> {
    if all.is_empty() {
        return None;
    }
    let mut k = RistrettoPoint::identity();
    for c in all {
        k += c.first()?;
    }
    if k.is_identity() {
        None
    } else {
        Some(k)
    }
}

/// Z_j = Σ_i eval_commitments(C_i, j) = z_j·B (SPEC.md §8.5).
pub fn verification_key(all: &[Vec<RistrettoPoint>], j: u64) -> RistrettoPoint {
    all.iter().fold(RistrettoPoint::identity(), |acc, c| {
        acc + eval_commitments(c, j)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::{dlog_bounded, Ciphertext};
    use crate::group::lagrange;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const MANIFEST: [u8; 32] = [7u8; 32];

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([19u8; 32])
    }

    /// Output of a simulated honest ceremony.
    struct Ceremony {
        polys: Vec<Polynomial>,
        commitments: Vec<Vec<RistrettoPoint>>,
        /// z[j-1] = z_j for trustee j.
        z: Vec<Scalar>,
    }

    /// Simulates a full honest round 1 and share distribution for (n, k).
    fn ceremony<R: RngCore + CryptoRng>(rng: &mut R, n: u64, k: usize) -> Ceremony {
        let polys: Vec<Polynomial> = (0..n).map(|_| Polynomial::random(rng, k)).collect();
        let commitments: Vec<Vec<RistrettoPoint>> = polys.iter().map(|p| p.commitments()).collect();
        let z = (1..=n)
            .map(|j| {
                let received: Vec<Scalar> = (1..=n)
                    .filter(|&i| i != j)
                    .map(|i| polys[(i - 1) as usize].eval(j))
                    .collect();
                secret_share(&polys[(j - 1) as usize], j, &received)
            })
            .collect();
        Ceremony {
            polys,
            commitments,
            z,
        }
    }

    #[test]
    fn eval_horner() {
        let p = Polynomial::from_coefficients(vec![
            Scalar::from(3u64),
            Scalar::from(5u64),
            Scalar::from(7u64),
        ]);
        assert_eq!(p.eval(2), Scalar::from(41u64));
        assert_eq!(p.eval(0), Scalar::from(3u64));
        assert_eq!(p.threshold(), 3);
    }

    #[test]
    fn commitments_and_shares_consistent() {
        let mut rng = rng();
        let p = Polynomial::random(&mut rng, 3);
        let c = p.commitments();
        for j in 1..=5u64 {
            assert!(verify_share(&c, j, &p.eval(j)));
            assert!(!verify_share(&c, j, &(p.eval(j) + Scalar::ONE)));
            assert!(!verify_share(&c, j + 1, &p.eval(j)));
        }
    }

    #[test]
    fn coefficient_proofs() {
        let mut rng = rng();
        let k = 3;
        let p = Polynomial::random(&mut rng, k);
        let c = p.commitments();
        let proofs = p.prove_coefficients(&mut rng, &MANIFEST, 2);
        assert!(verify_coefficients(&c, &proofs, k, &MANIFEST, 2));

        assert!(!verify_coefficients(&c, &proofs, k, &MANIFEST, 3));
        assert!(!verify_coefficients(&c, &proofs, k, &[8u8; 32], 2));

        let mut swapped = proofs.clone();
        swapped.swap(0, 1);
        assert!(!verify_coefficients(&c, &swapped, k, &MANIFEST, 2));

        let mut with_identity = c.clone();
        with_identity[1] = RistrettoPoint::identity();
        assert!(!verify_coefficients(
            &with_identity,
            &proofs,
            k,
            &MANIFEST,
            2
        ));

        assert!(!verify_coefficients(&c, &proofs, k + 1, &MANIFEST, 2));
        assert!(!verify_coefficients(&c[..k - 1], &proofs, k, &MANIFEST, 2));
        assert!(!verify_coefficients(&c, &proofs[..k - 1], k, &MANIFEST, 2));
    }

    #[test]
    fn ceremony_n3_k2() {
        check_ceremony(3, 2);
    }

    #[test]
    fn ceremony_n5_k3() {
        check_ceremony(5, 3);
    }

    fn check_ceremony(n: u64, k: usize) {
        let mut rng = rng();
        let cer = ceremony(&mut rng, n, k);

        for j in 1..=n {
            let z_j = cer.z[(j - 1) as usize];
            assert_eq!(verification_key(&cer.commitments, j), z_j * B);
        }

        let s: Scalar = cer.polys.iter().map(|p| p.eval(0)).sum();
        let key = joint_public_key(&cer.commitments).expect("K is not the identity");
        assert_eq!(key, s * B);
        assert!(!key.is_identity());
    }

    #[test]
    fn threshold_decryption_any_k_subset() {
        let mut rng = rng();
        let (n, k) = (5u64, 3usize);
        let cer = ceremony(&mut rng, n, k);
        let key = joint_public_key(&cer.commitments).unwrap();
        let r = random_scalar(&mut rng);
        let ct = Ciphertext::encrypt(1, &r, &key).unwrap();

        let decrypt = |set: &[u64]| {
            set.iter().fold(RistrettoPoint::identity(), |acc, &j| {
                let lam = lagrange(set, j).unwrap();
                acc + lam * (cer.z[(j - 1) as usize] * ct.alpha)
            })
        };

        for set in [[1u64, 2, 3], [1, 4, 5], [2, 3, 5]] {
            let m = decrypt(&set);
            assert_eq!(dlog_bounded(&(ct.beta - m), 1), Some(1));
        }

        let m = decrypt(&[1, 2]);
        assert_ne!(dlog_bounded(&(ct.beta - m), 10), Some(1));
    }

    #[test]
    fn bad_share_detected() {
        let mut rng = rng();
        let cer = ceremony(&mut rng, 3, 2);
        // Trustee 2 sends trustee 3 a share corrupted by +1.
        let bad = cer.polys[1].eval(3) + Scalar::ONE;
        assert!(!verify_share(&cer.commitments[1], 3, &bad));
    }

    #[test]
    fn joint_public_key_none_for_empty() {
        assert!(joint_public_key(&[]).is_none());
    }

    #[test]
    fn debug_is_redacted() {
        let p = Polynomial::from_coefficients(vec![
            Scalar::from(11u64),
            Scalar::from(12u64),
            Scalar::from(13u64),
        ]);
        let shown = format!("{:?}", p);
        assert!(shown.contains("k: 3"));
        for a in [11u64, 12, 13] {
            let hex_str = hex::encode(Scalar::from(a).to_bytes());
            assert!(!shown.contains(&hex_str));
        }
    }
}
