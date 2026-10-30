//! Ristretto255 group operations for eg/v1 (SPEC.md §5.1, §5.2, §5.6, §5.7, §6.2).

use curve25519_dalek::{ristretto::CompressedRistretto, traits::IsIdentity};
use sha2::{Digest, Sha512};

use crate::cbor::{self, Value};
use crate::error::Error;

pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::scalar::Scalar;

/// Standard Ristretto255 generator B (SPEC.md §5.1).
pub const B: RistrettoPoint = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

/// Encodes a group element as a 32-byte CBOR byte string (SPEC.md §6.2).
pub fn point_to_value(p: &RistrettoPoint) -> Value {
    Value::Bytes(p.compress().to_bytes().to_vec())
}

/// Decodes a group element from a 32-byte CBOR byte string, accepting the
/// identity (SPEC.md §5.1, §6.2).
///
/// Returns [`Error::InvalidPoint`] if the value is not a byte string of length
/// 32 or is not a canonical Ristretto255 encoding.
pub fn point_from_value(v: &Value) -> Result<RistrettoPoint, Error> {
    let bytes: [u8; 32] = v
        .as_bytes()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::InvalidPoint)?;
    CompressedRistretto(bytes)
        .decompress()
        .ok_or(Error::InvalidPoint)
}

/// Decodes a group element as [`point_from_value`] does, but additionally
/// rejects the identity element (SPEC.md §5.1, §6.2).
///
/// Returns [`Error::IdentityPoint`] if the decoded point is the identity.
pub fn point_nonidentity_from_value(v: &Value) -> Result<RistrettoPoint, Error> {
    let p = point_from_value(v)?;
    if p.is_identity() {
        return Err(Error::IdentityPoint);
    }
    Ok(p)
}

/// Encodes a scalar as a 32-byte little-endian CBOR byte string (SPEC.md §6.2).
pub fn scalar_to_value(s: &Scalar) -> Value {
    Value::Bytes(s.to_bytes().to_vec())
}

/// Decodes a scalar from a 32-byte little-endian CBOR byte string. Values
/// greater than or equal to the group order ℓ are rejected (SPEC.md §5.1, §6.2).
///
/// Returns [`Error::InvalidScalar`] on wrong length or non-canonical encoding.
pub fn scalar_from_value(v: &Value) -> Result<Scalar, Error> {
    let bytes: [u8; 32] = v
        .as_bytes()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::InvalidScalar)?;
    Option::from(Scalar::from_canonical_bytes(bytes)).ok_or(Error::InvalidScalar)
}

/// Random(): draws 64 bytes from `rng` and reduces them modulo ℓ, giving a
/// near-uniform scalar (SPEC.md §5.6).
pub fn random_scalar<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Gen(label, i) = FromUniformBytes(SHA-512(CBOR(["eg/v1/gen", context_hash,
/// label, i]))): derives a nothing-up-my-sleeve generator (SPEC.md §5.2).
pub fn gen(context_hash: &[u8; 32], label: &str, i: u64) -> RistrettoPoint {
    let input = cbor::encode(&Value::Array(vec![
        Value::from("eg/v1/gen"),
        Value::from(*context_hash),
        Value::from(label),
        Value::from(i),
    ]));
    let digest: [u8; 64] = Sha512::digest(&input).into();
    RistrettoPoint::from_uniform_bytes(&digest)
}

/// Lagrange coefficient λ_j(S) = ∏_{m ∈ S, m ≠ j} m · (m − j)^(−1) mod ℓ
/// (SPEC.md §5.7).
///
/// Returns [`Error::InvalidIndexSet`] if `set` is empty, contains 0, contains
/// duplicates, or does not contain `j`.
pub fn lagrange(set: &[u64], j: u64) -> Result<Scalar, Error> {
    if set.is_empty() || set.contains(&0) || !set.contains(&j) {
        return Err(Error::InvalidIndexSet);
    }
    for (i, a) in set.iter().enumerate() {
        if set[i + 1..].contains(a) {
            return Err(Error::InvalidIndexSet);
        }
    }

    let sj = Scalar::from(j);
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &m in set.iter().filter(|&&m| m != j) {
        let sm = Scalar::from(m);
        num *= sm;
        den *= sm - sj;
    }
    Ok(num * den.invert())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([7u8; 32])
    }

    #[test]
    fn point_round_trip() {
        let mut rng = rng();
        for _ in 0..16 {
            let p = random_scalar(&mut rng) * B;
            let v = point_to_value(&p);
            assert_eq!(v, Value::Bytes(p.compress().to_bytes().to_vec()));
            assert_eq!(point_from_value(&v), Ok(p));
            assert_eq!(point_nonidentity_from_value(&v), Ok(p));
        }
    }

    #[test]
    fn identity_round_trip() {
        let id = RistrettoPoint::identity();
        let v = point_to_value(&id);
        assert_eq!(point_from_value(&v), Ok(id));
        assert_eq!(point_nonidentity_from_value(&v), Err(Error::IdentityPoint));
    }

    #[test]
    fn point_rejects_bad_encodings() {
        let bad_len_31 = Value::Bytes(vec![0u8; 31]);
        let bad_len_33 = Value::Bytes(vec![0u8; 33]);
        let not_bytes = Value::Uint(0);
        let non_canonical = Value::Bytes(vec![0xff; 32]);
        let mut negative = vec![0u8; 32];
        negative[0] = 1;
        let negative = Value::Bytes(negative);

        for v in [
            &bad_len_31,
            &bad_len_33,
            &not_bytes,
            &non_canonical,
            &negative,
        ] {
            assert_eq!(point_from_value(v), Err(Error::InvalidPoint), "{v:?}");
            assert_eq!(
                point_nonidentity_from_value(v),
                Err(Error::InvalidPoint),
                "{v:?}"
            );
        }
    }

    #[test]
    fn scalar_round_trip() {
        let mut rng = rng();
        for _ in 0..16 {
            let s = random_scalar(&mut rng);
            let v = scalar_to_value(&s);
            assert_eq!(scalar_from_value(&v), Ok(s));
        }
    }

    #[test]
    fn scalar_rejects_non_canonical() {
        let l = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap();
        assert_eq!(
            scalar_from_value(&Value::Bytes(l)),
            Err(Error::InvalidScalar)
        );
        assert_eq!(
            scalar_from_value(&Value::Bytes(vec![0xff; 32])),
            Err(Error::InvalidScalar)
        );
        assert_eq!(
            scalar_from_value(&Value::Bytes(vec![0u8; 31])),
            Err(Error::InvalidScalar)
        );
        assert_eq!(
            scalar_from_value(&Value::Uint(1)),
            Err(Error::InvalidScalar)
        );
    }

    #[test]
    fn scalar_accepts_order_minus_one() {
        let lm1 = hex::decode("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap();
        let s = scalar_from_value(&Value::Bytes(lm1)).unwrap();
        assert_eq!(s, -Scalar::ONE);
    }

    #[test]
    fn random_scalar_draws_differ_and_nonzero() {
        let mut rng = rng();
        let a = random_scalar(&mut rng);
        let b = random_scalar(&mut rng);
        assert_ne!(a, b);
        assert_ne!(a, Scalar::ZERO);
        assert_ne!(b, Scalar::ZERO);
    }

    #[test]
    fn gen_is_deterministic_and_input_sensitive() {
        let ctx = [1u8; 32];
        let g = gen(&ctx, "G", 0);
        assert_eq!(g, gen(&ctx, "G", 0));
        assert_ne!(g, gen(&ctx, "H", 0));
        assert_ne!(g, gen(&ctx, "G", 1));
        assert_ne!(g, gen(&[2u8; 32], "G", 0));
        assert!(!g.is_identity());
    }

    /// Evaluates f(x) = a0 + a1·x + a2·x² at x.
    fn eval(coeffs: &[Scalar; 3], x: u64) -> Scalar {
        let x = Scalar::from(x);
        coeffs[0] + coeffs[1] * x + coeffs[2] * x * x
    }

    #[test]
    fn lagrange_shamir_reconstruction() {
        let mut rng = rng();
        let coeffs = [
            random_scalar(&mut rng),
            random_scalar(&mut rng),
            random_scalar(&mut rng),
        ];
        let shares: Vec<(u64, Scalar)> = (1..=5).map(|x| (x, eval(&coeffs, x))).collect();

        for set in [[1u64, 2, 3], [2, 4, 5], [1, 3, 5]] {
            let mut sum = Scalar::ZERO;
            let mut sum_exp = RistrettoPoint::identity();
            for &j in &set {
                let lam = lagrange(&set, j).unwrap();
                let fj = shares.iter().find(|(x, _)| *x == j).unwrap().1;
                sum += lam * fj;
                sum_exp += lam * (fj * B);
            }
            assert_eq!(sum, coeffs[0], "set {set:?}");
            assert_eq!(sum_exp, coeffs[0] * B, "set {set:?} in exponent");
        }
    }

    #[test]
    fn lagrange_rejects_invalid_sets() {
        assert_eq!(lagrange(&[], 1), Err(Error::InvalidIndexSet));
        assert_eq!(lagrange(&[0, 1, 2], 1), Err(Error::InvalidIndexSet));
        assert_eq!(lagrange(&[1, 1, 2], 1), Err(Error::InvalidIndexSet));
        assert_eq!(lagrange(&[1, 2, 3], 4), Err(Error::InvalidIndexSet));
    }
}
