//! Exponential ElGamal over Ristretto255 (SPEC.md §10).

use core::iter::Sum;
use core::ops::{Add, AddAssign};

use curve25519_dalek::traits::Identity;

use crate::cbor::{CborError, Value};
use crate::error::Error;
use crate::group::{
    point_from_value, point_nonidentity_from_value, point_to_value, RistrettoPoint, Scalar, B,
};

/// An exponential ElGamal ciphertext (α, β) (SPEC.md §10.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub alpha: RistrettoPoint,
    pub beta: RistrettoPoint,
}

impl Ciphertext {
    /// Enc(m; r) = (r·B, m·B + r·K) (SPEC.md §10.1). Requires 0 ≤ m < 2^32 by
    /// convention of the caller; `r` must be nonzero, else [`Error::ZeroNonce`].
    pub fn encrypt(m: u32, r: &Scalar, k: &RistrettoPoint) -> Result<Ciphertext, Error> {
        if *r == Scalar::ZERO {
            return Err(Error::ZeroNonce);
        }
        Ok(Ciphertext {
            alpha: r * B,
            beta: Scalar::from(u64::from(m)) * B + r * k,
        })
    }

    /// (O, O): neutral element for ⊕, i.e. Enc(0; 0) (SPEC.md §10.2). Starting
    /// point for sums.
    pub fn zero() -> Ciphertext {
        Ciphertext {
            alpha: RistrettoPoint::identity(),
            beta: RistrettoPoint::identity(),
        }
    }

    /// k·(α, β) = Enc(k·m; k·r) (SPEC.md §10.2).
    pub fn scale(&self, k: &Scalar) -> Ciphertext {
        Ciphertext {
            alpha: k * self.alpha,
            beta: k * self.beta,
        }
    }

    /// ReEnc((α, β); r') = (α + r'·B, β + r'·K) (SPEC.md §10.3).
    pub fn reencrypt(&self, r: &Scalar, k: &RistrettoPoint) -> Ciphertext {
        Ciphertext {
            alpha: self.alpha + r * B,
            beta: self.beta + r * k,
        }
    }

    /// β − s·α = m·B (SPEC.md §10.4). Informative only: the full key never
    /// exists in production, so this is used in tests.
    pub fn decrypt_to_point(&self, s: &Scalar) -> RistrettoPoint {
        self.beta - s * self.alpha
    }

    /// Encodes as CBOR `[point α, point β]` (SPEC.md §10.1, §6.2).
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            point_to_value(&self.alpha),
            point_to_value(&self.beta),
        ])
    }

    /// Generic decoding: exactly two points, identity allowed, since sums and
    /// tallies may contain it (SPEC.md §10.1).
    pub fn from_value(v: &Value) -> Result<Ciphertext, Error> {
        let [a, b] = pair(v)?;
        Ok(Ciphertext {
            alpha: point_from_value(a)?,
            beta: point_from_value(b)?,
        })
    }

    /// Ballot decoding: as [`Ciphertext::from_value`], but α must not be the
    /// identity, since a ballot nonce is nonzero (SPEC.md §10.1).
    pub fn ballot_from_value(v: &Value) -> Result<Ciphertext, Error> {
        let [a, b] = pair(v)?;
        Ok(Ciphertext {
            alpha: point_nonidentity_from_value(a)?,
            beta: point_from_value(b)?,
        })
    }
}

/// Extracts exactly two elements from a CBOR array (SPEC.md §10.1).
fn pair(v: &Value) -> Result<&[Value; 2], Error> {
    v.as_array()?.try_into().map_err(|_| {
        Error::Cbor(CborError::Schema(
            "ciphertext must be [point, point]".to_owned(),
        ))
    })
}

impl Add for Ciphertext {
    type Output = Ciphertext;

    /// ⊕: componentwise sum, = Enc(m1+m2; r1+r2) (SPEC.md §10.2).
    fn add(self, rhs: Ciphertext) -> Ciphertext {
        Ciphertext {
            alpha: self.alpha + rhs.alpha,
            beta: self.beta + rhs.beta,
        }
    }
}

impl AddAssign for Ciphertext {
    /// In-place ⊕ (SPEC.md §10.2).
    fn add_assign(&mut self, rhs: Ciphertext) {
        *self = *self + rhs;
    }
}

impl Sum for Ciphertext {
    /// Folds ⊕ starting from [`Ciphertext::zero`] (SPEC.md §10.2).
    fn sum<I: Iterator<Item = Ciphertext>>(iter: I) -> Ciphertext {
        iter.fold(Ciphertext::zero(), Add::add)
    }
}

/// Bounded discrete log (SPEC.md §20.4): the smallest m in 0..=max with
/// m·B == t, or None if there is none. Linear walk, so cost is O(max).
pub fn dlog_bounded(t: &RistrettoPoint, max: u64) -> Option<u64> {
    let mut acc = RistrettoPoint::identity();
    for m in 0..=max {
        if acc == *t {
            return Some(m);
        }
        acc += B;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::random_scalar;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([9u8; 32])
    }

    fn keypair(rng: &mut ChaCha20Rng) -> (Scalar, RistrettoPoint) {
        let s = random_scalar(rng);
        (s, s * B)
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
    fn encrypt_decrypt_round_trip() {
        let mut rng = rng();
        let (s, k) = keypair(&mut rng);
        for m in [0u32, 1, 7, 1000] {
            let ct = Ciphertext::encrypt(m, &nonzero(&mut rng), &k).unwrap();
            assert_eq!(
                dlog_bounded(&ct.decrypt_to_point(&s), 2000),
                Some(u64::from(m))
            );
        }
    }

    #[test]
    fn zero_nonce_rejected() {
        let mut rng = rng();
        let (_, k) = keypair(&mut rng);
        assert_eq!(
            Ciphertext::encrypt(1, &Scalar::ZERO, &k),
            Err(Error::ZeroNonce)
        );
    }

    #[test]
    fn homomorphic_tally() {
        let mut rng = rng();
        let (s, k) = keypair(&mut rng);
        let votes = [1u32, 0, 1, 1, 0, 1];
        let cts: Vec<Ciphertext> = votes
            .iter()
            .map(|&v| Ciphertext::encrypt(v, &nonzero(&mut rng), &k).unwrap())
            .collect();

        let summed: Ciphertext = cts.iter().copied().sum();
        assert_eq!(dlog_bounded(&summed.decrypt_to_point(&s), 10), Some(4));

        let pair_sum = cts[0] + cts[1];
        let mut acc = Ciphertext::zero();
        for ct in &cts {
            acc += *ct;
        }
        assert_eq!(acc, summed);
        assert_eq!(acc, cts.iter().fold(Ciphertext::zero(), |a, b| a + *b));
        assert_eq!(dlog_bounded(&pair_sum.decrypt_to_point(&s), 10), Some(1));
    }

    #[test]
    fn scale_multiplies_plaintext() {
        let mut rng = rng();
        let (s, k) = keypair(&mut rng);
        let ct = Ciphertext::encrypt(3, &nonzero(&mut rng), &k).unwrap();
        let scaled = ct.scale(&Scalar::from(5u64));
        assert_eq!(dlog_bounded(&scaled.decrypt_to_point(&s), 100), Some(15));
    }

    #[test]
    fn reencrypt_same_plaintext_new_ciphertext() {
        let mut rng = rng();
        let (s, k) = keypair(&mut rng);
        let ct = Ciphertext::encrypt(6, &nonzero(&mut rng), &k).unwrap();
        let re = ct.reencrypt(&nonzero(&mut rng), &k);
        assert_ne!(re.alpha, ct.alpha);
        assert_ne!(re.beta, ct.beta);
        assert_eq!(dlog_bounded(&re.decrypt_to_point(&s), 10), Some(6));
    }

    #[test]
    fn same_message_different_nonce_differs() {
        let mut rng = rng();
        let (_, k) = keypair(&mut rng);
        let c1 = Ciphertext::encrypt(1, &nonzero(&mut rng), &k).unwrap();
        let c2 = Ciphertext::encrypt(1, &nonzero(&mut rng), &k).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn value_round_trip() {
        let mut rng = rng();
        let (_, k) = keypair(&mut rng);
        let ct = Ciphertext::encrypt(2, &nonzero(&mut rng), &k).unwrap();
        let v = ct.to_value();
        assert_eq!(Ciphertext::from_value(&v), Ok(ct));
        assert_eq!(Ciphertext::ballot_from_value(&v), Ok(ct));
    }

    #[test]
    fn from_value_rejects() {
        let p = point_to_value(&RistrettoPoint::identity());
        let one = Value::Array(vec![p.clone()]);
        let three = Value::Array(vec![p.clone(), p.clone(), p.clone()]);
        let not_array = Value::Uint(0);
        let short_point = Value::Array(vec![Value::Bytes(vec![0u8; 31]), p.clone()]);

        assert!(Ciphertext::from_value(&one).is_err());
        assert!(matches!(
            Ciphertext::from_value(&three),
            Err(Error::Cbor(CborError::Schema(_)))
        ));
        assert!(Ciphertext::from_value(&not_array).is_err());
        assert!(Ciphertext::from_value(&short_point).is_err());
        assert!(Ciphertext::ballot_from_value(&one).is_err());
        assert!(Ciphertext::ballot_from_value(&three).is_err());
        assert!(Ciphertext::ballot_from_value(&short_point).is_err());
    }

    #[test]
    fn zero_ciphertext_ballot_rejected() {
        let v = Ciphertext::zero().to_value();
        assert!(Ciphertext::from_value(&v).is_ok());
        assert_eq!(Ciphertext::ballot_from_value(&v), Err(Error::IdentityPoint));
    }

    #[test]
    fn dlog_bounds() {
        assert_eq!(dlog_bounded(&RistrettoPoint::identity(), 0), Some(0));
        let t = Scalar::from(10u64) * B;
        assert_eq!(dlog_bounded(&t, 9), None);
        assert_eq!(dlog_bounded(&t, 10), Some(10));
    }
}
