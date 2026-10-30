//! HPKE encryption of key-ceremony shares (SPEC.md §5.5, §8.2).
//!
//! Base mode of RFC 9180 with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
//! ChaCha20-Poly1305. The plaintext is the 32-byte scalar share p_{i→j}.

use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::cbor::{self, Value};
use crate::error::Error;

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::ChaCha20Poly1305;
type HpkeEncappedKey = <Kem as hpke::Kem>::EncappedKey;

/// Domain label of the share HPKE `info` string (§5.5).
const SHARE_INFO_TAG: &str = "eg/v1/dkg-share";

/// A trustee's HPKE private key for receiving shares (§5.5).
pub struct HpkeSecretKey(<Kem as hpke::Kem>::PrivateKey);

impl std::fmt::Debug for HpkeSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HpkeSecretKey(..)")
    }
}

/// A trustee's HPKE public key for receiving shares (§5.5).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HpkePublicKey(<Kem as hpke::Kem>::PublicKey);

/// Generates an HPKE key pair for receiving shares (§5.5).
pub fn hpke_keygen<R: RngCore + CryptoRng>(rng: &mut R) -> (HpkeSecretKey, HpkePublicKey) {
    let (sk, pk) = <Kem as hpke::Kem>::gen_keypair(rng);
    (HpkeSecretKey(sk), HpkePublicKey(pk))
}

/// True if `bytes` is a small-order X25519 point. Such a key makes HPKE
/// encapsulation fail, so it is rejected when parsed. A clamped scalar
/// multiple of 8 annihilates every point whose order divides 8.
fn is_small_order(bytes: &[u8; 32]) -> bool {
    let mut scalar = [0u8; 32];
    scalar[0] = 8;
    MontgomeryPoint(*bytes).mul_clamped(scalar).0 == [0u8; 32]
}

impl HpkePublicKey {
    /// Encodes the key as a 32-byte CBOR byte string (§5.5).
    pub fn to_value(&self) -> Value {
        Value::Bytes(self.0.to_bytes().to_vec())
    }

    /// Decodes a key from a 32-byte CBOR byte string (§5.5).
    ///
    /// Returns [`Error::InvalidPublicKey`] on wrong length or a small-order point.
    pub fn from_value(v: &Value) -> Result<HpkePublicKey, Error> {
        let bytes: [u8; 32] = v
            .as_bytes()
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::InvalidPublicKey)?;
        if is_small_order(&bytes) {
            return Err(Error::InvalidPublicKey);
        }
        let pk = <<Kem as hpke::Kem>::PublicKey as Deserializable>::from_bytes(&bytes)
            .map_err(|_| Error::InvalidPublicKey)?;
        Ok(HpkePublicKey(pk))
    }
}

/// A share encrypted to one recipient: `{0: "enc_share", 1: j, 2: enc, 3: ciphertext}` (§8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncShare {
    /// Recipient index j.
    pub recipient: u64,
    /// HPKE encapsulated key.
    pub enc: Vec<u8>,
    /// HPKE ciphertext of the 32-byte share scalar, with the 16-byte tag appended.
    pub ciphertext: Vec<u8>,
}

impl EncShare {
    /// Encodes the share as a CBOR record (§8.2).
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(0), Value::from("enc_share")),
            (Value::Uint(1), Value::Uint(self.recipient)),
            (Value::Uint(2), Value::Bytes(self.enc.clone())),
            (Value::Uint(3), Value::Bytes(self.ciphertext.clone())),
        ])
    }

    /// Decodes a share from a CBOR record, rejecting unknown keys (§6.2, §8.2).
    pub fn from_value(v: &Value) -> Result<EncShare, Error> {
        let fields = cbor::record_fields(v, "enc_share", 4)?;
        Ok(EncShare {
            recipient: fields[1].as_uint()?,
            enc: fields[2].as_bytes()?.to_vec(),
            ciphertext: fields[3].as_bytes()?.to_vec(),
        })
    }
}

/// HPKE `info` for the share from `sender` to `recipient`:
/// `CBOR(["eg/v1/dkg-share", manifest_hash, sender, recipient])` (§5.5).
pub fn share_info(manifest_hash: &[u8; 32], sender: u64, recipient: u64) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::from(SHARE_INFO_TAG),
        Value::from(*manifest_hash),
        Value::Uint(sender),
        Value::Uint(recipient),
    ]))
}

/// Encrypts share p_{sender→recipient} to the recipient's HPKE key (§5.5, §8.2).
///
/// Encapsulation cannot fail for a key from [`hpke_keygen`] or
/// [`HpkePublicKey::from_value`], since both reject small-order points.
pub fn encrypt_share<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &HpkePublicKey,
    manifest_hash: &[u8; 32],
    sender: u64,
    recipient: u64,
    share: &Scalar,
) -> EncShare {
    let info = share_info(manifest_hash, sender, recipient);
    let mut plaintext = share.to_bytes();
    let (enc, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem, R>(
        &OpModeS::Base,
        &pk.0,
        &info,
        &plaintext,
        &[],
        rng,
    )
    .expect("HPKE seal cannot fail for a validated public key");
    plaintext.zeroize();
    EncShare {
        recipient,
        enc: enc.to_bytes().to_vec(),
        ciphertext,
    }
}

/// Decrypts and decodes a share (§5.5, §8.2).
///
/// Returns [`Error::ShareDecryption`] if the recipient index does not match, or
/// if HPKE open fails (wrong key, wrong info, tampered `enc` or ciphertext).
/// Returns [`Error::InvalidScalar`] if the plaintext is not a canonical scalar.
pub fn decrypt_share(
    sk: &HpkeSecretKey,
    manifest_hash: &[u8; 32],
    sender: u64,
    recipient: u64,
    enc_share: &EncShare,
) -> Result<Scalar, Error> {
    if enc_share.recipient != recipient {
        return Err(Error::ShareDecryption);
    }
    let info = share_info(manifest_hash, sender, recipient);
    let enc = <HpkeEncappedKey as Deserializable>::from_bytes(&enc_share.enc)
        .map_err(|_| Error::ShareDecryption)?;
    let mut plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk.0,
        &enc,
        &info,
        &enc_share.ciphertext,
        &[],
    )
    .map_err(|_| Error::ShareDecryption)?;
    let scalar = decode_scalar(&plaintext);
    plaintext.zeroize();
    scalar
}

/// Decodes a 32-byte little-endian canonical scalar.
fn decode_scalar(bytes: &[u8]) -> Result<Scalar, Error> {
    let mut arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidScalar)?;
    let scalar = Option::from(Scalar::from_canonical_bytes(arr)).ok_or(Error::InvalidScalar);
    arr.zeroize();
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::CborError;
    use crate::group::random_scalar;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([17u8; 32])
    }

    const MH: [u8; 32] = [0x42; 32];

    fn sample(rng: &mut ChaCha20Rng) -> (Scalar, HpkeSecretKey, HpkePublicKey, EncShare) {
        let share = random_scalar(rng);
        let (sk, pk) = hpke_keygen(rng);
        let enc = encrypt_share(rng, &pk, &MH, 1, 2, &share);
        (share, sk, pk, enc)
    }

    #[test]
    fn round_trip() {
        let mut rng = rng();
        let (share, sk, _, enc) = sample(&mut rng);
        assert_eq!(decrypt_share(&sk, &MH, 1, 2, &enc), Ok(share));
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let mut rng = rng();
        let (_, _, _, enc) = sample(&mut rng);
        let (other_sk, _) = hpke_keygen(&mut rng);
        assert_eq!(
            decrypt_share(&other_sk, &MH, 1, 2, &enc),
            Err(Error::ShareDecryption)
        );
    }

    #[test]
    fn info_is_bound() {
        let mut rng = rng();
        let (_, sk, _, enc) = sample(&mut rng);
        let other_mh = [0x43; 32];
        assert_eq!(
            decrypt_share(&sk, &other_mh, 1, 2, &enc),
            Err(Error::ShareDecryption)
        );
        assert_eq!(
            decrypt_share(&sk, &MH, 3, 2, &enc),
            Err(Error::ShareDecryption)
        );
        // Swapped sender/recipient: the index check passes, so HPKE must fail.
        let mut swapped = enc.clone();
        swapped.recipient = 1;
        assert_eq!(
            decrypt_share(&sk, &MH, 2, 1, &swapped),
            Err(Error::ShareDecryption)
        );
    }

    #[test]
    fn wrong_recipient_index_fails() {
        let mut rng = rng();
        let (_, sk, _, enc) = sample(&mut rng);
        assert_eq!(
            decrypt_share(&sk, &MH, 1, 3, &enc),
            Err(Error::ShareDecryption)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut rng = rng();
        let (_, sk, _, mut enc) = sample(&mut rng);
        enc.ciphertext[0] ^= 1;
        assert_eq!(
            decrypt_share(&sk, &MH, 1, 2, &enc),
            Err(Error::ShareDecryption)
        );
    }

    #[test]
    fn tampered_enc_fails() {
        let mut rng = rng();
        let (_, sk, _, mut enc) = sample(&mut rng);
        enc.enc[0] ^= 1;
        assert_eq!(
            decrypt_share(&sk, &MH, 1, 2, &enc),
            Err(Error::ShareDecryption)
        );
    }

    #[test]
    fn enc_share_value_round_trip() {
        let mut rng = rng();
        let (_, _, _, enc) = sample(&mut rng);
        let v = enc.to_value();
        assert_eq!(EncShare::from_value(&v), Ok(enc));
    }

    #[test]
    fn enc_share_rejects_extra_key_and_wrong_tag() {
        let mut rng = rng();
        let (_, _, _, enc) = sample(&mut rng);
        let Value::Map(mut entries) = enc.to_value() else {
            unreachable!()
        };
        entries.push((Value::Uint(4), Value::Uint(0)));
        assert!(matches!(
            EncShare::from_value(&Value::Map(entries.clone())),
            Err(Error::Cbor(CborError::Schema(_)))
        ));
        entries.pop();
        entries[0].1 = Value::from("enc_sh");
        assert!(matches!(
            EncShare::from_value(&Value::Map(entries)),
            Err(Error::Cbor(CborError::Schema(_)))
        ));
    }

    #[test]
    fn info_is_cbor() {
        let mut expected = vec![0x84, 0x6f];
        expected.extend_from_slice(b"eg/v1/dkg-share");
        expected.extend_from_slice(&[0x58, 0x20]);
        expected.extend_from_slice(&[0xaa; 32]);
        expected.extend_from_slice(&[0x01, 0x02]);
        assert_eq!(share_info(&[0xaa; 32], 1, 2), expected);
    }

    #[test]
    fn public_key_value_round_trip() {
        let mut rng = rng();
        let (_, pk) = hpke_keygen(&mut rng);
        let v = pk.to_value();
        assert_eq!(HpkePublicKey::from_value(&v), Ok(pk));
    }

    #[test]
    fn public_key_rejects_bad_input() {
        assert_eq!(
            HpkePublicKey::from_value(&Value::Bytes(vec![7u8; 31])),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            HpkePublicKey::from_value(&Value::Bytes(vec![0u8; 32])),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            HpkePublicKey::from_value(&Value::Uint(0)),
            Err(Error::InvalidPublicKey)
        );
    }

    #[test]
    fn non_canonical_plaintext_scalar_rejected() {
        assert_eq!(decode_scalar(&[0xff; 32]), Err(Error::InvalidScalar));
        assert_eq!(decode_scalar(&[0u8; 31]), Err(Error::InvalidScalar));
    }
}
