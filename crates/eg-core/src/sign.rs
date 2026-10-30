//! Ed25519 signatures and signed records for eg/v1 (SPEC.md §5.4, §8.1).

use ed25519_dalek::Signer;

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use crate::cbor::{self, Value};
use crate::error::Error;

/// Prefix of every signature domain-separation tag (Appendix A).
pub const SIG_TAG_PREFIX: &str = "eg/v1/sig/";

/// Message signed for `(tag, obj)`: `CBOR([tag, obj])` (SPEC.md §5.4).
///
/// Panics if `tag` lacks [`SIG_TAG_PREFIX`]: tags are compile-time constants,
/// so a bad one is a programming error.
fn message(tag: &str, obj: &Value) -> Vec<u8> {
    assert!(
        tag.starts_with(SIG_TAG_PREFIX),
        "signature tag {tag:?} must start with {SIG_TAG_PREFIX:?}"
    );
    cbor::encode(&Value::Array(vec![Value::from(tag), obj.clone()]))
}

/// Sign(sk, tag, obj) = Ed25519.Sign(sk, CBOR([tag, obj])) (SPEC.md §5.4).
///
/// Panics if `tag` does not start with [`SIG_TAG_PREFIX`].
pub fn sign(sk: &SigningKey, tag: &str, obj: &Value) -> Signature {
    sk.sign(&message(tag, obj))
}

/// Verify(pk, tag, obj, sig) with strict verification (SPEC.md §5.4).
///
/// Returns `false` for any failure, including small-order keys and
/// non-canonical signatures. Panics if `tag` does not start with
/// [`SIG_TAG_PREFIX`].
pub fn verify(pk: &VerifyingKey, tag: &str, obj: &Value, sig: &Signature) -> bool {
    pk.verify_strict(&message(tag, obj), sig).is_ok()
}

/// Encodes a verifying key as a 32-byte CBOR byte string (`ed25519pk`, §5.4).
pub fn verifying_key_to_value(pk: &VerifyingKey) -> Value {
    Value::Bytes(pk.to_bytes().to_vec())
}

/// Decodes a verifying key from a 32-byte CBOR byte string (`ed25519pk`, §5.4).
///
/// Returns [`Error::InvalidPublicKey`] if the value is not a 32-byte byte
/// string or is not a valid Ed25519 point encoding.
pub fn verifying_key_from_value(v: &Value) -> Result<VerifyingKey, Error> {
    let bytes: [u8; 32] = v
        .as_bytes()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| Error::InvalidPublicKey)
}

/// Encodes a signature as a 64-byte CBOR byte string (`ed25519sig`, §5.4).
pub fn signature_to_value(sig: &Signature) -> Value {
    Value::Bytes(sig.to_bytes().to_vec())
}

/// Decodes a signature from a 64-byte CBOR byte string (`ed25519sig`, §5.4).
///
/// Returns [`Error::InvalidSignature`] if the value is not a 64-byte byte
/// string.
pub fn signature_from_value(v: &Value) -> Result<Signature, Error> {
    let bytes: [u8; 64] = v
        .as_bytes()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::InvalidSignature)?;
    Ok(Signature::from_bytes(&bytes))
}

/// Returns the uint key of a record field, panicking on any other key type.
fn uint_key(key: &Value) -> u64 {
    match key {
        Value::Uint(n) => *n,
        other => panic!("record keys must be uint, got {other:?}"),
    }
}

/// Builds a signed record (SPEC.md §8.1).
///
/// `fields` are the map entries without the signature, keyed by uint. The
/// signature is `Sign(sk, tag, Map(fields))` and is stored under `sig_key`,
/// which becomes the last field of the record.
///
/// Panics if a key is not a uint or if `sig_key` is not greater than every
/// field key (programming errors).
pub fn sign_record(sk: &SigningKey, tag: &str, fields: Vec<(Value, Value)>, sig_key: u64) -> Value {
    for (key, _) in &fields {
        let n = uint_key(key);
        assert!(
            n < sig_key,
            "signature key {sig_key} must be greater than field key {n}"
        );
    }
    let sig = sign(sk, tag, &Value::Map(fields.clone()));
    let mut entries = fields;
    entries.push((Value::Uint(sig_key), signature_to_value(&sig)));
    Value::Map(entries)
}

/// Checks a signed record (SPEC.md §8.1).
///
/// `record` must be a map whose largest key is `sig_key`. That entry is
/// removed and the signature is verified over the remaining map.
///
/// Errors:
/// - not a map, a non-uint key, a missing `sig_key`, or `sig_key` not the
///   largest key: [`Error::Cbor`] with a schema error;
/// - malformed signature bytes or a failed verification:
///   [`Error::InvalidSignature`].
pub fn verify_record(
    pk: &VerifyingKey,
    tag: &str,
    record: &Value,
    sig_key: u64,
) -> Result<(), Error> {
    let entries = record.as_map()?;
    let mut largest = None;
    let mut sig_value = None;
    for (key, value) in entries {
        let n = match key {
            Value::Uint(n) => *n,
            _ => return Err(cbor::CborError::Schema("record keys must be uint".into()).into()),
        };
        if n == sig_key {
            sig_value = Some(value);
        }
        largest = Some(largest.map_or(n, |m: u64| m.max(n)));
    }
    let sig_value = sig_value.ok_or_else(|| {
        cbor::CborError::Schema(format!("record has no signature field {sig_key}"))
    })?;
    if largest != Some(sig_key) {
        return Err(cbor::CborError::Schema(format!(
            "signature field {sig_key} is not the last field"
        ))
        .into());
    }
    let sig = signature_from_value(sig_value)?;
    let rest: Vec<(Value, Value)> = entries
        .iter()
        .filter(|(k, _)| !matches!(k, Value::Uint(n) if *n == sig_key))
        .cloned()
        .collect();
    if verify(pk, tag, &Value::Map(rest), &sig) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([13u8; 32])
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn obj() -> Value {
        Value::Map(vec![(Value::Uint(0), Value::from("ballot"))])
    }

    const TAG: &str = "eg/v1/sig/test";

    #[test]
    fn sign_verify_round_trip() {
        let sk = SigningKey::generate(&mut rng());
        let sig = sign(&sk, TAG, &obj());
        assert!(verify(&sk.verifying_key(), TAG, &obj(), &sig));
    }

    #[test]
    fn wrong_tag_fails() {
        let sk = SigningKey::generate(&mut rng());
        let sig = sign(&sk, "eg/v1/sig/a", &obj());
        assert!(!verify(&sk.verifying_key(), "eg/v1/sig/b", &obj(), &sig));
    }

    #[test]
    fn wrong_obj_fails() {
        let sk = SigningKey::generate(&mut rng());
        let sig = sign(&sk, TAG, &obj());
        assert!(!verify(&sk.verifying_key(), TAG, &Value::Uint(1), &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let mut rng = rng();
        let sk = SigningKey::generate(&mut rng);
        let other = SigningKey::generate(&mut rng);
        let sig = sign(&sk, TAG, &obj());
        assert!(!verify(&other.verifying_key(), TAG, &obj(), &sig));
    }

    #[test]
    fn message_is_cbor_of_tag_and_obj() {
        let sk = SigningKey::generate(&mut rng());
        let sig = sign(&sk, "eg/v1/sig/t", &Value::Uint(5));
        // CBOR([ "eg/v1/sig/t", 5 ]) = 82 6b <11 bytes> 05
        let mut manual = vec![0x82, 0x6b];
        manual.extend_from_slice(b"eg/v1/sig/t");
        manual.push(0x05);
        assert!(sk.verifying_key().verify_strict(&manual, &sig).is_ok());
    }

    #[test]
    fn rfc8032_test_vector_1() {
        // RFC 8032 section 7.1, TEST 1 (empty message).
        let sk_bytes: [u8; 32] =
            arr("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pk_bytes: [u8; 32] =
            arr("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig_bytes: [u8; 64] = arr(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let sk = SigningKey::from_bytes(&sk_bytes);
        assert_eq!(sk.verifying_key().to_bytes(), pk_bytes);
        assert_eq!(sk.sign(b"").to_bytes(), sig_bytes);
        assert!(VerifyingKey::from_bytes(&pk_bytes)
            .unwrap()
            .verify_strict(b"", &Signature::from_bytes(&sig_bytes))
            .is_ok());
    }

    #[test]
    fn strict_rejects_small_order_key() {
        // The identity point encoding is a small-order key. Whether or not
        // it parses, no signature may verify under it.
        let identity: [u8; 32] =
            arr("0100000000000000000000000000000000000000000000000000000000000000");
        if let Ok(pk) = VerifyingKey::from_bytes(&identity) {
            let sig = Signature::from_bytes(&[0u8; 64]);
            assert!(!verify(&pk, TAG, &obj(), &sig));
        }
    }

    #[test]
    fn key_and_signature_encoding_round_trip() {
        let sk = SigningKey::generate(&mut rng());
        let pk = sk.verifying_key();
        let pk_value = verifying_key_to_value(&pk);
        assert_eq!(pk_value, Value::Bytes(pk.to_bytes().to_vec()));
        assert_eq!(verifying_key_from_value(&pk_value).unwrap(), pk);

        let sig = sign(&sk, TAG, &obj());
        let sig_value = signature_to_value(&sig);
        assert_eq!(sig_value, Value::Bytes(sig.to_bytes().to_vec()));
        assert_eq!(signature_from_value(&sig_value).unwrap(), sig);
    }

    #[test]
    fn rejects_bad_encoding_lengths() {
        assert_eq!(
            verifying_key_from_value(&Value::Bytes(vec![0u8; 31])),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            verifying_key_from_value(&Value::Uint(0)),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            signature_from_value(&Value::Bytes(vec![0u8; 63])),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            signature_from_value(&Value::Bytes(vec![0u8; 65])),
            Err(Error::InvalidSignature)
        );
    }

    fn record_fields() -> Vec<(Value, Value)> {
        vec![
            (Value::Uint(0), Value::from("t")),
            (Value::Uint(1), Value::Uint(1)),
            (Value::Uint(2), Value::Bytes(vec![7u8; 32])),
        ]
    }

    #[test]
    fn record_round_trip() {
        let sk = SigningKey::generate(&mut rng());
        let pk = sk.verifying_key();
        let record = sign_record(&sk, TAG, record_fields(), 3);
        assert!(record.get(3).unwrap().is_some());
        assert_eq!(verify_record(&pk, TAG, &record, 3), Ok(()));
    }

    #[test]
    fn record_tampered_field_fails() {
        let sk = SigningKey::generate(&mut rng());
        let pk = sk.verifying_key();
        let mut fields = record_fields();
        let record = sign_record(&sk, TAG, fields.clone(), 3);
        fields[1].1 = Value::Uint(2);
        let mut tampered = Value::Map(fields);
        if let Value::Map(entries) = &mut tampered {
            entries.push((Value::Uint(3), record.get(3).unwrap().unwrap().clone()));
        }
        assert_eq!(
            verify_record(&pk, TAG, &tampered, 3),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn record_missing_signature_is_rejected() {
        let sk = SigningKey::generate(&mut rng());
        let pk = sk.verifying_key();
        let unsigned = Value::Map(record_fields());
        assert!(matches!(
            verify_record(&pk, TAG, &unsigned, 3),
            Err(Error::Cbor(cbor::CborError::Schema(_)))
        ));
    }

    #[test]
    fn record_signature_not_last_is_rejected() {
        let sk = SigningKey::generate(&mut rng());
        let pk = sk.verifying_key();
        let mut record = sign_record(&sk, TAG, record_fields(), 3);
        if let Value::Map(entries) = &mut record {
            entries.push((Value::Uint(4), Value::Uint(0)));
        }
        assert!(matches!(
            verify_record(&pk, TAG, &record, 3),
            Err(Error::Cbor(cbor::CborError::Schema(_)))
        ));
    }

    #[test]
    fn record_non_map_is_rejected() {
        let sk = SigningKey::generate(&mut rng());
        let pk = sk.verifying_key();
        assert!(matches!(
            verify_record(&pk, TAG, &Value::Uint(1), 3),
            Err(Error::Cbor(cbor::CborError::Schema(_)))
        ));
    }

    #[test]
    #[should_panic(expected = "must be greater than field key")]
    fn sign_record_panics_when_sig_key_not_largest() {
        let sk = SigningKey::generate(&mut rng());
        let _ = sign_record(&sk, TAG, record_fields(), 2);
    }

    #[test]
    #[should_panic(expected = "must start with")]
    fn sign_panics_on_bad_tag() {
        let sk = SigningKey::generate(&mut rng());
        let _ = sign(&sk, "eg/v1/other", &obj());
    }
}
