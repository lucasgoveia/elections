//! Domain-separated hashes for eg/v1 (SPEC.md §5.3).

use sha2::{Digest, Sha256, Sha512};

use crate::cbor::{self, Value};
use crate::group::Scalar;

/// Prefix every domain-separation tag must start with (SPEC.md §5.3, Appendix A).
pub const TAG_PREFIX: &str = "eg/v1/";

/// Digest(tag, x1..xn) = SHA-256(CBOR([tag, x1, ..., xn])) (SPEC.md §5.3).
pub fn digest(tag: &str, items: &[Value]) -> [u8; 32] {
    Sha256::digest(transcript(tag, items)).into()
}

/// HashToScalar(tag, x1..xn) = SHA-512(CBOR([tag, x1, ..., xn])) mod ℓ
/// (SPEC.md §5.3).
pub fn hash_to_scalar(tag: &str, items: &[Value]) -> Scalar {
    let wide: [u8; 64] = Sha512::digest(transcript(tag, items)).into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Builds the deterministic CBOR input `CBOR([tag, x1, ..., xn])`.
///
/// Panics if `tag` does not start with [`TAG_PREFIX`]: tags are compile-time
/// constants, so a bad one is a programming error.
fn transcript(tag: &str, items: &[Value]) -> Vec<u8> {
    assert!(
        tag.starts_with(TAG_PREFIX),
        "domain-separation tag {tag:?} must start with {TAG_PREFIX:?}"
    );
    let mut arr = Vec::with_capacity(items.len() + 1);
    arr.push(Value::from(tag));
    arr.extend_from_slice(items);
    cbor::encode(&Value::Array(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{point_to_value, scalar_to_value, B};

    /// Hand-written CBOR for ["eg/v1/test", 1, bstr(32 x 0xab)].
    fn manual_test_transcript() -> Vec<u8> {
        let mut out = vec![0x83, 0x6a];
        out.extend_from_slice(b"eg/v1/test");
        out.push(0x01);
        out.extend_from_slice(&[0x58, 0x20]);
        out.extend_from_slice(&[0xab; 32]);
        out
    }

    fn test_items() -> Vec<Value> {
        vec![Value::Uint(1), Value::Bytes(vec![0xab; 32])]
    }

    #[test]
    fn digest_matches_manual_computation() {
        let expected: [u8; 32] = Sha256::digest(manual_test_transcript()).into();
        assert_eq!(digest("eg/v1/test", &test_items()), expected);
    }

    #[test]
    fn hash_to_scalar_matches_manual_computation() {
        let wide: [u8; 64] = Sha512::digest(manual_test_transcript()).into();
        let expected = Scalar::from_bytes_mod_order_wide(&wide);
        assert_eq!(hash_to_scalar("eg/v1/test", &test_items()), expected);
    }

    #[test]
    fn domain_separation() {
        let items = test_items();
        assert_ne!(digest("eg/v1/a", &items), digest("eg/v1/b", &items));
        assert_ne!(
            hash_to_scalar("eg/v1/a", &items),
            hash_to_scalar("eg/v1/b", &items)
        );
    }

    #[test]
    fn item_boundaries_matter() {
        let a = [Value::Bytes(b"ab".to_vec()), Value::Bytes(b"c".to_vec())];
        let b = [Value::Bytes(b"a".to_vec()), Value::Bytes(b"bc".to_vec())];
        assert_ne!(digest("eg/v1/t", &a), digest("eg/v1/t", &b));
        assert_ne!(hash_to_scalar("eg/v1/t", &a), hash_to_scalar("eg/v1/t", &b));
    }

    #[test]
    #[should_panic]
    fn rejects_tag_without_prefix() {
        digest("other/x", &[]);
    }

    #[test]
    fn point_and_scalar_items() {
        let items = [point_to_value(&B), scalar_to_value(&Scalar::ONE)];
        assert_eq!(digest("eg/v1/test", &items), digest("eg/v1/test", &items));
    }
}
