//! Error type for eg/v1 core primitives.

/// Errors produced by the eg/v1 core primitives.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("cbor: {0}")]
    Cbor(#[from] crate::cbor::CborError),
    #[error("not a canonical Ristretto255 point encoding")]
    InvalidPoint,
    #[error("scalar encoding is not canonical (>= group order)")]
    InvalidScalar,
    #[error("identity element where it is forbidden")]
    IdentityPoint,
    #[error("invalid trustee index set")]
    InvalidIndexSet,
    #[error("encryption nonce must be nonzero")]
    ZeroNonce,
    #[error("not a valid Ed25519 public key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("share decryption failed")]
    ShareDecryption,
    #[error("key ceremony: {0}")]
    Ceremony(String),
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("board: {0}")]
    Board(String),
}
