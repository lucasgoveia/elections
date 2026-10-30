//! eg/v1 core primitives (SPEC.md §5, §6, §10, §11).

pub mod cbor;
pub mod dkg;
pub mod elgamal;
pub mod error;
pub mod group;
pub mod hash;
pub mod proofs;
pub mod share_enc;
pub mod sign;

pub use error::Error;
