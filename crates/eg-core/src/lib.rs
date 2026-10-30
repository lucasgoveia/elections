//! eg/v1 core primitives (SPEC.md §5, §6, §10, §11).

pub mod apportionment;
pub mod ballot;
pub mod board;
pub mod cbor;
pub mod ceremony;
pub mod dkg;
pub mod elgamal;
pub mod error;
#[cfg(any(test, feature = "fixtures"))]
pub mod fixtures;
pub mod group;
pub mod hash;
pub mod manifest;
pub mod proofs;
pub mod registry;
pub mod share_enc;
pub mod shuffle;
pub mod sign;

pub use error::Error;
