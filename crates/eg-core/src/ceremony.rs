//! Key-ceremony records and public verification (SPEC.md §7.1, §8, §9).
//!
//! Every round message is a signed record: the signature is the last field and
//! covers the map of all other fields (SPEC.md §8.1). Records are decoded
//! strictly, checked against the trustee set, and verified under the sig key
//! of their author. [`verify_ceremony`] checks a whole published transcript and
//! derives the election context.

use std::fmt;

use rand_core::{CryptoRng, RngCore};

use crate::cbor::{self, CborError, Value};
use crate::dkg::{
    joint_public_key, secret_share, verification_key, verify_coefficients, verify_share, Polynomial,
};
use crate::error::Error;
use crate::group::{
    point_from_value, point_nonidentity_from_value, point_to_value, scalar_from_value,
    scalar_to_value, RistrettoPoint, Scalar,
};
use crate::hash::digest;
use crate::proofs::SchnorrProof;
use crate::share_enc::{decrypt_share, encrypt_share, EncShare, HpkePublicKey, HpkeSecretKey};
use crate::sign::{
    sign_record, verify_record, verifying_key_from_value, verifying_key_to_value, SigningKey,
    VerifyingKey,
};

/// Version carried by every ceremony record (SPEC.md §8).
const VERSION: u64 = 1;

/// Signature domain tags of the round records (SPEC.md §8.1–§8.4).
const SIG_DKG1: &str = "eg/v1/sig/dkg1";
const SIG_DKG2: &str = "eg/v1/sig/dkg2";
const SIG_DKG3: &str = "eg/v1/sig/dkg3";
const SIG_COMPLAINT: &str = "eg/v1/sig/dkg-complaint";
const SIG_REVEAL: &str = "eg/v1/sig/dkg-reveal";

fn schema(msg: impl Into<String>) -> Error {
    Error::Cbor(CborError::Schema(msg.into()))
}

fn ceremony(msg: impl Into<String>) -> Error {
    Error::Ceremony(msg.into())
}

/// Checks that a record's version field (key 1) is 1 (SPEC.md §8).
fn check_version(v: &Value) -> Result<(), Error> {
    if v.as_uint()? != VERSION {
        return Err(schema("unsupported record version"));
    }
    Ok(())
}

/// Decodes a 32-byte digest (manifest hash, transcript hash) from a byte string.
fn bytes32(v: &Value) -> Result<[u8; 32], Error> {
    let bytes: [u8; 32] = v
        .as_bytes()?
        .try_into()
        .map_err(|_| schema("expected a 32-byte digest"))?;
    Ok(bytes)
}

/// Rejects an empty `[+ ...]` array (SPEC.md §8).
fn non_empty<T>(items: Vec<T>, what: &str) -> Result<Vec<T>, Error> {
    if items.is_empty() {
        return Err(schema(format!("{what} must not be empty")));
    }
    Ok(items)
}

/// Strictly decodes a signed round record and verifies its signature under the
/// sig key of its author (key 3 in every round record, SPEC.md §8.1–§8.4). The
/// signature is the last field, key `n_fields − 1`.
fn open_record<'a>(
    v: &'a Value,
    type_tag: &str,
    n_fields: usize,
    sig_tag: &str,
    set: &TrusteeSet,
) -> Result<Vec<&'a Value>, Error> {
    let fields = cbor::record_fields(v, type_tag, n_fields)?;
    check_version(fields[1])?;
    let author = fields[3].as_uint()?;
    let trustee = set
        .get(author)
        .ok_or_else(|| schema(format!("unknown trustee index {author}")))?;
    verify_record(&trustee.sig_key, sig_tag, v, (n_fields - 1) as u64)?;
    Ok(fields)
}

/// Header entries shared by every round record: tag, version and manifest hash.
fn header(type_tag: &str, manifest_hash: &[u8; 32]) -> Vec<(Value, Value)> {
    vec![
        (Value::Uint(0), Value::from(type_tag)),
        (Value::Uint(1), Value::Uint(VERSION)),
        (Value::Uint(2), Value::from(*manifest_hash)),
    ]
}

/// Orders records by trustee index and checks that there is exactly one per
/// index 1..n. A missing or duplicated index disqualifies that trustee
/// (SPEC.md §8.1–§8.3).
fn in_index_order<T>(mut items: Vec<(u64, T)>, n: u64) -> Result<Vec<T>, Error> {
    items.sort_by_key(|(i, _)| *i);
    let mut expected = 1;
    for (i, _) in &items {
        if *i != expected {
            return Err(ceremony(format!(
                "trustee {expected} disqualified: missing or duplicate record"
            )));
        }
        expected += 1;
    }
    if expected != n + 1 {
        return Err(ceremony(format!(
            "trustee {expected} disqualified: missing record"
        )));
    }
    Ok(items.into_iter().map(|(_, t)| t).collect())
}

/// One trustee's entry in the trustee set (SPEC.md §7.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrusteeInfo {
    pub index: u64,
    pub name: String,
    pub sig_key: VerifyingKey,
    pub hpke_key: HpkePublicKey,
    pub bloc: String,
}

impl TrusteeInfo {
    /// Encodes the entry as `trustee_info` (SPEC.md §7.1).
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(0), Value::from("trustee")),
            (Value::Uint(1), Value::Uint(self.index)),
            (Value::Uint(2), Value::from(self.name.as_str())),
            (Value::Uint(3), verifying_key_to_value(&self.sig_key)),
            (Value::Uint(4), self.hpke_key.to_value()),
            (Value::Uint(5), Value::from(self.bloc.as_str())),
        ])
    }
}

/// The trustee set `trustee_set` (SPEC.md §7.1). Trustees are numbered 1..n.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrusteeSet {
    pub k: u64,
    pub trustees: Vec<TrusteeInfo>,
}

impl TrusteeSet {
    /// Number of trustees, n.
    pub fn n(&self) -> u64 {
        self.trustees.len() as u64
    }

    /// Encodes the set as `trustee_set` (SPEC.md §7.1).
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(0), Value::from("trustees")),
            (Value::Uint(1), Value::Uint(self.n())),
            (Value::Uint(2), Value::Uint(self.k)),
            (
                Value::Uint(3),
                Value::Array(self.trustees.iter().map(TrusteeInfo::to_value).collect()),
            ),
        ])
    }

    /// Strict decode: 2 ≤ k ≤ n, exactly n entries, indices 1..n in order
    /// (SPEC.md §7.1). Schema errors otherwise.
    pub fn from_value(v: &Value) -> Result<TrusteeSet, Error> {
        let f = cbor::record_fields(v, "trustees", 4)?;
        let n = f[1].as_uint()?;
        let k = f[2].as_uint()?;
        if !(2..=n).contains(&k) {
            return Err(schema("trustee set must satisfy 2 <= k <= n"));
        }
        let entries = f[3].as_array()?;
        if entries.len() as u64 != n {
            return Err(schema("trustee count does not match n"));
        }
        let mut trustees = Vec::with_capacity(entries.len());
        for (pos, entry) in entries.iter().enumerate() {
            let t = cbor::record_fields(entry, "trustee", 6)?;
            let index = t[1].as_uint()?;
            if index != pos as u64 + 1 {
                return Err(schema("trustee indices must be 1..n in order"));
            }
            trustees.push(TrusteeInfo {
                index,
                name: t[2].as_text()?.to_owned(),
                sig_key: verifying_key_from_value(t[3])?,
                hpke_key: HpkePublicKey::from_value(t[4])?,
                bloc: t[5].as_text()?.to_owned(),
            });
        }
        Ok(TrusteeSet { k, trustees })
    }

    /// The trustee with index `i`, if any.
    pub fn get(&self, i: u64) -> Option<&TrusteeInfo> {
        self.trustees.iter().find(|t| t.index == i)
    }
}

/// Round-1 record `dkg_round1`: commitments and proofs of trustee i (SPEC.md §8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round1 {
    pub manifest_hash: [u8; 32],
    pub i: u64,
    pub commitments: Vec<RistrettoPoint>,
    pub proofs: Vec<SchnorrProof>,
}

impl Round1 {
    /// Commits to polynomial `poly` and proves knowledge of each coefficient
    /// (SPEC.md §8.1).
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        manifest_hash: &[u8; 32],
        i: u64,
        poly: &Polynomial,
    ) -> Round1 {
        Round1 {
            manifest_hash: *manifest_hash,
            i,
            commitments: poly.commitments(),
            proofs: poly.prove_coefficients(rng, manifest_hash, i),
        }
    }

    /// Builds and signs the record with trustee i's signing key (SPEC.md §8.1).
    pub fn sign(&self, sk: &SigningKey) -> Value {
        let mut fields = header("dkg_round1", &self.manifest_hash);
        fields.push((Value::Uint(3), Value::Uint(self.i)));
        fields.push((
            Value::Uint(4),
            Value::Array(self.commitments.iter().map(point_to_value).collect()),
        ));
        fields.push((
            Value::Uint(5),
            Value::Array(self.proofs.iter().map(SchnorrProof::to_value).collect()),
        ));
        sign_record(sk, SIG_DKG1, fields, 6)
    }

    /// Strictly decodes and verifies a signed round-1 record against `set`
    /// (SPEC.md §8.1).
    pub fn from_signed(v: &Value, set: &TrusteeSet) -> Result<Round1, Error> {
        let f = open_record(v, "dkg_round1", 7, SIG_DKG1, set)?;
        let commitments = f[4]
            .as_array()?
            .iter()
            .map(point_nonidentity_from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let proofs = f[5]
            .as_array()?
            .iter()
            .map(SchnorrProof::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Round1 {
            manifest_hash: bytes32(f[2])?,
            i: f[3].as_uint()?,
            commitments: non_empty(commitments, "commitments")?,
            proofs: non_empty(proofs, "proofs")?,
        })
    }
}

/// Round-2 record `dkg_round2`: encrypted shares from trustee i (SPEC.md §8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round2 {
    pub manifest_hash: [u8; 32],
    pub i: u64,
    pub shares: Vec<EncShare>,
}

impl Round2 {
    /// Encrypts P_i(j) to every j ≠ i in `set`, sorted by j (SPEC.md §8.2).
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        manifest_hash: &[u8; 32],
        i: u64,
        poly: &Polynomial,
        set: &TrusteeSet,
    ) -> Round2 {
        let mut others: Vec<&TrusteeInfo> = set.trustees.iter().filter(|t| t.index != i).collect();
        others.sort_by_key(|t| t.index);
        let mut shares = Vec::with_capacity(others.len());
        for t in others {
            let share = poly.eval(t.index);
            shares.push(encrypt_share(
                rng,
                &t.hpke_key,
                manifest_hash,
                i,
                t.index,
                &share,
            ));
        }
        Round2 {
            manifest_hash: *manifest_hash,
            i,
            shares,
        }
    }

    /// Builds and signs the record with trustee i's signing key (SPEC.md §8.2).
    pub fn sign(&self, sk: &SigningKey) -> Value {
        let mut fields = header("dkg_round2", &self.manifest_hash);
        fields.push((Value::Uint(3), Value::Uint(self.i)));
        fields.push((
            Value::Uint(4),
            Value::Array(self.shares.iter().map(EncShare::to_value).collect()),
        ));
        sign_record(sk, SIG_DKG2, fields, 5)
    }

    /// Strictly decodes and verifies a signed round-2 record against `set`
    /// (SPEC.md §8.2).
    pub fn from_signed(v: &Value, set: &TrusteeSet) -> Result<Round2, Error> {
        let f = open_record(v, "dkg_round2", 6, SIG_DKG2, set)?;
        let shares = f[4]
            .as_array()?
            .iter()
            .map(EncShare::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Round2 {
            manifest_hash: bytes32(f[2])?,
            i: f[3].as_uint()?,
            shares: non_empty(shares, "shares")?,
        })
    }
}

/// Transcript hash over the signed round-1 and round-2 records, each in index
/// order 1..n (SPEC.md §8.5).
pub fn transcript_hash(manifest_hash: &[u8; 32], round1: &[Value], round2: &[Value]) -> [u8; 32] {
    digest(
        "eg/v1/dkg-transcript",
        &[
            Value::from(*manifest_hash),
            Value::Array(round1.to_vec()),
            Value::Array(round2.to_vec()),
        ],
    )
}

/// Outcome for trustee j after round 2 (SPEC.md §8.3).
pub enum ShareOutcome {
    /// Every share addressed to j verified; `z_j` is j's secret share.
    Accept { z_j: Scalar },
    /// These senders sent a share that is missing, undecryptable or invalid.
    Complain { accused: Vec<u64> },
}

impl fmt::Debug for ShareOutcome {
    /// Redacted: never prints `z_j`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShareOutcome::Accept { .. } => f.write_str("Accept { z_j: .. }"),
            ShareOutcome::Complain { accused } => f
                .debug_struct("Complain")
                .field("accused", accused)
                .finish(),
        }
    }
}

/// Decrypts every share addressed to j, checks each against its sender's round-1
/// commitments, and returns z_j if all pass, else the failing senders (SPEC.md §8.3).
///
/// A missing share for j, or a decryption error, counts as a failing sender.
pub fn process_shares(
    manifest_hash: &[u8; 32],
    j: u64,
    own: &Polynomial,
    hpke_sk: &HpkeSecretKey,
    round1: &[Round1],
    round2: &[Round2],
) -> ShareOutcome {
    let mut senders: Vec<&Round1> = round1.iter().filter(|r| r.i != j).collect();
    senders.sort_by_key(|r| r.i);
    let mut received = Vec::with_capacity(senders.len());
    let mut accused = Vec::new();
    for r1 in senders {
        let share = round2
            .iter()
            .find(|r2| r2.i == r1.i)
            .and_then(|r2| r2.shares.iter().find(|s| s.recipient == j))
            .and_then(|enc| decrypt_share(hpke_sk, manifest_hash, r1.i, j, enc).ok())
            .filter(|p| verify_share(&r1.commitments, j, p));
        match share {
            Some(p) => received.push(p),
            None => accused.push(r1.i),
        }
    }
    if accused.is_empty() {
        ShareOutcome::Accept {
            z_j: secret_share(own, j, &received),
        }
    } else {
        ShareOutcome::Complain { accused }
    }
}

/// Round-3 record `dkg_round3`: trustee j accepts the transcript (SPEC.md §8.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Round3 {
    pub manifest_hash: [u8; 32],
    pub j: u64,
    pub transcript_hash: [u8; 32],
}

impl Round3 {
    /// Builds and signs the record with trustee j's signing key (SPEC.md §8.5).
    pub fn sign(&self, sk: &SigningKey) -> Value {
        let mut fields = header("dkg_round3", &self.manifest_hash);
        fields.push((Value::Uint(3), Value::Uint(self.j)));
        fields.push((Value::Uint(4), Value::from(self.transcript_hash)));
        fields.push((Value::Uint(5), Value::from("accept")));
        sign_record(sk, SIG_DKG3, fields, 6)
    }

    /// Strictly decodes and verifies a signed round-3 record against `set`
    /// (SPEC.md §8.5).
    pub fn from_signed(v: &Value, set: &TrusteeSet) -> Result<Round3, Error> {
        let f = open_record(v, "dkg_round3", 7, SIG_DKG3, set)?;
        if f[5].as_text()? != "accept" {
            return Err(schema("round 3 must carry \"accept\""));
        }
        Ok(Round3 {
            manifest_hash: bytes32(f[2])?,
            j: f[3].as_uint()?,
            transcript_hash: bytes32(f[4])?,
        })
    }
}

/// Complaint record `dkg_complaint`: trustee j reports a bad share from i (SPEC.md §8.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Complaint {
    pub manifest_hash: [u8; 32],
    pub j: u64,
    pub i: u64,
}

impl Complaint {
    /// Builds and signs the complaint with trustee j's signing key (SPEC.md §8.4).
    pub fn sign(&self, sk: &SigningKey) -> Value {
        let mut fields = header("dkg_complaint", &self.manifest_hash);
        fields.push((Value::Uint(3), Value::Uint(self.j)));
        fields.push((Value::Uint(4), Value::Uint(self.i)));
        sign_record(sk, SIG_COMPLAINT, fields, 5)
    }

    /// Strictly decodes and verifies a signed complaint against `set` (SPEC.md §8.4).
    pub fn from_signed(v: &Value, set: &TrusteeSet) -> Result<Complaint, Error> {
        let f = open_record(v, "dkg_complaint", 6, SIG_COMPLAINT, set)?;
        Ok(Complaint {
            manifest_hash: bytes32(f[2])?,
            j: f[3].as_uint()?,
            i: f[4].as_uint()?,
        })
    }
}

/// Reveal record `dkg_reveal`: accused trustee i publishes p_{i→j} in clear (SPEC.md §8.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub manifest_hash: [u8; 32],
    pub i: u64,
    pub j: u64,
    pub share: Scalar,
}

impl Reveal {
    /// Builds and signs the reveal with trustee i's signing key (SPEC.md §8.4).
    pub fn sign(&self, sk: &SigningKey) -> Value {
        let mut fields = header("dkg_reveal", &self.manifest_hash);
        fields.push((Value::Uint(3), Value::Uint(self.i)));
        fields.push((Value::Uint(4), Value::Uint(self.j)));
        fields.push((Value::Uint(5), scalar_to_value(&self.share)));
        sign_record(sk, SIG_REVEAL, fields, 6)
    }

    /// Strictly decodes and verifies a signed reveal against `set` (SPEC.md §8.4).
    pub fn from_signed(v: &Value, set: &TrusteeSet) -> Result<Reveal, Error> {
        let f = open_record(v, "dkg_reveal", 7, SIG_REVEAL, set)?;
        Ok(Reveal {
            manifest_hash: bytes32(f[2])?,
            i: f[3].as_uint()?,
            j: f[4].as_uint()?,
            share: scalar_from_value(f[5])?,
        })
    }
}

/// The election context (SPEC.md §9): joint key K and verification keys Z_1..Z_n.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub manifest_hash: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub k: RistrettoPoint,
    /// z[j-1] = Z_j.
    pub z: Vec<RistrettoPoint>,
}

impl Context {
    /// Encodes the context as `context` (SPEC.md §9).
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Uint(0), Value::from("context")),
            (Value::Uint(1), Value::Uint(VERSION)),
            (Value::Uint(2), Value::from(self.manifest_hash)),
            (Value::Uint(3), Value::from(self.transcript_hash)),
            (Value::Uint(4), point_to_value(&self.k)),
            (
                Value::Uint(5),
                Value::Array(self.z.iter().map(point_to_value).collect()),
            ),
        ])
    }

    /// Strict decode of a `context` record (SPEC.md §9). K must not be the identity.
    pub fn from_value(v: &Value) -> Result<Context, Error> {
        let f = cbor::record_fields(v, "context", 6)?;
        check_version(f[1])?;
        let z = f[5]
            .as_array()?
            .iter()
            .map(point_from_value)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Context {
            manifest_hash: bytes32(f[2])?,
            transcript_hash: bytes32(f[3])?,
            k: point_nonidentity_from_value(f[4])?,
            z: non_empty(z, "Z")?,
        })
    }

    /// context_hash = Digest("eg/v1/context", context) (SPEC.md §9).
    pub fn hash(&self) -> [u8; 32] {
        digest("eg/v1/context", &[self.to_value()])
    }
}

/// Everything published during the ceremony, as signed record Values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    pub round1: Vec<Value>,
    pub round2: Vec<Value>,
    pub round3: Vec<Value>,
    pub complaints: Vec<Value>,
    pub reveals: Vec<Value>,
}

/// Checks the whole ceremony and returns the election context (SPEC.md §8.1–§8.5, §9).
///
/// Any disqualification aborts the ceremony (v1). The error names the trustee.
pub fn verify_ceremony(
    manifest_hash: &[u8; 32],
    set: &TrusteeSet,
    published: &Published,
) -> Result<Context, Error> {
    let n = set.n();
    let k = set.k as usize;

    // 1. Round 1: exactly one valid record per trustee.
    let mut round1 = Vec::with_capacity(published.round1.len());
    for v in &published.round1 {
        let r = Round1::from_signed(v, set)?;
        round1.push((r.i, (r, v.clone())));
    }
    let round1 = in_index_order(round1, n)?;
    for (r, _) in &round1 {
        if r.manifest_hash != *manifest_hash {
            return Err(ceremony(format!(
                "trustee {} disqualified: round 1 manifest_hash mismatch",
                r.i
            )));
        }
        if !verify_coefficients(&r.commitments, &r.proofs, k, manifest_hash, r.i) {
            return Err(ceremony(format!(
                "trustee {} disqualified: invalid round 1 commitments or proofs",
                r.i
            )));
        }
    }
    let round1_values: Vec<Value> = round1.iter().map(|(_, v)| v.clone()).collect();
    let all: Vec<Vec<RistrettoPoint>> = round1.iter().map(|(r, _)| r.commitments.clone()).collect();

    // 2. Round 2: exactly one record per trustee, shares to every other trustee in order.
    let mut round2 = Vec::with_capacity(published.round2.len());
    for v in &published.round2 {
        let r = Round2::from_signed(v, set)?;
        round2.push((r.i, (r, v.clone())));
    }
    let round2 = in_index_order(round2, n)?;
    for (r, _) in &round2 {
        if r.manifest_hash != *manifest_hash {
            return Err(ceremony(format!(
                "trustee {} disqualified: round 2 manifest_hash mismatch",
                r.i
            )));
        }
        let expected = (1..=n).filter(|&j| j != r.i);
        if !r.shares.iter().map(|s| s.recipient).eq(expected) {
            return Err(ceremony(format!(
                "trustee {} disqualified: round 2 shares are not one per other trustee in order",
                r.i
            )));
        }
    }
    let round2_values: Vec<Value> = round2.iter().map(|(_, v)| v.clone()).collect();

    // 3. Complaints: each must be answered by a valid reveal from the accused.
    for v in &published.complaints {
        let c = Complaint::from_signed(v, set)?;
        if c.manifest_hash != *manifest_hash {
            return Err(ceremony(format!(
                "complaint by trustee {} has a manifest_hash mismatch",
                c.j
            )));
        }
        if c.i == c.j {
            return Err(schema(format!("trustee {} complains about itself", c.j)));
        }
        let accused = round1
            .iter()
            .find(|(r, _)| r.i == c.i)
            .ok_or_else(|| schema(format!("unknown trustee index {}", c.i)))?;
        let commitments_i = &accused.0.commitments;
        let revealed = published.reveals.iter().find_map(|v| {
            let r = Reveal::from_signed(v, set).ok()?;
            (r.i == c.i && r.j == c.j && r.manifest_hash == *manifest_hash).then_some(r)
        });
        let valid = revealed.is_some_and(|r| verify_share(commitments_i, c.j, &r.share));
        if !valid {
            return Err(ceremony(format!(
                "trustee {} disqualified: invalid or missing reveal for complaint by {}",
                c.i, c.j
            )));
        }
    }

    // 4. Round 3: one acceptance per trustee, all over the same transcript.
    let transcript = transcript_hash(manifest_hash, &round1_values, &round2_values);
    let mut round3 = Vec::with_capacity(published.round3.len());
    for v in &published.round3 {
        let r = Round3::from_signed(v, set)?;
        round3.push((r.j, r));
    }
    for r in in_index_order(round3, n)? {
        if r.manifest_hash != *manifest_hash {
            return Err(ceremony(format!(
                "trustee {} disqualified: round 3 manifest_hash mismatch",
                r.j
            )));
        }
        if r.transcript_hash != transcript {
            return Err(ceremony(format!(
                "trustee {} disqualified: transcript_hash mismatch",
                r.j
            )));
        }
    }

    // 5. Joint key K and verification keys Z_j.
    let key =
        joint_public_key(&all).ok_or_else(|| ceremony("joint public key K is the identity"))?;
    let z = (1..=n).map(|j| verification_key(&all, j)).collect();
    Ok(Context {
        manifest_hash: *manifest_hash,
        transcript_hash: transcript,
        k: key,
        z,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::{dlog_bounded, Ciphertext};
    use crate::group::{lagrange, random_scalar, B};
    use crate::share_enc::hpke_keygen;
    use curve25519_dalek::traits::Identity;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    const M: [u8; 32] = [7u8; 32];

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([23u8; 32])
    }

    /// Per-trustee secrets (index j at position j-1) and the public trustee set.
    struct Setup {
        sign: Vec<SigningKey>,
        hpke: Vec<HpkeSecretKey>,
        polys: Vec<Polynomial>,
        set: TrusteeSet,
    }

    fn setup(rng: &mut ChaCha20Rng, n: u64, k: usize) -> Setup {
        let mut sign = Vec::new();
        let mut hpke = Vec::new();
        let mut polys = Vec::new();
        let mut trustees = Vec::new();
        for i in 1..=n {
            let sk = SigningKey::generate(rng);
            let (hsk, hpk) = hpke_keygen(rng);
            trustees.push(TrusteeInfo {
                index: i,
                name: format!("T{i}"),
                sig_key: sk.verifying_key(),
                hpke_key: hpk,
                bloc: "test".into(),
            });
            sign.push(sk);
            hpke.push(hsk);
            polys.push(Polynomial::random(rng, k));
        }
        Setup {
            sign,
            hpke,
            polys,
            set: TrusteeSet {
                k: k as u64,
                trustees,
            },
        }
    }

    /// Signed round-1 and round-2 structs of an honest ceremony, in index order.
    fn honest_rounds(rng: &mut ChaCha20Rng, s: &Setup) -> (Vec<Round1>, Vec<Round2>) {
        let n = s.set.n();
        let mut r1 = Vec::new();
        for i in 1..=n {
            r1.push(Round1::new(rng, &M, i, &s.polys[(i - 1) as usize]));
        }
        let mut r2 = Vec::new();
        for i in 1..=n {
            r2.push(Round2::new(rng, &M, i, &s.polys[(i - 1) as usize], &s.set));
        }
        (r1, r2)
    }

    /// Runs process_shares for every trustee, expecting every one to accept.
    fn accept_all(s: &Setup, r1: &[Round1], r2: &[Round2]) -> Vec<Scalar> {
        (1..=s.set.n())
            .map(|j| {
                let p = &s.polys[(j - 1) as usize];
                let hsk = &s.hpke[(j - 1) as usize];
                match process_shares(&M, j, p, hsk, r1, r2) {
                    ShareOutcome::Accept { z_j } => z_j,
                    other => panic!("trustee {j} complained: {other:?}"),
                }
            })
            .collect()
    }

    /// Publishes the given rounds with round 3 signed by every trustee over the
    /// honest transcript of `r1` and `r2`.
    fn publish(
        s: &Setup,
        r1: &[Round1],
        r2: &[Round2],
        complaints: Vec<Value>,
        reveals: Vec<Value>,
    ) -> Published {
        let round1: Vec<Value> = r1
            .iter()
            .map(|r| r.sign(&s.sign[(r.i - 1) as usize]))
            .collect();
        let round2: Vec<Value> = r2
            .iter()
            .map(|r| r.sign(&s.sign[(r.i - 1) as usize]))
            .collect();
        let th = transcript_hash(&M, &round1, &round2);
        let round3 = (1..=s.set.n())
            .map(|j| {
                Round3 {
                    manifest_hash: M,
                    j,
                    transcript_hash: th,
                }
                .sign(&s.sign[(j - 1) as usize])
            })
            .collect();
        Published {
            round1,
            round2,
            round3,
            complaints,
            reveals,
        }
    }

    fn expect_ceremony_error(r: Result<Context, Error>) -> String {
        match r {
            Err(Error::Ceremony(msg)) => msg,
            other => panic!("expected a ceremony error, got {other:?}"),
        }
    }

    #[test]
    fn trustee_set_round_trip() {
        let s = setup(&mut rng(), 3, 2);
        let v = s.set.to_value();
        assert_eq!(TrusteeSet::from_value(&v).unwrap(), s.set);
        assert_eq!(s.set.get(2).unwrap().name, "T2");
        assert!(s.set.get(0).is_none());
        assert!(s.set.get(4).is_none());
    }

    #[test]
    fn trustee_set_rejects_bad_threshold_and_order() {
        let s = setup(&mut rng(), 3, 2);

        let mut k1 = s.set.clone();
        k1.k = 1;
        assert!(TrusteeSet::from_value(&k1.to_value()).is_err());

        let mut big_k = s.set.clone();
        big_k.k = 4;
        assert!(TrusteeSet::from_value(&big_k.to_value()).is_err());

        let mut unordered = s.set.clone();
        unordered.trustees.swap(0, 1);
        assert!(TrusteeSet::from_value(&unordered.to_value()).is_err());
    }

    fn check_honest(n: u64, k: usize) {
        let mut rng = rng();
        let s = setup(&mut rng, n, k);
        let (r1, r2) = honest_rounds(&mut rng, &s);
        let zs = accept_all(&s, &r1, &r2);
        let published = publish(&s, &r1, &r2, vec![], vec![]);

        let ctx = verify_ceremony(&M, &s.set, &published).expect("honest ceremony verifies");
        let secret: Scalar = s.polys.iter().map(|p| p.eval(0)).sum();
        assert_eq!(ctx.k, secret * B);
        for j in 1..=n {
            assert_eq!(ctx.z[(j - 1) as usize], zs[(j - 1) as usize] * B);
        }

        let v = ctx.to_value();
        let decoded = Context::from_value(&v).unwrap();
        assert_eq!(decoded, ctx);
        assert_eq!(ctx.hash(), digest("eg/v1/context", &[v]));
        assert_eq!(ctx.hash(), decoded.hash());
    }

    #[test]
    fn honest_ceremony_n3_k2() {
        check_honest(3, 2);
    }

    #[test]
    fn honest_ceremony_n5_k3() {
        check_honest(5, 3);
    }

    #[test]
    fn context_decrypts() {
        let mut rng = rng();
        let s = setup(&mut rng, 5, 3);
        let (r1, r2) = honest_rounds(&mut rng, &s);
        let zs = accept_all(&s, &r1, &r2);
        let ctx = verify_ceremony(&M, &s.set, &publish(&s, &r1, &r2, vec![], vec![])).unwrap();

        let r = random_scalar(&mut rng);
        let ct = Ciphertext::encrypt(1, &r, &ctx.k).unwrap();
        let set = [1u64, 2, 3];
        let m = set.iter().fold(RistrettoPoint::identity(), |acc, &j| {
            acc + lagrange(&set, j).unwrap() * (zs[(j - 1) as usize] * ct.alpha)
        });
        assert_eq!(dlog_bounded(&(ct.beta - m), 1), Some(1));
    }

    #[test]
    fn round_records_round_trip() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let (r1, r2) = honest_rounds(&mut rng, &s);

        for r in &r1 {
            let v = r.sign(&s.sign[(r.i - 1) as usize]);
            assert_eq!(Round1::from_signed(&v, &s.set).unwrap(), *r);
        }
        for r in &r2 {
            let v = r.sign(&s.sign[(r.i - 1) as usize]);
            assert_eq!(Round2::from_signed(&v, &s.set).unwrap(), *r);
        }

        let r3 = Round3 {
            manifest_hash: M,
            j: 2,
            transcript_hash: [9u8; 32],
        };
        let v = r3.sign(&s.sign[1]);
        assert_eq!(Round3::from_signed(&v, &s.set).unwrap(), r3);

        let c = Complaint {
            manifest_hash: M,
            j: 2,
            i: 3,
        };
        let v = c.sign(&s.sign[1]);
        assert_eq!(Complaint::from_signed(&v, &s.set).unwrap(), c);

        let rv = Reveal {
            manifest_hash: M,
            i: 3,
            j: 2,
            share: s.polys[2].eval(2),
        };
        let v = rv.sign(&s.sign[2]);
        assert_eq!(Reveal::from_signed(&v, &s.set).unwrap(), rv);
    }

    #[test]
    fn forged_signature_rejected() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let r = Round1::new(&mut rng, &M, 1, &s.polys[0]);
        let forged = r.sign(&s.sign[1]);
        assert_eq!(
            Round1::from_signed(&forged, &s.set),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn wrong_version_rejected() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let r = Round1::new(&mut rng, &M, 1, &s.polys[0]);
        let fields = vec![
            (Value::Uint(0), Value::from("dkg_round1")),
            (Value::Uint(1), Value::Uint(2)),
            (Value::Uint(2), Value::from(M)),
            (Value::Uint(3), Value::Uint(1)),
            (
                Value::Uint(4),
                Value::Array(r.commitments.iter().map(point_to_value).collect()),
            ),
            (
                Value::Uint(5),
                Value::Array(r.proofs.iter().map(SchnorrProof::to_value).collect()),
            ),
        ];
        let v = sign_record(&s.sign[0], SIG_DKG1, fields, 6);
        assert!(Round1::from_signed(&v, &s.set).is_err());
    }

    #[test]
    fn bad_share_complaint_resolved() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let (r1, mut r2) = honest_rounds(&mut rng, &s);

        // Trustee 1 sends trustee 2 a share for P_1(2) + 1.
        let bad = encrypt_share(
            &mut rng,
            &s.set.trustees[1].hpke_key,
            &M,
            1,
            2,
            &(s.polys[0].eval(2) + Scalar::ONE),
        );
        let idx = r2[0].shares.iter().position(|e| e.recipient == 2).unwrap();
        r2[0].shares[idx] = bad;

        match process_shares(&M, 2, &s.polys[1], &s.hpke[1], &r1, &r2) {
            ShareOutcome::Complain { accused } => assert_eq!(accused, vec![1]),
            other => panic!("expected a complaint, got {other:?}"),
        }

        let complaint = Complaint {
            manifest_hash: M,
            j: 2,
            i: 1,
        }
        .sign(&s.sign[1]);
        let reveal = Reveal {
            manifest_hash: M,
            i: 1,
            j: 2,
            share: s.polys[0].eval(2),
        }
        .sign(&s.sign[0]);
        let published = publish(&s, &r1, &r2, vec![complaint], vec![reveal]);
        verify_ceremony(&M, &s.set, &published).expect("resolved complaint verifies");
    }

    #[test]
    fn bad_share_complaint_unresolved() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let (r1, mut r2) = honest_rounds(&mut rng, &s);
        let bad = encrypt_share(
            &mut rng,
            &s.set.trustees[1].hpke_key,
            &M,
            1,
            2,
            &(s.polys[0].eval(2) + Scalar::ONE),
        );
        let idx = r2[0].shares.iter().position(|e| e.recipient == 2).unwrap();
        r2[0].shares[idx] = bad;
        let complaint = Complaint {
            manifest_hash: M,
            j: 2,
            i: 1,
        }
        .sign(&s.sign[1]);

        // Reveal of a wrong share.
        let wrong = Reveal {
            manifest_hash: M,
            i: 1,
            j: 2,
            share: s.polys[0].eval(2) + Scalar::ONE,
        }
        .sign(&s.sign[0]);
        let published = publish(&s, &r1, &r2, vec![complaint.clone()], vec![wrong]);
        let msg = expect_ceremony_error(verify_ceremony(&M, &s.set, &published));
        assert!(msg.contains("trustee 1"), "{msg}");

        // No reveal at all.
        let published = publish(&s, &r1, &r2, vec![complaint], vec![]);
        let msg = expect_ceremony_error(verify_ceremony(&M, &s.set, &published));
        assert!(msg.contains("trustee 1"), "{msg}");
    }

    #[test]
    fn transcript_mismatch_rejected() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let (r1, r2) = honest_rounds(&mut rng, &s);
        let mut published = publish(&s, &r1, &r2, vec![], vec![]);
        published.round3[1] = Round3 {
            manifest_hash: M,
            j: 2,
            transcript_hash: [0u8; 32],
        }
        .sign(&s.sign[1]);
        assert!(verify_ceremony(&M, &s.set, &published).is_err());
    }

    #[test]
    fn missing_round1_rejected() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let (r1, r2) = honest_rounds(&mut rng, &s);
        let mut published = publish(&s, &r1, &r2, vec![], vec![]);
        published.round1.remove(1);
        let msg = expect_ceremony_error(verify_ceremony(&M, &s.set, &published));
        assert!(msg.contains("trustee 2"), "{msg}");
    }

    #[test]
    fn duplicate_round1_rejected() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let (r1, r2) = honest_rounds(&mut rng, &s);
        let mut published = publish(&s, &r1, &r2, vec![], vec![]);
        published.round1[2] = published.round1[0].clone();
        assert!(verify_ceremony(&M, &s.set, &published).is_err());
    }

    #[test]
    fn round2_wrong_recipients_rejected() {
        let mut rng = rng();
        let s = setup(&mut rng, 3, 2);
        let (r1, mut r2) = honest_rounds(&mut rng, &s);
        r2[0].shares.remove(0);
        let published = publish(&s, &r1, &r2, vec![], vec![]);
        assert!(verify_ceremony(&M, &s.set, &published).is_err());
    }
}
