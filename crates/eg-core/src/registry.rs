//! Machine registry (SPEC.md §7.6, §7.7).
//!
//! The registry says which machines serve which sections and contests, and
//! lists the poll worker keys of each section and the observer keys. The EA
//! signs it. Validation checks the registry rules of §7.7 against the manifest.

use std::collections::{HashMap, HashSet};

use crate::cbor::{self, Value};
use crate::error::Error;
use crate::manifest::{bytes32, decode_list, expect_version, record, uint_item, Manifest};
use crate::sign::{
    sign, signature_from_value, signature_to_value, verify, verifying_key_from_value,
    verifying_key_to_value, SigningKey, VerifyingKey,
};

/// Signature domain tag of the registry (SPEC.md §7.7).
const SIG_REGISTRY: &str = "eg/v1/sig/registry";

/// Error for a violated registry rule. The text is prefixed with `registry: `.
fn reg_err(msg: impl Into<String>) -> Error {
    Error::Manifest(format!("registry: {}", msg.into()))
}

/// The machine registry (`registry`, §7.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    /// Field 2: hash of the manifest this registry belongs to.
    pub manifest_hash: [u8; 32],
    /// Field 3: registry_version, starts at 1 and increases by 1.
    pub version: u64,
    /// Field 4: machines, at least one.
    pub machines: Vec<MachineEntry>,
    /// Field 5: sections, at least one.
    pub sections: Vec<SectionEntry>,
    /// Field 6: observers, possibly empty.
    pub observers: Vec<ObserverEntry>,
}

/// One machine (`machine`, §7.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineEntry {
    /// Field 1: machine identifier, unique within the registry.
    pub machine_id: String,
    /// Field 2: section served, or "" for a reserve machine (§7.7).
    pub section_id: String,
    /// Field 3: machine signing key.
    pub key: VerifyingKey,
    /// Field 4: contest indices offered by this machine, strictly ascending.
    pub contests: Vec<u64>,
}

/// One polling section (`section`, §7.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionEntry {
    /// Field 1: section identifier, unique and non-empty.
    pub section_id: String,
    /// Field 2: eligible voters on the roll.
    pub eligible: u64,
    /// Field 3: poll worker (mesário) keys of this section, at least one.
    pub poll_worker_keys: Vec<VerifyingKey>,
    /// Field 4: maximum sessions per machine of this section (at least 1).
    pub max_sessions: u64,
    /// Field 5: region, used for regional mixing (§19.1).
    pub region: String,
}

/// One observer (`observer`, §7.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverEntry {
    /// Field 1: organisation the observer represents.
    pub organisation: String,
    /// Field 2: observer (fiscal) key.
    pub key: VerifyingKey,
}

impl MachineEntry {
    fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("machine")),
            (1, Value::from(self.machine_id.as_str())),
            (2, Value::from(self.section_id.as_str())),
            (3, verifying_key_to_value(&self.key)),
            (
                4,
                Value::Array(self.contests.iter().map(|c| Value::Uint(*c)).collect()),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields(v, "machine", 5)?;
        Ok(MachineEntry {
            machine_id: f[1].as_text()?.to_owned(),
            section_id: f[2].as_text()?.to_owned(),
            key: verifying_key_from_value(f[3])?,
            contests: decode_list(f[4], 1, "machine contests", uint_item)?,
        })
    }
}

impl SectionEntry {
    fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("section")),
            (1, Value::from(self.section_id.as_str())),
            (2, Value::Uint(self.eligible)),
            (
                3,
                Value::Array(
                    self.poll_worker_keys
                        .iter()
                        .map(verifying_key_to_value)
                        .collect(),
                ),
            ),
            (4, Value::Uint(self.max_sessions)),
            (5, Value::from(self.region.as_str())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields(v, "section", 6)?;
        Ok(SectionEntry {
            section_id: f[1].as_text()?.to_owned(),
            eligible: f[2].as_uint()?,
            poll_worker_keys: decode_list(f[3], 1, "poll worker keys", verifying_key_from_value)?,
            max_sessions: f[4].as_uint()?,
            region: f[5].as_text()?.to_owned(),
        })
    }
}

impl ObserverEntry {
    fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("observer")),
            (1, Value::from(self.organisation.as_str())),
            (2, verifying_key_to_value(&self.key)),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = cbor::record_fields(v, "observer", 3)?;
        Ok(ObserverEntry {
            organisation: f[1].as_text()?.to_owned(),
            key: verifying_key_from_value(f[2])?,
        })
    }
}

impl Registry {
    /// Encodes the registry as the CBOR map of §7.7.
    pub fn to_value(&self) -> Value {
        record(vec![
            (0, Value::from("registry")),
            (1, Value::Uint(1)),
            (2, Value::from(self.manifest_hash)),
            (3, Value::Uint(self.version)),
            (
                4,
                Value::Array(self.machines.iter().map(MachineEntry::to_value).collect()),
            ),
            (
                5,
                Value::Array(self.sections.iter().map(SectionEntry::to_value).collect()),
            ),
            (
                6,
                Value::Array(self.observers.iter().map(ObserverEntry::to_value).collect()),
            ),
        ])
    }

    /// Strict decode of a `registry` record (§7.7). Well-formedness against a
    /// manifest is checked by [`Registry::validate`].
    pub fn from_value(v: &Value) -> Result<Registry, Error> {
        let f = cbor::record_fields(v, "registry", 7)?;
        expect_version(f[1])?;
        Ok(Registry {
            manifest_hash: bytes32(f[2])?,
            version: f[3].as_uint()?,
            machines: decode_list(f[4], 1, "machines", MachineEntry::from_value)?,
            sections: decode_list(f[5], 1, "sections", SectionEntry::from_value)?,
            observers: decode_list(f[6], 0, "observers", ObserverEntry::from_value)?,
        })
    }

    /// Checks the registry rules of §7.7 against `manifest`:
    /// - `manifest_hash` is the hash of the manifest, and `registry_version` ≥ 1;
    /// - machine identifiers are unique, and section identifiers are unique and non-empty;
    /// - every machine's section exists, or is "" (a reserve machine);
    /// - each machine's contests are strictly ascending, exist in the manifest,
    ///   and include all or none of each link group;
    /// - every section has at least one non-reserve machine;
    /// - `max_sessions` ≥ 1;
    /// - machine keys, poll worker keys and observer keys are pairwise disjoint,
    ///   and no key appears twice.
    pub fn validate(&self, manifest: &Manifest) -> Result<(), Error> {
        if self.manifest_hash != manifest.hash() {
            return Err(reg_err("manifest_hash does not match the manifest"));
        }
        if self.version < 1 {
            return Err(reg_err("registry_version must be at least 1"));
        }

        let mut machine_ids = HashSet::new();
        for m in &self.machines {
            if !machine_ids.insert(m.machine_id.as_str()) {
                return Err(reg_err(format!("duplicate machine id {:?}", m.machine_id)));
            }
        }

        let mut section_ids = HashSet::new();
        for s in &self.sections {
            if s.section_id.is_empty() {
                return Err(reg_err(
                    "section id must not be empty (\"\" is the reserve marker)",
                ));
            }
            if !section_ids.insert(s.section_id.as_str()) {
                return Err(reg_err(format!("duplicate section id {:?}", s.section_id)));
            }
            if s.max_sessions < 1 {
                return Err(reg_err(format!(
                    "section {:?}: max_sessions must be at least 1",
                    s.section_id
                )));
            }
        }

        for m in &self.machines {
            if !m.section_id.is_empty() && !section_ids.contains(m.section_id.as_str()) {
                return Err(reg_err(format!(
                    "machine {:?} names unknown section {:?}",
                    m.machine_id, m.section_id
                )));
            }
            self.check_machine_contests(m, manifest)?;
        }

        for s in &self.sections {
            let has_regular = self.machines.iter().any(|m| m.section_id == s.section_id);
            if !has_regular {
                return Err(reg_err(format!(
                    "section {:?} has no regular machine (only reserve machines serve it)",
                    s.section_id
                )));
            }
        }

        check_keys_disjoint(self)
    }

    /// Contest offers of one machine: non-empty, strictly ascending, existing,
    /// and all-or-none of each link group.
    fn check_machine_contests(&self, m: &MachineEntry, manifest: &Manifest) -> Result<(), Error> {
        if m.contests.is_empty() {
            return Err(reg_err(format!(
                "machine {:?} offers no contests",
                m.machine_id
            )));
        }
        if !m.contests.windows(2).all(|w| w[0] < w[1]) {
            return Err(reg_err(format!(
                "machine {:?}: contest indices must be strictly ascending",
                m.machine_id
            )));
        }
        for &c in &m.contests {
            if manifest.contest(c).is_none() {
                return Err(reg_err(format!(
                    "machine {:?} offers unknown contest {c}",
                    m.machine_id
                )));
            }
        }
        for g in &manifest.link_groups {
            let offered = g.contests.iter().filter(|c| m.contests.contains(c)).count();
            if offered != 0 && offered != g.contests.len() {
                return Err(reg_err(format!(
                    "machine {:?} offers {offered} of the {} contests of link group {}; a machine offers all or none",
                    m.machine_id,
                    g.contests.len(),
                    g.index
                )));
            }
        }
        Ok(())
    }

    /// The machine with identifier `id`, if any.
    pub fn machine(&self, id: &str) -> Option<&MachineEntry> {
        self.machines.iter().find(|m| m.machine_id == id)
    }

    /// The section with identifier `id`, if any.
    pub fn section(&self, id: &str) -> Option<&SectionEntry> {
        self.sections.iter().find(|s| s.section_id == id)
    }
}

/// Machine, poll worker and observer keys are pairwise disjoint and each is
/// used once (§7.7).
fn check_keys_disjoint(r: &Registry) -> Result<(), Error> {
    let mut owners: HashMap<[u8; 32], String> = HashMap::new();
    let mut claim = |key: &VerifyingKey, owner: String| -> Result<(), Error> {
        if let Some(prev) = owners.insert(key.to_bytes(), owner.clone()) {
            return Err(reg_err(format!("key of {owner} is already used by {prev}")));
        }
        Ok(())
    };
    for m in &r.machines {
        claim(&m.key, format!("machine {:?}", m.machine_id))?;
    }
    for s in &r.sections {
        for k in &s.poll_worker_keys {
            claim(k, format!("a poll worker of section {:?}", s.section_id))?;
        }
    }
    for o in &r.observers {
        claim(&o.key, format!("observer {:?}", o.organisation))?;
    }
    Ok(())
}

/// Signs a registry with the EA key (SPEC.md §7.7):
/// `{ 0: "signed_registry", 1: registry, 2: Sign(ea_sk, "eg/v1/sig/registry", registry) }`.
pub fn sign_registry(r: &Registry, ea_sk: &SigningKey) -> Value {
    let body = r.to_value();
    let sig = sign(ea_sk, SIG_REGISTRY, &body);
    record(vec![
        (0, Value::from("signed_registry")),
        (1, body),
        (2, signature_to_value(&sig)),
    ])
}

/// Decodes a `signed_registry`, verifies it with the EA key of `manifest`, and
/// validates it against `manifest` (SPEC.md §7.7).
pub fn open_signed_registry(v: &Value, manifest: &Manifest) -> Result<Registry, Error> {
    let f = cbor::record_fields(v, "signed_registry", 3)?;
    let registry = Registry::from_value(f[1])?;
    let sig = signature_from_value(f[2])?;
    if !verify(&manifest.ea_key, SIG_REGISTRY, f[1], &sig) {
        return Err(Error::InvalidSignature);
    }
    registry.validate(manifest)?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{sample_manifest, sample_registry, Keys};
    use crate::sign::SigningKey;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup() -> (Manifest, Keys, Registry) {
        let (m, keys) = sample_manifest(1);
        let r = sample_registry(&m, &keys);
        (m, keys, r)
    }

    /// Asserts that `r` is rejected with a registry error containing `needle`.
    fn assert_reg_err(r: &Registry, m: &Manifest, needle: &str) {
        match r.validate(m) {
            Err(Error::Manifest(msg)) => {
                assert!(msg.starts_with("registry: "), "{msg}");
                assert!(msg.contains(needle), "expected {needle:?} in: {msg}");
            }
            other => panic!("expected registry error containing {needle:?}, got {other:?}"),
        }
    }

    #[test]
    fn sample_validates() {
        let (m, _, r) = setup();
        r.validate(&m).unwrap();
        assert_eq!(r.machine("M-S1-01").unwrap().section_id, "S1");
        assert_eq!(r.section("S2").unwrap().region, "RJ");
        assert!(r.machine("nope").is_none());
        assert!(r.section("S9").is_none());
    }

    #[test]
    fn round_trip() {
        let (_, _, r) = setup();
        let v = r.to_value();
        assert_eq!(Registry::from_value(&v).unwrap(), r);
        let bytes = cbor::encode(&v);
        assert_eq!(cbor::encode(&cbor::decode(&bytes).unwrap()), bytes);
    }

    #[test]
    fn strict_decode_rejects_wrong_version_and_unknown_key() {
        let (_, _, r) = setup();
        let mut v = r.to_value();
        if let Value::Map(entries) = &mut v {
            for (k, val) in entries.iter_mut() {
                if *k == Value::Uint(1) {
                    *val = Value::Uint(2);
                }
            }
        }
        assert!(Registry::from_value(&v).is_err());

        let mut v = r.to_value();
        if let Value::Map(entries) = &mut v {
            entries.push((Value::Uint(7), Value::Uint(0)));
        }
        assert!(Registry::from_value(&v).is_err());
    }

    #[test]
    fn signed_registry_opens() {
        let (m, keys, r) = setup();
        let signed = sign_registry(&r, &keys.ea);
        assert_eq!(open_signed_registry(&signed, &m).unwrap(), r);
    }

    #[test]
    fn signed_registry_with_wrong_key_fails() {
        let (m, _, r) = setup();
        let other = SigningKey::generate(&mut ChaCha20Rng::seed_from_u64(5));
        let signed = sign_registry(&r, &other);
        assert_eq!(
            open_signed_registry(&signed, &m),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn tampered_signed_registry_fails() {
        let (m, keys, r) = setup();
        let mut signed = sign_registry(&r, &keys.ea);
        let mut tampered = r.clone();
        tampered.version = 2;
        if let Value::Map(entries) = &mut signed {
            for (k, val) in entries.iter_mut() {
                if *k == Value::Uint(1) {
                    *val = tampered.to_value();
                }
            }
        }
        assert_eq!(
            open_signed_registry(&signed, &m),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn unknown_section_is_rejected() {
        let (m, _, mut r) = setup();
        r.machines[0].section_id = "S9".to_owned();
        assert_reg_err(&r, &m, "unknown section");
    }

    #[test]
    fn duplicate_machine_id_is_rejected() {
        let (m, _, mut r) = setup();
        r.machines[1].machine_id = r.machines[0].machine_id.clone();
        assert_reg_err(&r, &m, "duplicate machine id");
    }

    #[test]
    fn partial_link_group_offer_is_rejected() {
        // Link group 0 is contests 4 and 5. Offering 4 without 5 is not allowed.
        let (m, _, mut r) = setup();
        r.machines[0].contests = vec![0, 1, 2, 3, 4];
        assert_reg_err(&r, &m, "link group 0");
    }

    #[test]
    fn unknown_or_unsorted_contest_is_rejected() {
        let (m, _, mut r) = setup();
        r.machines[0].contests.push(9);
        assert_reg_err(&r, &m, "unknown contest 9");

        let (m, _, mut r) = setup();
        r.machines[0].contests = vec![1, 0, 2, 3, 4, 5];
        assert_reg_err(&r, &m, "ascending");
    }

    #[test]
    fn section_without_regular_machine_is_rejected() {
        let (m, _, mut r) = setup();
        // S2's only machine becomes a reserve machine.
        r.machines[1].section_id = String::new();
        assert_reg_err(&r, &m, "section \"S2\" has no regular machine");
    }

    #[test]
    fn reserve_machine_is_allowed() {
        let (m, _, r) = setup();
        assert!(r.machines.iter().any(|x| x.section_id.is_empty()));
        r.validate(&m).unwrap();
    }

    #[test]
    fn key_reused_across_roles_is_rejected() {
        // Observer key equal to a machine key.
        let (m, _, mut r) = setup();
        r.observers[0].key = r.machines[0].key;
        assert_reg_err(&r, &m, "already used");

        // Poll worker key equal to an observer key.
        let (m, _, mut r) = setup();
        r.sections[0].poll_worker_keys[0] = r.observers[1].key;
        assert_reg_err(&r, &m, "already used");

        // Same key twice within the poll workers of one section.
        let (m, _, mut r) = setup();
        r.sections[0].poll_worker_keys[1] = r.sections[0].poll_worker_keys[0];
        assert_reg_err(&r, &m, "already used");
    }

    #[test]
    fn manifest_hash_mismatch_is_rejected() {
        let (m, _, mut r) = setup();
        r.manifest_hash[0] ^= 1;
        assert_reg_err(&r, &m, "manifest_hash");
    }

    #[test]
    fn zero_registry_version_is_rejected() {
        let (m, _, mut r) = setup();
        r.version = 0;
        assert_reg_err(&r, &m, "registry_version");
    }

    #[test]
    fn zero_max_sessions_is_rejected() {
        let (m, _, mut r) = setup();
        r.sections[1].max_sessions = 0;
        assert_reg_err(&r, &m, "max_sessions");
    }

    #[test]
    fn duplicate_section_id_is_rejected() {
        let (m, _, mut r) = setup();
        r.sections[1].section_id = "S1".to_owned();
        assert_reg_err(&r, &m, "duplicate section id");
    }
}
