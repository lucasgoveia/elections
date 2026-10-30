//! Deterministic sample election for tests and downstream modules.
//!
//! Compiled only for tests and with the `fixtures` feature. Every key is drawn
//! from a ChaCha20 stream seeded with the caller's seed, so the same seed gives
//! the same election, hashes and signatures.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::ceremony::{TrusteeInfo, TrusteeSet};
use crate::manifest::{
    ApportionmentRule, BallotOption, Contest, ContestKind, LinkGroup, Manifest, Method, Mirror,
    MixPolicy, OptionKind, Party, ReleaseSigner, SoftwarePolicy,
};
use crate::registry::{MachineEntry, ObserverEntry, Registry, SectionEntry};
use crate::share_enc::{hpke_keygen, HpkeSecretKey};
use crate::sign::SigningKey;

/// Number of trustees in the sample.
const N_TRUSTEES: usize = 3;
/// Machines: one per section plus one reserve.
const N_MACHINES: usize = 3;
/// Planets (sections and machines) of the Star Wars scenario.
const N_PLANETS: usize = 10;
/// Poll workers: two per section.
const N_POLL_WORKERS: usize = 4;
/// Observers.
const N_OBSERVERS: usize = 2;
/// Release signers.
const N_RELEASE_SIGNERS: usize = 3;
/// Mirrors.
const N_MIRRORS: usize = 2;

/// Secret keys of the sample election. Public keys are in the manifest and registry.
pub struct Keys {
    pub ea: SigningKey,
    pub board: SigningKey,
    /// Trustee signing keys, index i at position i-1.
    pub trustee_sig: Vec<SigningKey>,
    /// Trustee HPKE secret keys, index i at position i-1.
    pub trustee_hpke: Vec<HpkeSecretKey>,
    /// Machine keys: sections S1 and S2 use 0 and 1, the reserve machine uses 2.
    pub machines: Vec<SigningKey>,
    /// Poll worker keys: S1 uses 0 and 1, S2 uses 2 and 3.
    pub poll_workers: Vec<SigningKey>,
    pub observers: Vec<SigningKey>,
    pub release_signers: Vec<SigningKey>,
    pub release_log: SigningKey,
    pub mirrors: Vec<SigningKey>,
}

fn sk(rng: &mut ChaCha20Rng) -> SigningKey {
    SigningKey::generate(rng)
}

fn option(index: usize, name: &str, kind: OptionKind, number: Option<&str>) -> BallotOption {
    BallotOption {
        index: index as u64,
        name: name.to_owned(),
        kind,
        number: number.map(str::to_owned),
        party_index: None,
        tiebreak_rank: None,
    }
}

/// Options of a single-seat contest: candidates, then blank and null.
fn single_options(candidates: &[(&str, &str)]) -> Vec<BallotOption> {
    let mut opts: Vec<BallotOption> = candidates
        .iter()
        .enumerate()
        .map(|(i, &(name, num))| option(i, name, OptionKind::Candidate, Some(num)))
        .collect();
    let n = opts.len();
    opts.push(option(n, "Branco", OptionKind::Blank, None));
    opts.push(option(n + 1, "Nulo", OptionKind::Null, None));
    opts
}

fn contest(
    index: u64,
    name: &str,
    kind: ContestKind,
    method: Method,
    limit: u64,
    options: Vec<BallotOption>,
) -> Contest {
    Contest {
        index,
        name: name.to_owned(),
        kind,
        method,
        limit,
        options,
        apportionment: None,
        seats: None,
        regional_mix: false,
    }
}

/// Builds the sample manifest and all its secret keys from `seed`.
///
/// The election is a small Brazilian-style pilot with three trustees (k = 2)
/// in the blocs "TSE", "OAB" and "university", and six contests: 0 single
/// homomorphic, 1 multi homomorphic (L = 2), 2 proportional (D'Hondt, 3 seats,
/// two parties), 3 single mixnet with regional mixing, and 4 and 5 two single
/// senator contests in link group 0. It has three release signers and two mirrors.
pub fn sample_manifest(seed: u64) -> (Manifest, Keys) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let ea = sk(&mut rng);
    let board = sk(&mut rng);
    let trustee_sig: Vec<SigningKey> = (0..N_TRUSTEES).map(|_| sk(&mut rng)).collect();
    let mut trustee_hpke = Vec::with_capacity(N_TRUSTEES);
    let mut trustee_hpke_public = Vec::with_capacity(N_TRUSTEES);
    for _ in 0..N_TRUSTEES {
        let (secret, public) = hpke_keygen(&mut rng);
        trustee_hpke.push(secret);
        trustee_hpke_public.push(public);
    }
    let machines: Vec<SigningKey> = (0..N_MACHINES).map(|_| sk(&mut rng)).collect();
    let poll_workers: Vec<SigningKey> = (0..N_POLL_WORKERS).map(|_| sk(&mut rng)).collect();
    let observers: Vec<SigningKey> = (0..N_OBSERVERS).map(|_| sk(&mut rng)).collect();
    let release_signers: Vec<SigningKey> = (0..N_RELEASE_SIGNERS).map(|_| sk(&mut rng)).collect();
    let release_log = sk(&mut rng);
    let mirrors: Vec<SigningKey> = (0..N_MIRRORS).map(|_| sk(&mut rng)).collect();

    // Trustees: bloc labels are distinct, so no bloc holds k = 2 shares.
    let blocs = ["TSE", "OAB", "university"];
    let trustees = TrusteeSet {
        k: 2,
        trustees: (0..N_TRUSTEES)
            .map(|i| TrusteeInfo {
                index: i as u64 + 1,
                name: format!("Trustee org {}", i + 1),
                sig_key: trustee_sig[i].verifying_key(),
                hpke_key: trustee_hpke_public[i].clone(),
                bloc: blocs[i].to_owned(),
            })
            .collect(),
    };

    // Contest 2: proportional. Parties P1 (index 0) and P2 (index 1), each with
    // two candidates, a party option, and shared blank and null options.
    let mut prop_options = Vec::new();
    let prop_candidates = [
        ("Dora", "12001", 0u64, 1u64),
        ("Edu", "12002", 0, 2),
        ("Fabi", "45001", 1, 3),
        ("Gil", "45002", 1, 4),
    ];
    for (i, &(name, num, party, rank)) in prop_candidates.iter().enumerate() {
        let mut o = option(i, name, OptionKind::Candidate, Some(num));
        o.party_index = Some(party);
        o.tiebreak_rank = Some(rank);
        prop_options.push(o);
    }
    for (i, (name, num, party)) in [("Partido Azul", "12", 0u64), ("Partido Verde", "45", 1)]
        .into_iter()
        .enumerate()
    {
        let mut o = option(4 + i, name, OptionKind::Party, Some(num));
        o.party_index = Some(party);
        prop_options.push(o);
    }
    prop_options.push(option(6, "Branco", OptionKind::Blank, None));
    prop_options.push(option(7, "Nulo", OptionKind::Null, None));
    let mut deputado = contest(
        2,
        "Deputado Federal",
        ContestKind::Proportional,
        Method::Homomorphic,
        1,
        prop_options,
    );
    deputado.apportionment = Some(ApportionmentRule::Dhondt { threshold_bp: None });
    deputado.seats = Some(3);

    // Contest 1: multi, L = 2, four candidates and null (no blank).
    let mut senado_options: Vec<BallotOption> = [
        ("Hugo", "1001"),
        ("Iara", "1002"),
        ("Joana", "1003"),
        ("Lucio", "1004"),
    ]
    .iter()
    .enumerate()
    .map(|(i, &(name, num))| option(i, name, OptionKind::Candidate, Some(num)))
    .collect();
    senado_options.push(option(4, "Nulo", OptionKind::Null, None));

    // Contests 4 and 5: the two single senator contests, identical option lists.
    let senators = [("Mario", "501"), ("Nina", "502"), ("Otavio", "503")];

    let mut prefeito = contest(
        3,
        "Prefeito",
        ContestKind::Single,
        Method::Mixnet,
        1,
        single_options(&[("Hugo", "10"), ("Iara", "20"), ("Joana", "30")]),
    );
    prefeito.regional_mix = true;

    let contests = vec![
        contest(
            0,
            "Governador",
            ContestKind::Single,
            Method::Homomorphic,
            1,
            single_options(&[("Ana", "12"), ("Bruno", "45"), ("Carla", "13")]),
        ),
        contest(
            1,
            "Senador",
            ContestKind::Multi,
            Method::Homomorphic,
            2,
            senado_options,
        ),
        deputado,
        prefeito,
        contest(
            4,
            "1º Senador",
            ContestKind::Single,
            Method::Homomorphic,
            1,
            single_options(&senators),
        ),
        contest(
            5,
            "2º Senador",
            ContestKind::Single,
            Method::Homomorphic,
            1,
            single_options(&senators),
        ),
    ];

    let parties = vec![
        Party {
            index: 0,
            name: "Partido Azul".to_owned(),
            number: "12".to_owned(),
            key: None,
        },
        Party {
            index: 1,
            name: "Partido Verde".to_owned(),
            number: "45".to_owned(),
            key: None,
        },
    ];

    let software_policy = SoftwarePolicy {
        signers: (0..N_RELEASE_SIGNERS)
            .map(|i| ReleaseSigner {
                key: release_signers[i].verifying_key(),
                organisation: format!("Release signer {}", i + 1),
                bloc: blocs[i].to_owned(),
            })
            .collect(),
        k_r: 2,
        release_log_key: release_log.verifying_key(),
        approved_hashes: vec![[0xaa; 32]],
        attestation_required: false,
    };

    let manifest = Manifest {
        election_id: "BR-2026-SP-PILOT-01".to_owned(),
        title: "Piloto de eleição de amostra".to_owned(),
        contests,
        parties,
        federations: Vec::new(),
        trustees,
        ea_key: ea.verifying_key(),
        board_key: board.verifying_key(),
        software_policy,
        mix_policy: MixPolicy {
            min_mixers: 2,
            min_region_rows: 1,
        },
        link_groups: vec![LinkGroup {
            index: 0,
            contests: vec![4, 5],
        }],
        min_section_ballots: 1,
        ea_bloc: "TSE".to_owned(),
        mirrors: vec![
            Mirror {
                operator: "Mirror org A".to_owned(),
                bloc: "OAB".to_owned(),
                url: "https://mirror-a.example.org".to_owned(),
                key: mirrors[0].verifying_key(),
            },
            Mirror {
                operator: "Mirror org B".to_owned(),
                bloc: "university".to_owned(),
                url: "https://mirror-b.example.org".to_owned(),
                key: mirrors[1].verifying_key(),
            },
        ],
    };

    let keys = Keys {
        ea,
        board,
        trustee_sig,
        trustee_hpke,
        machines,
        poll_workers,
        observers,
        release_signers,
        release_log,
        mirrors,
    };
    (manifest, keys)
}

/// Builds the sample registry for `manifest`, using the keys in `keys`.
///
/// Two sections: "S1" (region "SP") and "S2" (region "RJ"). Each has one
/// machine offering all contests and two poll workers, eligible 100, and
/// max_sessions 2. There is also one reserve machine and two observers.
pub fn sample_registry(manifest: &Manifest, keys: &Keys) -> Registry {
    let all_contests: Vec<u64> = manifest.contests.iter().map(|c| c.index).collect();
    Registry {
        manifest_hash: manifest.hash(),
        version: 1,
        machines: vec![
            MachineEntry {
                machine_id: "M-S1-01".to_owned(),
                section_id: "S1".to_owned(),
                key: keys.machines[0].verifying_key(),
                contests: all_contests.clone(),
            },
            MachineEntry {
                machine_id: "M-S2-01".to_owned(),
                section_id: "S2".to_owned(),
                key: keys.machines[1].verifying_key(),
                contests: all_contests.clone(),
            },
            MachineEntry {
                machine_id: "M-R-01".to_owned(),
                section_id: String::new(),
                key: keys.machines[2].verifying_key(),
                contests: all_contests,
            },
        ],
        sections: vec![
            SectionEntry {
                section_id: "S1".to_owned(),
                eligible: 100,
                poll_worker_keys: keys.poll_workers[0..2]
                    .iter()
                    .map(SigningKey::verifying_key)
                    .collect(),
                max_sessions: 2,
                region: "SP".to_owned(),
            },
            SectionEntry {
                section_id: "S2".to_owned(),
                eligible: 100,
                poll_worker_keys: keys.poll_workers[2..4]
                    .iter()
                    .map(SigningKey::verifying_key)
                    .collect(),
                max_sessions: 2,
                region: "RJ".to_owned(),
            },
        ],
        observers: vec![
            ObserverEntry {
                organisation: "Party Azul observers".to_owned(),
                key: keys.observers[0].verifying_key(),
            },
            ObserverEntry {
                organisation: "Civil society observers".to_owned(),
                key: keys.observers[1].verifying_key(),
            },
        ],
    }
}

/// Planets of the Star Wars scenario: one section, one machine and one contest
/// each. Each planet has four senator candidates.
const PLANETS: [(&str, [&str; 4]); N_PLANETS] = [
    (
        "Tatooine",
        ["Owen Lars", "Beru Lars", "Jabba the Hutt", "Bib Fortuna"],
    ),
    (
        "Naboo",
        ["Padmé Amidala", "Jar Jar Binks", "Sio Bibble", "Boss Nass"],
    ),
    (
        "Coruscant",
        ["Mas Amedda", "Sly Moore", "Orn Free Taa", "Finis Valorum"],
    ),
    (
        "Alderaan",
        [
            "Bail Organa",
            "Leia Organa",
            "Breha Organa",
            "Raymus Antilles",
        ],
    ),
    (
        "Kashyyyk",
        ["Tarfful", "Attichitcuk", "Malla", "Lumpawarrump"],
    ),
    (
        "Corellia",
        ["Han Solo", "Qi'ra", "Garris Shrike", "Wedge Antilles"],
    ),
    (
        "Mon Cala",
        ["Gial Ackbar", "Raddus", "Lee-Char", "Nossor Ri"],
    ),
    ("Kamino", ["Lama Su", "Taun We", "Nala Se", "Ko Sai"]),
    (
        "Endor",
        ["Wicket W. Warrick", "Chief Chirpa", "Logray", "Teebo"],
    ),
    (
        "Mandalore",
        ["Bo-Katan Kryze", "Satine Kryze", "Pre Vizsla", "Din Djarin"],
    ),
];

/// Presidential candidates of the Star Wars scenario, with their display numbers.
const PRESIDENTS: [(&str, &str); 5] = [
    ("Luke Skywalker", "10"),
    ("Palpatine", "66"),
    ("Darth Vader", "77"),
    ("Chewbacca", "22"),
    ("Obi-Wan Kenobi", "11"),
];

/// Builds the Star Wars manifest and its secret keys from `seed`.
///
/// The election is "Galactic Republic General Election". Contest 0 is the
/// President (single, homomorphic). Contests 1 to 10 are one senate race per
/// planet (multi, homomorphic, L = 2), each offered by that planet's machine
/// only. Three trustees (k = 2) sit in the blocs "jedi", "rebellion" and
/// "banking". The EA is in the bloc "senate", and the two mirrors are in
/// "press" and "civil". There are no parties, federations or link groups.
pub fn starwars_manifest(seed: u64) -> (Manifest, Keys) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let ea = sk(&mut rng);
    let board = sk(&mut rng);
    let trustee_sig: Vec<SigningKey> = (0..N_TRUSTEES).map(|_| sk(&mut rng)).collect();
    let mut trustee_hpke = Vec::with_capacity(N_TRUSTEES);
    let mut trustee_hpke_public = Vec::with_capacity(N_TRUSTEES);
    for _ in 0..N_TRUSTEES {
        let (secret, public) = hpke_keygen(&mut rng);
        trustee_hpke.push(secret);
        trustee_hpke_public.push(public);
    }
    let machines: Vec<SigningKey> = (0..N_PLANETS).map(|_| sk(&mut rng)).collect();
    let poll_workers: Vec<SigningKey> = (0..2 * N_PLANETS).map(|_| sk(&mut rng)).collect();
    let observers: Vec<SigningKey> = (0..N_OBSERVERS).map(|_| sk(&mut rng)).collect();
    let release_signers: Vec<SigningKey> = (0..N_RELEASE_SIGNERS).map(|_| sk(&mut rng)).collect();
    let release_log = sk(&mut rng);
    let mirrors: Vec<SigningKey> = (0..N_MIRRORS).map(|_| sk(&mut rng)).collect();

    // Trustees and release signers: one bloc per organisation, so no bloc holds k.
    let trustee_names = [
        "Jedi Council",
        "Rebel Alliance",
        "InterGalactic Banking Clan",
    ];
    let blocs = ["jedi", "rebellion", "banking"];
    let trustees = TrusteeSet {
        k: 2,
        trustees: (0..N_TRUSTEES)
            .map(|i| TrusteeInfo {
                index: i as u64 + 1,
                name: trustee_names[i].to_owned(),
                sig_key: trustee_sig[i].verifying_key(),
                hpke_key: trustee_hpke_public[i].clone(),
                bloc: blocs[i].to_owned(),
            })
            .collect(),
    };

    // Contest 0: the President. Candidates, then Blank and Null (no numbers).
    let mut president_options: Vec<BallotOption> = PRESIDENTS
        .iter()
        .enumerate()
        .map(|(i, &(name, num))| option(i, name, OptionKind::Candidate, Some(num)))
        .collect();
    let n = president_options.len();
    president_options.push(option(n, "Blank", OptionKind::Blank, None));
    president_options.push(option(n + 1, "Null", OptionKind::Null, None));

    let mut contests = vec![contest(
        0,
        "President of the Galactic Republic",
        ContestKind::Single,
        Method::Homomorphic,
        1,
        president_options,
    )];

    // Contests 1 to 10: one senate race per planet. Candidate numbers are 101 to
    // 104 for planet 1, 201 to 204 for planet 2, and so on up to 901 to 904.
    // Planet 10 uses 111 to 114. Each contest has a Null option and no blank.
    for (i, (planet, senators)) in PLANETS.iter().enumerate() {
        let p = i as u64 + 1;
        let base = if p == 10 { 110 } else { 100 * p };
        let mut options = Vec::with_capacity(senators.len() + 1);
        for (c, name) in senators.iter().enumerate() {
            let num = (base + c as u64 + 1).to_string();
            options.push(option(c, name, OptionKind::Candidate, Some(num.as_str())));
        }
        options.push(option(senators.len(), "Null", OptionKind::Null, None));
        contests.push(contest(
            p,
            &format!("Senator \u{2014} {planet}"),
            ContestKind::Multi,
            Method::Homomorphic,
            2,
            options,
        ));
    }

    let software_policy = SoftwarePolicy {
        signers: [
            "Jedi Archives",
            "Rebel Alliance Engineering",
            "Banking Clan Audit",
        ]
        .iter()
        .enumerate()
        .map(|(i, org)| ReleaseSigner {
            key: release_signers[i].verifying_key(),
            organisation: (*org).to_owned(),
            bloc: blocs[i].to_owned(),
        })
        .collect(),
        k_r: 2,
        release_log_key: release_log.verifying_key(),
        approved_hashes: vec![[0xaa; 32]],
        attestation_required: false,
    };

    let manifest = Manifest {
        election_id: "GALACTIC-REPUBLIC-GE-1".to_owned(),
        title: "Galactic Republic General Election".to_owned(),
        contests,
        parties: Vec::new(),
        federations: Vec::new(),
        trustees,
        ea_key: ea.verifying_key(),
        board_key: board.verifying_key(),
        software_policy,
        mix_policy: MixPolicy {
            min_mixers: 2,
            min_region_rows: 1,
        },
        link_groups: Vec::new(),
        min_section_ballots: 1,
        ea_bloc: "senate".to_owned(),
        mirrors: vec![
            Mirror {
                operator: "HoloNet News".to_owned(),
                bloc: "press".to_owned(),
                url: "https://holonet.example.org".to_owned(),
                key: mirrors[0].verifying_key(),
            },
            Mirror {
                operator: "Mos Eisley Cantina Watch".to_owned(),
                bloc: "civil".to_owned(),
                url: "https://cantina-watch.example.org".to_owned(),
                key: mirrors[1].verifying_key(),
            },
        ],
    };

    let keys = Keys {
        ea,
        board,
        trustee_sig,
        trustee_hpke,
        machines,
        poll_workers,
        observers,
        release_signers,
        release_log,
        mirrors,
    };
    (manifest, keys)
}

/// Builds the Star Wars registry for `manifest`, using the keys in `keys`.
///
/// One section per planet, named after the planet, with region equal to the
/// planet name. Each section has two poll workers, eligible 100 and
/// max_sessions 2. Each planet has one machine "M-<Planet>" (spaces removed)
/// offering contests 0 and its own contest. There is no reserve machine, since
/// a reserve machine would need to serve a single section. There are two
/// observers.
pub fn starwars_registry(manifest: &Manifest, keys: &Keys) -> Registry {
    let machines = PLANETS
        .iter()
        .enumerate()
        .map(|(i, (planet, _))| MachineEntry {
            machine_id: format!("M-{}", planet.replace(' ', "")),
            section_id: (*planet).to_owned(),
            key: keys.machines[i].verifying_key(),
            contests: vec![0, i as u64 + 1],
        })
        .collect();
    let sections = PLANETS
        .iter()
        .enumerate()
        .map(|(i, (planet, _))| SectionEntry {
            section_id: (*planet).to_owned(),
            eligible: 100,
            poll_worker_keys: keys.poll_workers[2 * i..2 * i + 2]
                .iter()
                .map(SigningKey::verifying_key)
                .collect(),
            max_sessions: 2,
            region: (*planet).to_owned(),
        })
        .collect();
    Registry {
        manifest_hash: manifest.hash(),
        version: 1,
        machines,
        sections,
        observers: vec![
            ObserverEntry {
                organisation: "Senate observers".to_owned(),
                key: keys.observers[0].verifying_key(),
            },
            ObserverEntry {
                organisation: "Civil society observers".to_owned(),
                key: keys.observers[1].verifying_key(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starwars_manifest_and_registry_validate() {
        let (manifest, keys) = starwars_manifest(1);
        manifest
            .validate()
            .expect("the Star Wars manifest validates");
        let registry = starwars_registry(&manifest, &keys);
        registry
            .validate(&manifest)
            .expect("the Star Wars registry validates");
    }

    #[test]
    fn starwars_shape_matches_the_scenario() {
        let (manifest, keys) = starwars_manifest(2);
        assert_eq!(manifest.contests.len(), 11);
        assert_eq!(
            manifest.contests[0].name,
            "President of the Galactic Republic"
        );
        assert_eq!(manifest.contests[0].options.len(), 7);
        assert_eq!(manifest.contests[0].options[5].name, "Blank");
        assert_eq!(manifest.contests[0].options[6].name, "Null");
        assert!(manifest.link_groups.is_empty());
        assert!(manifest.parties.is_empty());
        assert_eq!(manifest.trustees.k, 2);
        assert_eq!(manifest.trustees.n(), 3);

        let registry = starwars_registry(&manifest, &keys);
        assert_eq!(registry.sections.len(), 10);
        assert_eq!(registry.machines.len(), 10);
        assert!(registry.machines.iter().all(|m| !m.section_id.is_empty()));
        assert!(registry.machines.iter().all(|m| m.contests.len() == 2));
        assert!(registry.machine("M-MonCala").is_some());
        assert_eq!(manifest.contests[10].name, "Senator — Mandalore");
        let planet10 = manifest.contest(10).expect("contest 10");
        let numbers: Vec<_> = planet10
            .options
            .iter()
            .filter_map(|o| o.number.as_deref())
            .collect();
        assert_eq!(numbers, ["111", "112", "113", "114"]);
    }
}
