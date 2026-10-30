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

/// Parties of the Star Wars scenario: name and ballot number. Each candidate
/// number starts with its party's number.
const SW_PARTIES: [(&str, &str); 5] = [
    ("Aliança Rebelde", "10"),
    ("Ordem Jedi", "11"),
    ("Wookiees Livres", "22"),
    ("Império Galáctico", "66"),
    ("Ordem Sith", "77"),
];

/// A Star Wars candidate: name, party index, and display number.
type SwCandidate = (&'static str, u64, &'static str);

/// Presidential candidates, one per party, numbered with the party's number.
const SW_PRESIDENTS: [SwCandidate; 5] = [
    ("Luke Skywalker", 0, "10"),
    ("Obi-Wan Kenobi", 1, "11"),
    ("Chewbacca", 2, "22"),
    ("Palpatine", 3, "66"),
    ("Darth Vader", 4, "77"),
];

/// Planets of the Star Wars scenario, each with four senate candidates from
/// four different parties. Each planet elects two senators.
const SW_PLANETS: [(&str, [SwCandidate; 4]); N_PLANETS] = [
    (
        "Tatooine",
        [
            ("Owen Lars", 0, "101"),
            ("Beru Lars", 1, "112"),
            ("Jabba the Hutt", 3, "661"),
            ("Bib Fortuna", 4, "773"),
        ],
    ),
    (
        "Naboo",
        [
            ("Padmé Amidala", 0, "103"),
            ("Jar Jar Binks", 3, "662"),
            ("Sio Bibble", 1, "111"),
            ("Boss Nass", 2, "221"),
        ],
    ),
    (
        "Coruscant",
        [
            ("Mas Amedda", 3, "663"),
            ("Sly Moore", 4, "772"),
            ("Orn Free Taa", 1, "113"),
            ("Finis Valorum", 2, "223"),
        ],
    ),
    (
        "Alderaan",
        [
            ("Bail Organa", 0, "101"),
            ("Leia Organa", 1, "112"),
            ("Breha Organa", 2, "223"),
            ("Raymus Antilles", 3, "664"),
        ],
    ),
    (
        "Kashyyyk",
        [
            ("Tarfful", 2, "221"),
            ("Attichitcuk", 0, "102"),
            ("Malla", 1, "113"),
            ("Lumpawarrump", 3, "665"),
        ],
    ),
    (
        "Corellia",
        [
            ("Han Solo", 0, "103"),
            ("Qi'ra", 4, "771"),
            ("Garris Shrike", 3, "668"),
            ("Wedge Antilles", 2, "224"),
        ],
    ),
    (
        "Mon Cala",
        [
            ("Gial Ackbar", 0, "104"),
            ("Raddus", 2, "223"),
            ("Lee-Char", 3, "666"),
            ("Nossor Ri", 4, "776"),
        ],
    ),
    (
        "Kamino",
        [
            ("Lama Su", 3, "667"),
            ("Taun We", 0, "105"),
            ("Nala Se", 1, "117"),
            ("Ko Sai", 2, "226"),
        ],
    ),
    (
        "Endor",
        [
            ("Wicket W. Warrick", 0, "106"),
            ("Chefe Chirpa", 2, "227"),
            ("Logray", 1, "118"),
            ("Teebo", 3, "669"),
        ],
    ),
    (
        "Mandalore",
        [
            ("Bo-Katan Kryze", 0, "107"),
            ("Satine Kryze", 1, "119"),
            ("Pre Vizsla", 4, "778"),
            ("Din Djarin", 2, "228"),
        ],
    ),
];

/// Options of a single-seat contest: the candidates, each with its party, then
/// "Branco" and "Nulo".
fn starwars_options(candidates: &[SwCandidate]) -> Vec<BallotOption> {
    let mut opts: Vec<BallotOption> = candidates
        .iter()
        .enumerate()
        .map(|(i, &(name, party, num))| {
            let mut o = option(i, name, OptionKind::Candidate, Some(num));
            o.party_index = Some(party);
            o
        })
        .collect();
    let n = opts.len();
    opts.push(option(n, "Branco", OptionKind::Blank, None));
    opts.push(option(n + 1, "Nulo", OptionKind::Null, None));
    opts
}

/// Builds the Star Wars manifest and its secret keys from `seed`.
///
/// The election is "Eleição Geral da República Galáctica", in Brazilian form.
/// Contest 0 is the presidency: a single-seat contest with one candidate per
/// party. Each planet then has two single-seat senate contests, "1ª vaga" and
/// "2ª vaga", with identical options. Each pair is a link group, so a voter
/// picks a given senate candidate at most once in total. Five parties are
/// listed. Three trustees (k = 2) sit in the blocs "jedi", "rebelião" and
/// "banco". The EA is in the bloc "senado", and the two mirrors are in "imprensa"
/// and "civil".
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
        "Conselho Jedi",
        "Aliança Rebelde",
        "Clã Bancário Intergaláctico",
    ];
    let blocs = ["jedi", "rebelião", "banco"];
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

    let parties: Vec<Party> = SW_PARTIES
        .iter()
        .enumerate()
        .map(|(i, &(name, number))| Party {
            index: i as u64,
            name: name.to_owned(),
            number: number.to_owned(),
            key: None,
        })
        .collect();

    // Contest 0: the presidency. Contests 2p-1 and 2p: the two senate seats of
    // planet p (p = 1 to 10), with identical options.
    let mut contests = vec![contest(
        0,
        "Presidente",
        ContestKind::Single,
        Method::Homomorphic,
        1,
        starwars_options(&SW_PRESIDENTS),
    )];
    for (i, (planet, senators)) in SW_PLANETS.iter().enumerate() {
        let first = 2 * i as u64 + 1;
        for (seat, seat_name) in [(first, "1ª vaga"), (first + 1, "2ª vaga")] {
            contests.push(contest(
                seat,
                &format!("Senador \u{2014} {planet} \u{2014} {seat_name}"),
                ContestKind::Single,
                Method::Homomorphic,
                1,
                starwars_options(senators),
            ));
        }
    }

    let link_groups: Vec<LinkGroup> = (0..N_PLANETS)
        .map(|i| LinkGroup {
            index: i as u64,
            contests: vec![2 * i as u64 + 1, 2 * i as u64 + 2],
        })
        .collect();

    let software_policy = SoftwarePolicy {
        signers: [
            "Arquivo Jedi",
            "Engenharia da Aliança Rebelde",
            "Auditoria do Clã Bancário",
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
        election_id: "REPUBLICA-GALACTICA-EG-1".to_owned(),
        title: "Eleição Geral da República Galáctica".to_owned(),
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
        link_groups,
        min_section_ballots: 1,
        ea_bloc: "senado".to_owned(),
        mirrors: vec![
            Mirror {
                operator: "HoloNet Notícias".to_owned(),
                bloc: "imprensa".to_owned(),
                url: "https://holonet.example.org".to_owned(),
                key: mirrors[0].verifying_key(),
            },
            Mirror {
                operator: "Observatório da Cantina de Mos Eisley".to_owned(),
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
/// planet name and eligible 120. Each section has two poll workers and
/// max_sessions 2. Each planet has one machine "Urna-<Planeta>" (spaces removed)
/// offering the presidency and its two senate contests. There is no reserve
/// machine. There are two observers.
pub fn starwars_registry(manifest: &Manifest, keys: &Keys) -> Registry {
    let machines = SW_PLANETS
        .iter()
        .enumerate()
        .map(|(i, (planet, _))| MachineEntry {
            machine_id: format!("Urna-{}", planet.replace(' ', "")),
            section_id: (*planet).to_owned(),
            key: keys.machines[i].verifying_key(),
            contests: vec![0, 2 * i as u64 + 1, 2 * i as u64 + 2],
        })
        .collect();
    let sections = SW_PLANETS
        .iter()
        .enumerate()
        .map(|(i, (planet, _))| SectionEntry {
            section_id: (*planet).to_owned(),
            eligible: 30,
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
                organisation: "Observadores do Senado".to_owned(),
                key: keys.observers[0].verifying_key(),
            },
            ObserverEntry {
                organisation: "Observadores da sociedade civil".to_owned(),
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
        assert_eq!(manifest.election_id, "REPUBLICA-GALACTICA-EG-1");
        assert_eq!(manifest.contests.len(), 21);
        assert_eq!(manifest.contests[0].name, "Presidente");
        assert_eq!(manifest.contests[0].options.len(), 7);
        assert_eq!(manifest.contests[0].options[5].name, "Branco");
        assert_eq!(manifest.contests[0].options[6].name, "Nulo");
        assert_eq!(manifest.contests[1].name, "Senador — Tatooine — 1ª vaga");
        assert_eq!(manifest.contests[2].name, "Senador — Tatooine — 2ª vaga");
        assert_eq!(manifest.contests[20].name, "Senador — Mandalore — 2ª vaga");
        assert_eq!(manifest.link_groups.len(), 10);
        assert_eq!(manifest.link_groups[6].contests, [13, 14]);
        assert_eq!(manifest.parties.len(), 5);
        assert_eq!(manifest.parties[3].number, "66");
        assert_eq!(manifest.trustees.k, 2);
        assert_eq!(manifest.trustees.n(), 3);

        let registry = starwars_registry(&manifest, &keys);
        assert_eq!(registry.sections.len(), 10);
        assert_eq!(registry.machines.len(), 10);
        assert!(registry.machines.iter().all(|m| !m.section_id.is_empty()));
        assert!(registry.machines.iter().all(|m| m.contests.len() == 3));
        let moncala = registry.machine("Urna-MonCala").expect("Urna-MonCala");
        assert_eq!(moncala.contests, [0, 13, 14]);
        assert_eq!(registry.section("Mon Cala").expect("section").eligible, 120);
    }

    #[test]
    fn starwars_candidate_numbers_follow_their_party() {
        let (manifest, _) = starwars_manifest(3);
        for c in &manifest.contests[1..] {
            let names: Vec<&str> = c.options.iter().map(|o| o.name.as_str()).collect();
            assert_eq!(names.len(), 6, "{names:?}");
            assert_eq!(c.options[4].name, "Branco", "{names:?}");
        }
        for (planet, senators) in &SW_PLANETS {
            let mut parties: Vec<u64> = senators.iter().map(|s| s.1).collect();
            parties.sort_unstable();
            parties.dedup();
            assert_eq!(parties.len(), 4, "{planet}: parties must be distinct");
            let mut numbers: Vec<&str> = senators.iter().map(|s| s.2).collect();
            numbers.sort_unstable();
            numbers.dedup();
            assert_eq!(numbers.len(), 4, "{planet}: numbers must be distinct");
            for &(name, party, number) in senators {
                let prefix = SW_PARTIES[party as usize].1;
                assert_eq!(number.len(), 3, "{name}");
                assert!(number.starts_with(prefix), "{name} {number} {prefix}");
            }
        }
        for &(name, party, number) in &SW_PRESIDENTS {
            assert_eq!(number, SW_PARTIES[party as usize].1, "{name}");
        }
    }
}
