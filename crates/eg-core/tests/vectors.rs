//! Test vectors for eg/v1 (SPEC.md §27).
//!
//! Every vector is a deterministic CBOR map with its inputs, intermediate
//! values and outputs. The `.cbor` files are the normative encoding and the
//! `.json` files are a human-readable rendering of the same values. Running
//! with `EG_WRITE_VECTORS=1` regenerates both; a plain run fails if the files
//! on disk differ from what the code produces.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use eg_core::cbor::{self, Value};
use eg_core::elgamal::{dlog_bounded, Ciphertext};
use eg_core::group::{
    gen, lagrange, point_to_value, random_scalar, scalar_to_value, RistrettoPoint, Scalar, B,
};
use eg_core::hash::{digest, hash_to_scalar};
use eg_core::proofs::{
    prove_decryption_share, prove_sum, verify_decryption_share, verify_sum, CpProof, Disj01Proof,
    SchnorrProof,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

/// Seed of a vector's own RNG: SHA-256("eg/v1/test-vector/" || name).
fn seed_for(name: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"eg/v1/test-vector/");
    h.update(name.as_bytes());
    h.finalize().into()
}

fn rng_for(name: &str) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed_for(name))
}

/// Fixed per-vector context hash, recorded in each vector's inputs.
fn context_hash(name: &str) -> [u8; 32] {
    digest("eg/v1/test-vector/context", &[Value::from(name)])
}

fn obj(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::from(k), v))
            .collect(),
    )
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn vector(name: &str, draws: &str, inputs: Value, intermediates: Value, outputs: Value) -> Value {
    obj(vec![
        ("name", Value::from(name)),
        ("seed", bytes(&seed_for(name))),
        ("draws", Value::from(draws)),
        ("inputs", inputs),
        ("intermediates", intermediates),
        ("outputs", outputs),
    ])
}

fn hash_vector() -> Value {
    let name = "hash";
    let tag = "eg/v1/test-vector/hash";
    let items = vec![
        Value::from(1u64),
        Value::Bytes(vec![0xab; 32]),
        Value::from("x"),
    ];

    let mut transcript_items = vec![Value::from(tag)];
    transcript_items.extend(items.iter().cloned());
    let transcript = cbor::encode(&Value::Array(transcript_items));
    let d = digest(tag, &items);
    let h = hash_to_scalar(tag, &items);

    vector(
        name,
        "none",
        obj(vec![
            ("tag", Value::from(tag)),
            ("items", Value::Array(items)),
        ]),
        obj(vec![]),
        obj(vec![
            ("transcript", Value::Bytes(transcript)),
            ("digest", bytes(&d)),
            ("hash_to_scalar", scalar_to_value(&h)),
        ]),
    )
}

fn gen_vector() -> Value {
    let name = "gen";
    let ch = context_hash(name);
    let generators: Vec<Value> = (0..3).map(|i| point_to_value(&gen(&ch, "h", i))).collect();

    vector(
        name,
        "none",
        obj(vec![
            ("context_hash", bytes(&ch)),
            ("label", Value::from("h")),
        ]),
        obj(vec![]),
        obj(vec![("generators", Value::Array(generators))]),
    )
}

fn elgamal_vector() -> Value {
    let name = "elgamal";
    let mut rng = rng_for(name);
    let s = random_scalar(&mut rng);
    let rs: Vec<Scalar> = (0..5).map(|_| random_scalar(&mut rng)).collect();
    let r_prime = random_scalar(&mut rng);

    let k = s * B;
    let messages: [u32; 5] = [0, 1, 1, 0, 1];
    let cts: Vec<Ciphertext> = messages
        .iter()
        .zip(&rs)
        .map(|(&m, r)| Ciphertext::encrypt(m, r, &k).expect("encrypt"))
        .collect();
    let sum: Ciphertext = cts.iter().copied().sum();
    let sum_plaintext = dlog_bounded(&sum.decrypt_to_point(&s), 5);
    assert_eq!(sum_plaintext, Some(3), "elgamal: sum plaintext");
    let reencrypted_sum = sum.reencrypt(&r_prime, &k);

    vector(
        name,
        "s, r_0, r_1, r_2, r_3, r_4, r_prime",
        obj(vec![
            ("s", scalar_to_value(&s)),
            ("r", Value::Array(rs.iter().map(scalar_to_value).collect())),
            ("r_prime", scalar_to_value(&r_prime)),
            (
                "messages",
                Value::Array(
                    messages
                        .iter()
                        .map(|&m| Value::from(u64::from(m)))
                        .collect(),
                ),
            ),
        ]),
        obj(vec![]),
        obj(vec![
            ("K", point_to_value(&k)),
            (
                "ciphertexts",
                Value::Array(cts.iter().map(Ciphertext::to_value).collect()),
            ),
            ("sum", sum.to_value()),
            ("sum_plaintext", Value::from(3u64)),
            ("reencrypted_sum", reencrypted_sum.to_value()),
        ]),
    )
}

fn schnorr_vector() -> Value {
    let name = "schnorr";
    let ch = context_hash(name);
    let mut rng = rng_for(name);
    let x = random_scalar(&mut rng);
    let ctx = Value::Array(vec![Value::from("test"), bytes(&ch)]);

    let big_x = x * B;
    let proof = SchnorrProof::prove(&mut rng, &ctx, &x);
    assert!(proof.verify(&ctx, &big_x), "schnorr: proof does not verify");
    let a = proof.v * B - proof.c * big_x;

    vector(
        name,
        "x, u (inside prove)",
        obj(vec![
            ("context_hash", bytes(&ch)),
            ("x", scalar_to_value(&x)),
            ("ctx", ctx.clone()),
        ]),
        obj(vec![
            ("X", point_to_value(&big_x)),
            ("A", point_to_value(&a)),
            ("c", scalar_to_value(&proof.c)),
        ]),
        obj(vec![("proof", proof.to_value())]),
    )
}

fn chaum_pedersen_vector() -> Value {
    let name = "chaum-pedersen";
    let ch = context_hash(name);
    let mut rng = rng_for(name);
    let x = random_scalar(&mut rng);
    let g1 = B;
    let g2 = gen(&ch, "test-g2", 0);
    let ctx = Value::Array(vec![Value::from("test"), bytes(&ch)]);

    let x1 = x * g1;
    let x2 = x * g2;
    let proof = CpProof::prove(&mut rng, &ctx, &x, &g1, &g2);
    assert!(
        proof.verify(&ctx, &g1, &x1, &g2, &x2),
        "chaum-pedersen: proof does not verify"
    );
    let a1 = proof.v * g1 - proof.c * x1;
    let a2 = proof.v * g2 - proof.c * x2;

    vector(
        name,
        "x, u (inside prove)",
        obj(vec![
            ("context_hash", bytes(&ch)),
            ("x", scalar_to_value(&x)),
            ("G1", point_to_value(&g1)),
            ("G2", point_to_value(&g2)),
            ("ctx", ctx.clone()),
        ]),
        obj(vec![
            ("X1", point_to_value(&x1)),
            ("X2", point_to_value(&x2)),
            ("A1", point_to_value(&a1)),
            ("A2", point_to_value(&a2)),
            ("c", scalar_to_value(&proof.c)),
        ]),
        obj(vec![("proof", proof.to_value())]),
    )
}

/// Disjunctive 0-or-1 proof. `name` is `disj01-0` or `disj01-1`, `b` the bit.
fn disj01_vector(name: &str, b: u8) -> Value {
    let ch = context_hash(name);
    let mut rng = rng_for(name);
    let s = random_scalar(&mut rng);
    let k = s * B;
    let r = random_scalar(&mut rng);
    let ballot = [0x42u8; 32];
    let ctx = Value::Array(vec![
        Value::from("sel"),
        bytes(&ch),
        bytes(&ballot),
        Value::from(0u64),
        Value::from(3u64),
    ]);

    let (ct, proof) = Disj01Proof::prove(&mut rng, &ctx, &k, b, &r).expect("disj01: prove");
    assert!(proof.verify(&ctx, &k, &ct), "{name}: proof does not verify");

    let Disj01Proof { c0, c1, v0, v1 } = proof;
    let a0 = v0 * B - c0 * ct.alpha;
    let d0 = v0 * k - c0 * ct.beta;
    let a1 = v1 * B - c1 * ct.alpha;
    let d1 = v1 * k - c1 * (ct.beta - B);

    vector(
        name,
        "s, r, u, c_sim, v_sim",
        obj(vec![
            ("context_hash", bytes(&ch)),
            ("s", scalar_to_value(&s)),
            ("K", point_to_value(&k)),
            ("b", Value::from(u64::from(b))),
            ("r", scalar_to_value(&r)),
            ("ctx", ctx.clone()),
        ]),
        obj(vec![
            ("A0", point_to_value(&a0)),
            ("D0", point_to_value(&d0)),
            ("A1", point_to_value(&a1)),
            ("D1", point_to_value(&d1)),
            ("c", scalar_to_value(&(c0 + c1))),
        ]),
        obj(vec![
            ("ciphertext", ct.to_value()),
            ("proof", proof.to_value()),
        ]),
    )
}

fn sum_vector() -> Value {
    let name = "sum";
    let ch = context_hash(name);
    let mut rng = rng_for(name);
    let s = random_scalar(&mut rng);
    let k = s * B;
    let rs: Vec<Scalar> = (0..4).map(|_| random_scalar(&mut rng)).collect();

    let bits: [u64; 4] = [0, 1, 0, 1];
    let l = 2u64;
    let ballot = [0x42u8; 32];
    let cts: Vec<Ciphertext> = bits
        .iter()
        .zip(&rs)
        .map(|(&b, r)| Ciphertext::encrypt(b as u32, r, &k).expect("sum: encrypt"))
        .collect();
    let sum: Ciphertext = cts.iter().copied().sum();
    let r_sum: Scalar = rs.iter().sum();

    let ctx = Value::Array(vec![
        Value::from("sum"),
        bytes(&ch),
        bytes(&ballot),
        Value::from(0u64),
    ]);
    let proof = prove_sum(&mut rng, &ctx, &k, &r_sum);
    assert!(
        verify_sum(&proof, &ctx, &k, &sum, l),
        "sum: l=2 must verify"
    );
    assert!(!verify_sum(&proof, &ctx, &k, &sum, 1), "sum: l=1 must fail");

    let x2 = sum.beta - Scalar::from(l) * B;
    let a1 = proof.v * B - proof.c * sum.alpha;
    let a2 = proof.v * k - proof.c * x2;

    vector(
        name,
        "s, r_0, r_1, r_2, r_3, u",
        obj(vec![
            ("context_hash", bytes(&ch)),
            ("s", scalar_to_value(&s)),
            ("K", point_to_value(&k)),
            (
                "bits",
                Value::Array(bits.iter().map(|&b| Value::from(b)).collect()),
            ),
            ("L", Value::from(l)),
            ("r", Value::Array(rs.iter().map(scalar_to_value).collect())),
            ("ballot_id", bytes(&ballot)),
            ("ctx", ctx.clone()),
        ]),
        obj(vec![
            (
                "ciphertexts",
                Value::Array(cts.iter().map(Ciphertext::to_value).collect()),
            ),
            ("r_sum", scalar_to_value(&r_sum)),
            ("sum", sum.to_value()),
            ("X2", point_to_value(&x2)),
            ("A1", point_to_value(&a1)),
            ("A2", point_to_value(&a2)),
            ("c", scalar_to_value(&proof.c)),
        ]),
        obj(vec![("proof", proof.to_value())]),
    )
}

fn decryption_vector() -> Value {
    let name = "decryption";
    let ch = context_hash(name);
    let mut rng = rng_for(name);
    let a0 = random_scalar(&mut rng);
    let a1 = random_scalar(&mut rng);
    let r = random_scalar(&mut rng);

    let k = a0 * B;
    let ctx = Value::Array(vec![
        Value::from("dec"),
        bytes(&ch),
        bytes(&[0x55u8; 32]),
        Value::from(0u64),
    ]);
    let ct = Ciphertext::encrypt(1, &r, &k).expect("decryption: encrypt");
    let alpha = ct.alpha;

    // Trustee j (1..=3) holds z_j = f(j) for f(x) = a0 + a1·x.
    let shares: Vec<(u64, Scalar, RistrettoPoint)> = (1..=3u64)
        .map(|j| {
            let z = a0 + a1 * Scalar::from(j);
            (j, z, z * B)
        })
        .collect();

    let mut m_js: Vec<RistrettoPoint> = Vec::new();
    let mut proofs: Vec<CpProof> = Vec::new();
    for (_, z, z_big) in &shares {
        let m_j = *z * alpha;
        let proof = prove_decryption_share(&mut rng, &ctx, z, &alpha);
        assert!(
            verify_decryption_share(&proof, &ctx, z_big, &alpha, &m_j),
            "decryption: share proof does not verify"
        );
        m_js.push(m_j);
        proofs.push(proof);
    }

    let mut combinations = Vec::new();
    let mut agreed: Option<RistrettoPoint> = None;
    for set in [[1u64, 2], [2, 3]] {
        let lambdas: Vec<Scalar> = set
            .iter()
            .map(|&j| lagrange(&set, j).expect("decryption: lagrange"))
            .collect();
        let m: RistrettoPoint = set
            .iter()
            .zip(&lambdas)
            .map(|(&j, lam)| *lam * m_js[(j - 1) as usize])
            .sum();
        let t = ct.beta - m;
        let plaintext = dlog_bounded(&t, 1);
        assert_eq!(plaintext, Some(1), "decryption: m for set {set:?}");
        match agreed {
            Some(prev) => assert_eq!(prev, m, "decryption: M differs between sets"),
            None => agreed = Some(m),
        }
        combinations.push(obj(vec![
            (
                "set",
                Value::Array(set.iter().map(|&j| Value::from(j)).collect()),
            ),
            (
                "lambdas",
                Value::Array(lambdas.iter().map(scalar_to_value).collect()),
            ),
            ("M", point_to_value(&m)),
            ("T", point_to_value(&t)),
            ("m", Value::from(plaintext.expect("checked above"))),
        ]));
    }

    vector(
        name,
        "a0, a1, r, u_1, u_2, u_3",
        obj(vec![
            ("context_hash", bytes(&ch)),
            ("a0", scalar_to_value(&a0)),
            ("a1", scalar_to_value(&a1)),
            ("r", scalar_to_value(&r)),
            ("message", Value::from(1u64)),
            ("ctx", ctx.clone()),
        ]),
        obj(vec![
            ("K", point_to_value(&k)),
            ("ciphertext", ct.to_value()),
            (
                "z",
                Value::Array(shares.iter().map(|(_, z, _)| scalar_to_value(z)).collect()),
            ),
            (
                "Z",
                Value::Array(shares.iter().map(|(_, _, zb)| point_to_value(zb)).collect()),
            ),
            (
                "M_j",
                Value::Array(m_js.iter().map(point_to_value).collect()),
            ),
        ]),
        obj(vec![
            (
                "share_proofs",
                Value::Array(proofs.iter().map(CpProof::to_value).collect()),
            ),
            ("combinations", Value::Array(combinations)),
        ]),
    )
}

/// Every vector, as (name, value). The name is also the file stem.
fn build_all() -> Vec<(String, Value)> {
    vec![
        ("hash".to_owned(), hash_vector()),
        ("gen".to_owned(), gen_vector()),
        ("elgamal".to_owned(), elgamal_vector()),
        ("schnorr".to_owned(), schnorr_vector()),
        ("chaum-pedersen".to_owned(), chaum_pedersen_vector()),
        ("disj01-0".to_owned(), disj01_vector("disj01-0", 0)),
        ("disj01-1".to_owned(), disj01_vector("disj01-1", 1)),
        ("sum".to_owned(), sum_vector()),
        ("decryption".to_owned(), decryption_vector()),
    ]
}

fn vector_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/m1"
    ))
}

/// Renders the value held in `encoded` as JSON with 2-space indentation.
/// The value is decoded from its encoding so that map keys appear in the
/// same order as in the `.cbor` file.
fn render_json(encoded: &[u8]) -> String {
    let v = cbor::decode(encoded).expect("vector re-decodes");
    let mut out = String::new();
    write_json(&v, 0, &mut out);
    out.push('\n');
    out
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_json(v: &Value, depth: usize, out: &mut String) {
    match v {
        Value::Uint(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Bytes(b) => {
            out.push('"');
            out.push_str(&hex::encode(b));
            out.push('"');
        }
        Value::Text(s) => write_json_string(s, out),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                push_indent(out, depth + 1);
                write_json(item, depth + 1, out);
            }
            out.push('\n');
            push_indent(out, depth);
            out.push(']');
        }
        Value::Map(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                let Value::Text(k) = key else {
                    panic!("JSON rendering requires text map keys, got {key:?}");
                };
                push_indent(out, depth + 1);
                write_json_string(k, out);
                out.push_str(": ");
                write_json(value, depth + 1, out);
            }
            out.push('\n');
            push_indent(out, depth);
            out.push('}');
        }
    }
}

#[test]
fn vectors_match_files() {
    let dir = vector_dir();
    let write = std::env::var_os("EG_WRITE_VECTORS").is_some();
    if write {
        fs::create_dir_all(&dir).expect("create test-vectors/m1");
    }

    for (name, v) in build_all() {
        let encoded = cbor::encode(&v);
        let json = render_json(&encoded);
        let cbor_path = dir.join(format!("{name}.cbor"));
        let json_path = dir.join(format!("{name}.json"));

        if write {
            fs::write(&cbor_path, &encoded).expect("write .cbor");
            fs::write(&json_path, &json).expect("write .json");
            continue;
        }

        let hint = "if the change is intended, regenerate with \
                    `EG_WRITE_VECTORS=1 cargo test -p eg-core --test vectors`";
        let on_disk = fs::read(&cbor_path)
            .unwrap_or_else(|e| panic!("missing {}: {e}; {hint}", cbor_path.display()));
        assert!(
            on_disk == encoded,
            "{} differs from the fresh encoding; {hint}",
            cbor_path.display()
        );
        let on_disk_json = fs::read_to_string(&json_path)
            .unwrap_or_else(|e| panic!("missing {}: {e}; {hint}", json_path.display()));
        assert!(
            on_disk_json == json,
            "{} differs from the fresh rendering; {hint}",
            json_path.display()
        );
    }
}

#[test]
fn vector_files_are_canonical() {
    let mut count = 0;
    for entry in fs::read_dir(vector_dir()).expect("read test-vectors/m1") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("cbor") {
            continue;
        }
        let bytes = fs::read(&path).expect("read .cbor");
        let v = cbor::decode(&bytes)
            .unwrap_or_else(|e| panic!("{} does not decode: {e}", path.display()));
        assert!(
            cbor::encode(&v) == bytes,
            "{} is not in canonical form",
            path.display()
        );
        count += 1;
    }
    assert!(count > 0, "no .cbor vectors found");
}

#[test]
fn chacha20_matches_rfc_keystream() {
    // ChaCha20 with key 0, nonce 0, counter 0 (the standard keystream).
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut out = [0u8; 32];
    rng.fill_bytes(&mut out);
    assert_eq!(
        hex::encode(out),
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
        "ChaCha20Rng does not produce the standard ChaCha20 keystream"
    );
}
