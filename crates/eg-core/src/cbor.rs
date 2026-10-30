//! Deterministic CBOR (RFC 8949 §4.2.1) for eg/v1 (SPEC.md §6.1).
//!
//! Supported items are unsigned integers, byte strings, text strings, arrays,
//! maps and the booleans `false` and `true` (SPEC.md §7.1 uses `bool` fields).
//! Everything else, including floats, null and other simple values, is
//! rejected by the decoder.

use std::cmp::Ordering;

const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;

/// Encodings of the simple values `false` and `true` (major type 7).
const SIMPLE_FALSE: u8 = 0xf4;
const SIMPLE_TRUE: u8 = 0xf5;

/// Maximum number of nested arrays/maps accepted by the decoder.
const MAX_DEPTH: usize = 64;

/// A CBOR data item restricted to the eg/v1 subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>), // order as constructed; encoder sorts
    Bool(bool),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CborError {
    #[error("unexpected end of input")]
    Eof,
    #[error("trailing bytes after item")]
    Trailing,
    #[error("unsupported major type or additional info")]
    Unsupported,
    #[error("non-shortest integer or length encoding")]
    NonCanonicalInt,
    #[error("map keys not in canonical order")]
    KeyOrder,
    #[error("duplicate map key")]
    DuplicateKey,
    #[error("invalid UTF-8 text")]
    Utf8,
    #[error("nesting too deep")]
    TooDeep,
    #[error("{0}")]
    Schema(String),
}

fn schema(msg: &str) -> CborError {
    CborError::Schema(msg.to_owned())
}

impl Value {
    pub fn as_uint(&self) -> Result<u64, CborError> {
        match self {
            Value::Uint(n) => Ok(*n),
            _ => Err(schema("expected unsigned integer")),
        }
    }

    pub fn as_bytes(&self) -> Result<&[u8], CborError> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(schema("expected byte string")),
        }
    }

    pub fn as_text(&self) -> Result<&str, CborError> {
        match self {
            Value::Text(s) => Ok(s),
            _ => Err(schema("expected text string")),
        }
    }

    pub fn as_array(&self) -> Result<&[Value], CborError> {
        match self {
            Value::Array(items) => Ok(items),
            _ => Err(schema("expected array")),
        }
    }

    pub fn as_map(&self) -> Result<&[(Value, Value)], CborError> {
        match self {
            Value::Map(entries) => Ok(entries),
            _ => Err(schema("expected map")),
        }
    }

    pub fn as_bool(&self) -> Result<bool, CborError> {
        match self {
            Value::Bool(b) => Ok(*b),
            _ => Err(schema("expected boolean")),
        }
    }

    /// Look up a map entry by uint key.
    pub fn get(&self, key: u64) -> Result<Option<&Value>, CborError> {
        Ok(self
            .as_map()?
            .iter()
            .find(|(k, _)| matches!(k, Value::Uint(n) if *n == key))
            .map(|(_, v)| v))
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Uint(n)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}

impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}

impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl From<[u8; 32]> for Value {
    fn from(b: [u8; 32]) -> Self {
        Value::Bytes(b.to_vec())
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Self {
        Value::Array(items)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

/// Encodes a value in deterministic form. Map entries are sorted by the
/// bytewise order of their encoded keys.
///
/// # Panics
///
/// Panics if a map contains two keys with identical encodings (a programming
/// error).
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

/// Appends the deterministic encoding of `v` to `out`. See [`encode`].
pub fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(n) => write_head(MAJOR_UINT, *n, out),
        Value::Bytes(b) => {
            write_head(MAJOR_BYTES, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(MAJOR_TEXT, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            write_head(MAJOR_ARRAY, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Bool(b) => out.push(if *b { SIMPLE_TRUE } else { SIMPLE_FALSE }),
        Value::Map(entries) => {
            let mut sorted: Vec<(Vec<u8>, &Value)> =
                entries.iter().map(|(k, val)| (encode(k), val)).collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            assert!(
                sorted.windows(2).all(|w| w[0].0 != w[1].0),
                "duplicate map key in CBOR encode"
            );
            write_head(MAJOR_MAP, sorted.len() as u64, out);
            for (key, val) in sorted {
                out.extend_from_slice(&key);
                encode_into(val, out);
            }
        }
    }
}

fn write_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => {
            out.push(m | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

/// Decodes exactly one data item, rejecting any input that is not in
/// deterministic form.
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    let mut dec = Decoder {
        input: bytes,
        pos: 0,
    };
    let value = dec.item(0)?;
    if dec.pos != bytes.len() {
        return Err(CborError::Trailing);
    }
    Ok(value)
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if n > self.remaining() {
            return Err(CborError::Eof);
        }
        let slice = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Reads a big-endian unsigned argument of `n` bytes.
    fn be(&mut self, n: usize) -> Result<u64, CborError> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// Converts a declared length or count to `usize`, rejecting values that
    /// cannot possibly be satisfied by the remaining input. This prevents
    /// large preallocations from attacker-controlled headers.
    fn len(&self, arg: u64) -> Result<usize, CborError> {
        match usize::try_from(arg) {
            Ok(n) if n <= self.remaining() => Ok(n),
            _ => Err(CborError::Eof),
        }
    }

    /// Reads an initial byte and its argument, enforcing shortest form.
    fn head(&mut self) -> Result<(u8, u64), CborError> {
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let info = initial & 0x1f;
        if !matches!(
            major,
            MAJOR_UINT | MAJOR_BYTES | MAJOR_TEXT | MAJOR_ARRAY | MAJOR_MAP
        ) {
            return Err(CborError::Unsupported);
        }
        let (arg, min) = match info {
            0..=23 => return Ok((major, u64::from(info))),
            24 => (self.be(1)?, 24),
            25 => (self.be(2)?, 0x100),
            26 => (self.be(4)?, 0x1_0000),
            27 => (self.be(8)?, 0x1_0000_0000),
            // 28..=30 are reserved, 31 is indefinite length (and break).
            _ => return Err(CborError::Unsupported),
        };
        if arg < min {
            return Err(CborError::NonCanonicalInt);
        }
        Ok((major, arg))
    }

    /// Returns the nesting depth for the container being entered.
    fn enter(depth: usize) -> Result<usize, CborError> {
        if depth >= MAX_DEPTH {
            Err(CborError::TooDeep)
        } else {
            Ok(depth + 1)
        }
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        // The only simple values in the subset are false and true. Every
        // other major-type-7 item is rejected by `head`.
        match self.input.get(self.pos) {
            Some(&SIMPLE_FALSE) => {
                self.pos += 1;
                return Ok(Value::Bool(false));
            }
            Some(&SIMPLE_TRUE) => {
                self.pos += 1;
                return Ok(Value::Bool(true));
            }
            _ => {}
        }
        let (major, arg) = self.head()?;
        match major {
            MAJOR_UINT => Ok(Value::Uint(arg)),
            MAJOR_BYTES => {
                let n = self.len(arg)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            MAJOR_TEXT => {
                let n = self.len(arg)?;
                let raw = self.take(n)?;
                let text = std::str::from_utf8(raw).map_err(|_| CborError::Utf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            MAJOR_ARRAY => {
                let child = Self::enter(depth)?;
                let n = self.len(arg)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(child)?);
                }
                Ok(Value::Array(items))
            }
            MAJOR_MAP => {
                let child = Self::enter(depth)?;
                let n = self.len(arg)?;
                let mut entries = Vec::with_capacity(n);
                // Byte range of the previous key's encoding in the input.
                let mut prev: Option<(usize, usize)> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let key = self.item(child)?;
                    let end = self.pos;
                    if let Some((ps, pe)) = prev {
                        // Input is verified canonical, so the slice is the
                        // key's deterministic encoding.
                        match self.input[ps..pe].cmp(&self.input[start..end]) {
                            Ordering::Less => {}
                            Ordering::Equal => return Err(CborError::DuplicateKey),
                            Ordering::Greater => return Err(CborError::KeyOrder),
                        }
                    }
                    prev = Some((start, end));
                    let value = self.item(child)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(CborError::Unsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    fn enc_hex(v: &Value) -> String {
        hex::encode(encode(v))
    }

    #[test]
    fn rfc8949_uints() {
        let cases: &[(u64, &str)] = &[
            (0, "00"),
            (1, "01"),
            (10, "0a"),
            (23, "17"),
            (24, "1818"),
            (25, "1819"),
            (100, "1864"),
            (1000, "1903e8"),
            (1_000_000, "1a000f4240"),
            (1_000_000_000_000, "1b000000e8d4a51000"),
            (18_446_744_073_709_551_615, "1bffffffffffffffff"),
        ];
        for &(n, h) in cases {
            assert_eq!(enc_hex(&Value::Uint(n)), h, "encode {n}");
            assert_eq!(decode(&hx(h)), Ok(Value::Uint(n)), "decode {h}");
        }
    }

    #[test]
    fn rfc8949_text() {
        for (s, h) in [("", "60"), ("a", "6161"), ("IETF", "6449455446")] {
            assert_eq!(enc_hex(&Value::from(s)), h);
            assert_eq!(decode(&hx(h)), Ok(Value::from(s)));
        }
    }

    #[test]
    fn rfc8949_bytes() {
        let empty: &[u8] = &[];
        assert_eq!(enc_hex(&Value::from(empty)), "40");
        assert_eq!(decode(&hx("40")), Ok(Value::Bytes(vec![])));
        assert_eq!(enc_hex(&Value::from(vec![1, 2, 3, 4])), "4401020304");
        assert_eq!(
            decode(&hx("4401020304")),
            Ok(Value::Bytes(vec![1, 2, 3, 4]))
        );
    }

    #[test]
    fn rfc8949_arrays_and_maps() {
        assert_eq!(enc_hex(&Value::Array(vec![])), "80");
        assert_eq!(decode(&hx("80")), Ok(Value::Array(vec![])));

        let nested = Value::Array(vec![
            Value::Uint(1),
            Value::Array(vec![Value::Uint(2), Value::Uint(3)]),
            Value::Array(vec![Value::Uint(4), Value::Uint(5)]),
        ]);
        assert_eq!(enc_hex(&nested), "8301820203820405");
        assert_eq!(decode(&hx("8301820203820405")), Ok(nested));

        let map = Value::Map(vec![
            (Value::Uint(1), Value::Uint(2)),
            (Value::Uint(3), Value::Uint(4)),
        ]);
        assert_eq!(enc_hex(&map), "a201020304");
        assert_eq!(decode(&hx("a201020304")), Ok(map));
    }

    #[test]
    fn encoder_sorts_map_keys_by_encoding() {
        let map = Value::Map(vec![
            (Value::from("aa"), Value::Uint(0)),
            (Value::Uint(100), Value::Uint(0)),
            (Value::from("z"), Value::Uint(0)),
            (Value::Uint(10), Value::Uint(0)),
        ]);
        // 10 (0a) < 100 (18 64) < "z" (61 7a) < "aa" (62 61 61)
        assert_eq!(enc_hex(&map), "a40a00186400617a0062616100");
    }

    #[test]
    fn round_trip() {
        let v = Value::Map(vec![
            (Value::Uint(0), Value::from("ballot")),
            (
                Value::Uint(1),
                Value::Array(vec![
                    Value::Bytes(vec![0xab; 32]),
                    Value::Uint(u64::MAX),
                    Value::from("héllo"),
                    Value::Array(vec![]),
                ]),
            ),
            (Value::Uint(7), Value::Map(vec![])),
        ]);
        let bytes = encode(&v);
        assert_eq!(decode(&bytes), Ok(v.clone()));
        assert_eq!(encode(&decode(&bytes).unwrap()), bytes);
    }

    #[test]
    fn accessors() {
        let map = Value::Map(vec![
            (Value::Uint(1), Value::from("x")),
            (Value::Uint(2), Value::from(vec![1u8])),
        ]);
        assert_eq!(map.get(1).unwrap(), Some(&Value::from("x")));
        assert_eq!(map.get(3).unwrap(), None);
        assert_eq!(map.get(1).unwrap().unwrap().as_text(), Ok("x"));
        assert_eq!(map.get(2).unwrap().unwrap().as_bytes(), Ok(&[1u8][..]));
        assert!(matches!(
            Value::Uint(1).as_text(),
            Err(CborError::Schema(_))
        ));
        assert!(matches!(Value::Uint(1).get(0), Err(CborError::Schema(_))));
        assert_eq!(Value::Uint(9).as_uint(), Ok(9));
        assert_eq!(Value::Array(vec![]).as_array(), Ok(&[][..]));
        assert_eq!(Value::Map(vec![]).as_map(), Ok(&[][..]));
        assert_eq!(Value::from([7u8; 32]).as_bytes().unwrap(), &[7u8; 32][..]);
    }

    #[test]
    #[should_panic(expected = "duplicate map key")]
    fn encode_panics_on_duplicate_key() {
        let v = Value::Map(vec![
            (Value::Uint(1), Value::Uint(0)),
            (Value::Uint(1), Value::Uint(2)),
        ]);
        let _ = encode(&v);
    }

    #[test]
    fn rejects_non_shortest_int() {
        assert_eq!(decode(&hx("1805")), Err(CborError::NonCanonicalInt));
        assert_eq!(decode(&hx("1900ff")), Err(CborError::NonCanonicalInt));
        assert_eq!(decode(&hx("780161")), Err(CborError::NonCanonicalInt));
    }

    #[test]
    fn rejects_indefinite_length() {
        assert_eq!(decode(&hx("9f0102ff")), Err(CborError::Unsupported));
        assert_eq!(decode(&hx("5f4101ff")), Err(CborError::Unsupported));
        assert_eq!(decode(&hx("ff")), Err(CborError::Unsupported));
    }

    #[test]
    fn rejects_unsorted_map() {
        // {2: 0, 1: 0}
        assert_eq!(decode(&hx("a202000100")), Err(CborError::KeyOrder));
    }

    #[test]
    fn rejects_duplicate_key() {
        // {1: 0, 1: 0}
        assert_eq!(decode(&hx("a201000100")), Err(CborError::DuplicateKey));
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert_eq!(decode(&hx("0001")), Err(CborError::Trailing));
    }

    #[test]
    fn rejects_negative_int() {
        assert_eq!(decode(&hx("20")), Err(CborError::Unsupported));
    }

    #[test]
    fn rejects_tag() {
        assert_eq!(decode(&hx("c001")), Err(CborError::Unsupported));
    }

    #[test]
    fn rejects_float() {
        assert_eq!(decode(&hx("f90000")), Err(CborError::Unsupported));
        assert_eq!(
            decode(&hx("fb3ff0000000000000")),
            Err(CborError::Unsupported)
        );
    }

    #[test]
    fn rejects_simple_values() {
        assert_eq!(decode(&hx("f6")), Err(CborError::Unsupported)); // null
        assert_eq!(decode(&hx("f7")), Err(CborError::Unsupported)); // undefined
        assert_eq!(decode(&hx("f820")), Err(CborError::Unsupported)); // simple(32)
        assert_eq!(decode(&hx("f0")), Err(CborError::Unsupported)); // simple(16)
        assert_eq!(decode(&hx("f9")), Err(CborError::Unsupported)); // half float prefix
    }

    #[test]
    fn bool_round_trip() {
        assert_eq!(enc_hex(&Value::Bool(true)), "f5");
        assert_eq!(enc_hex(&Value::Bool(false)), "f4");
        assert_eq!(decode(&hx("f5")), Ok(Value::Bool(true)));
        assert_eq!(decode(&hx("f4")), Ok(Value::Bool(false)));
        assert_eq!(Value::from(true), Value::Bool(true));
        assert_eq!(Value::Bool(true).as_bool(), Ok(true));
        assert_eq!(Value::Bool(false).as_bool(), Ok(false));
        assert!(matches!(
            Value::Uint(1).as_bool(),
            Err(CborError::Schema(_))
        ));

        let v = Value::Map(vec![
            (Value::Uint(0), Value::Bool(true)),
            (Value::Uint(1), Value::Array(vec![Value::Bool(false)])),
        ]);
        assert_eq!(decode(&encode(&v)), Ok(v));
    }

    #[test]
    fn bool_map_key_decodes_but_is_not_a_uint_key() {
        // {true: 1}: the decoder accepts the item; schema helpers reject it.
        let v = decode(&hx("a1f501")).unwrap();
        assert_eq!(v.get(1), Ok(None));
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert_eq!(decode(&hx("62c328")), Err(CborError::Utf8));
    }

    #[test]
    fn rejects_truncated_input() {
        assert_eq!(decode(&hx("1a00")), Err(CborError::Eof));
        assert_eq!(decode(&hx("8301")), Err(CborError::Eof));
        assert_eq!(decode(&hx("44010203")), Err(CborError::Eof));
        assert_eq!(decode(&[]), Err(CborError::Eof));
    }

    #[test]
    fn huge_declared_length_is_eof_without_allocating() {
        assert_eq!(decode(&hx("5bffffffffffffffff")), Err(CborError::Eof));
        assert_eq!(decode(&hx("9bffffffffffffffff")), Err(CborError::Eof));
        assert_eq!(decode(&hx("bbffffffffffffffff")), Err(CborError::Eof));
    }

    #[test]
    fn nesting_depth_limit() {
        let mut ok = vec![0x81u8; 64];
        ok.push(0x00);
        assert!(decode(&ok).is_ok());

        let mut too_deep = vec![0x81u8; 65];
        too_deep.push(0x00);
        assert_eq!(decode(&too_deep), Err(CborError::TooDeep));
    }
}

/// Checks that `v` is a record map whose keys are exactly 0..n (n = `n_fields`,
/// consecutive uints) and whose key 0 is the text `type_tag` (§6.2), and returns
/// the field values indexed by key. Errors are `CborError::Schema` with a short
/// message (not a map, wrong type tag, missing key, unknown key).
pub fn record_fields<'a>(
    v: &'a Value,
    type_tag: &str,
    n_fields: usize,
) -> Result<Vec<&'a Value>, CborError> {
    let entries = v.as_map().map_err(|_| schema("record is not a map"))?;
    let mut fields: Vec<Option<&Value>> = vec![None; n_fields];
    for (k, val) in entries {
        let Value::Uint(key) = k else {
            return Err(schema("record key is not a uint"));
        };
        let slot = usize::try_from(*key)
            .ok()
            .filter(|&i| i < n_fields)
            .ok_or_else(|| schema("unknown record key"))?;
        if fields[slot].replace(val).is_some() {
            return Err(schema("duplicate record key"));
        }
    }
    let fields: Vec<&Value> = fields
        .into_iter()
        .map(|f| f.ok_or_else(|| schema("missing record key")))
        .collect::<Result<_, _>>()?;
    if fields[0].as_text() != Ok(type_tag) {
        return Err(schema("wrong record type tag"));
    }
    Ok(fields)
}

/// Like [`record_fields`], but keys in `optional` may be absent. Required keys
/// are `0..n_required` (key 0 is the type tag). Returns one entry per key
/// `0..=max_key`, where `max_key` is the larger of `n_required - 1` and the
/// largest optional key; absent optional keys and gaps are `None`. Any other
/// key is rejected with a schema error.
///
/// Panics if `n_required` is 0 (every record has a type tag).
pub fn record_fields_opt<'a>(
    v: &'a Value,
    type_tag: &str,
    n_required: usize,
    optional: &[u64],
) -> Result<Vec<Option<&'a Value>>, CborError> {
    assert!(n_required >= 1, "a record has at least its type tag");
    let entries = v.as_map().map_err(|_| schema("record is not a map"))?;
    let len = optional
        .iter()
        .map(|&k| k as usize + 1)
        .max()
        .unwrap_or(0)
        .max(n_required);
    let mut slots: Vec<Option<&Value>> = vec![None; len];
    for (k, val) in entries {
        let Value::Uint(key) = k else {
            return Err(schema("record key is not a uint"));
        };
        let slot = usize::try_from(*key)
            .ok()
            .filter(|&i| i < n_required || optional.contains(&(i as u64)))
            .ok_or_else(|| schema("unknown record key"))?;
        if slots[slot].replace(val).is_some() {
            return Err(schema("duplicate record key"));
        }
    }
    if slots[..n_required].iter().any(Option::is_none) {
        return Err(schema("missing record key"));
    }
    if slots[0].and_then(|t| t.as_text().ok()) != Some(type_tag) {
        return Err(schema("wrong record type tag"));
    }
    Ok(slots)
}

#[cfg(test)]
mod record_fields_tests {
    use super::*;

    fn record(tag: &str, extra: Option<(u64, Value)>, skip: Option<u64>) -> Value {
        let mut entries = vec![
            (Value::Uint(0), Value::from(tag)),
            (Value::Uint(1), Value::Uint(5)),
            (Value::Uint(2), Value::from(vec![0u8])),
        ];
        if let Some(k) = skip {
            entries.retain(|(key, _)| *key != Value::Uint(k));
        }
        if let Some((k, v)) = extra {
            entries.push((Value::Uint(k), v));
        }
        Value::Map(entries)
    }

    #[test]
    fn accepts_exact_record() {
        let v = record("t", None, None);
        let fields = record_fields(&v, "t", 3).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[1], &Value::Uint(5));
        assert_eq!(fields[2], &Value::from(vec![0u8]));
    }

    #[test]
    fn rejects_wrong_tag() {
        let v = record("u", None, None);
        assert!(matches!(
            record_fields(&v, "t", 3),
            Err(CborError::Schema(_))
        ));
    }

    #[test]
    fn rejects_missing_key() {
        let v = record("t", None, Some(2));
        assert!(matches!(
            record_fields(&v, "t", 3),
            Err(CborError::Schema(_))
        ));
    }

    #[test]
    fn rejects_extra_key() {
        let v = record("t", Some((3, Value::Uint(0))), None);
        assert!(matches!(
            record_fields(&v, "t", 3),
            Err(CborError::Schema(_))
        ));
    }

    #[test]
    fn rejects_non_uint_key() {
        let mut v = record("t", None, None);
        if let Value::Map(entries) = &mut v {
            entries.push((Value::from("x"), Value::Uint(0)));
        }
        assert!(matches!(
            record_fields(&v, "t", 3),
            Err(CborError::Schema(_))
        ));
    }

    #[test]
    fn rejects_non_map() {
        assert!(matches!(
            record_fields(&Value::Uint(0), "t", 3),
            Err(CborError::Schema(_))
        ));
    }
}

#[cfg(test)]
mod record_fields_opt_tests {
    use super::*;

    /// Record "t" with required keys 1 and 2 and the given extra entries.
    fn record(extra: Vec<(Value, Value)>) -> Value {
        let mut entries = vec![
            (Value::Uint(0), Value::from("t")),
            (Value::Uint(1), Value::Uint(5)),
            (Value::Uint(2), Value::from(vec![0u8])),
        ];
        entries.extend(extra);
        Value::Map(entries)
    }

    #[test]
    fn absent_optional_keys_are_none() {
        let v = record(vec![]);
        let f = record_fields_opt(&v, "t", 3, &[3, 5]).unwrap();
        assert_eq!(f.len(), 6);
        assert_eq!(f[1], Some(&Value::Uint(5)));
        assert_eq!(f[2], Some(&Value::from(vec![0u8])));
        assert_eq!(f[3], None);
        assert_eq!(f[4], None);
        assert_eq!(f[5], None);
    }

    #[test]
    fn present_optional_keys_are_some() {
        let v = record(vec![
            (Value::Uint(3), Value::Bool(true)),
            (Value::Uint(5), Value::Uint(9)),
        ]);
        let f = record_fields_opt(&v, "t", 3, &[3, 5]).unwrap();
        assert_eq!(f[3], Some(&Value::Bool(true)));
        assert_eq!(f[4], None);
        assert_eq!(f[5], Some(&Value::Uint(9)));
    }

    #[test]
    fn length_is_at_least_required_count() {
        let v = record(vec![]);
        let f = record_fields_opt(&v, "t", 3, &[]).unwrap();
        assert_eq!(f.len(), 3);
    }

    #[test]
    fn rejects_missing_required_key() {
        let mut v = record(vec![]);
        if let Value::Map(entries) = &mut v {
            entries.retain(|(k, _)| *k != Value::Uint(2));
        }
        assert!(matches!(
            record_fields_opt(&v, "t", 3, &[3]),
            Err(CborError::Schema(_))
        ));
    }

    #[test]
    fn rejects_unknown_key() {
        // Key 4 is neither required nor optional.
        let v = record(vec![(Value::Uint(4), Value::Uint(0))]);
        assert!(matches!(
            record_fields_opt(&v, "t", 3, &[3]),
            Err(CborError::Schema(_))
        ));
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut v = record(vec![]);
        if let Value::Map(entries) = &mut v {
            entries[0].1 = Value::from("u");
        }
        assert!(matches!(
            record_fields_opt(&v, "t", 3, &[3]),
            Err(CborError::Schema(_))
        ));
    }

    #[test]
    fn rejects_duplicate_key() {
        let v = record(vec![(Value::Uint(1), Value::Uint(6))]);
        assert!(matches!(
            record_fields_opt(&v, "t", 3, &[]),
            Err(CborError::Schema(_))
        ));
    }

    #[test]
    fn rejects_non_uint_key_and_non_map() {
        let v = record(vec![(Value::from("x"), Value::Uint(0))]);
        assert!(matches!(
            record_fields_opt(&v, "t", 3, &[3]),
            Err(CborError::Schema(_))
        ));
        assert!(matches!(
            record_fields_opt(&Value::Uint(0), "t", 3, &[3]),
            Err(CborError::Schema(_))
        ));
    }
}
