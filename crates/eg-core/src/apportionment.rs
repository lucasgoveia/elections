//! Seat apportionment (SPEC.md §22): party totals, lists, and the `dhondt`
//! and `brazil-2021` rules.
//!
//! Everything is integer arithmetic. Fractions are compared by cross-multiplying
//! in `u128`, and thresholds are tested as `votes · 10000 ≥ bp · QE` (§22.3).

use std::cmp::{Ordering, Reverse};

use crate::cbor::{self, CborError, Value};
use crate::error::Error;
use crate::manifest::{
    record, schema, ApportionmentRule, BallotOption, Contest, ContestKind, Manifest, OptionKind,
};

/// A list (§22.1, §22.4): a federation, or a party in no federation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    /// Position in the §22.4 order.
    pub index: u64,
    /// Party indices in the list.
    pub parties: Vec<u64>,
    /// `list_total` (§22.1).
    pub total: u64,
    /// Candidate option indices of this list, in option order.
    pub candidates: Vec<u64>,
}

/// Outcome of apportionment for one proportional contest (`seat_allocation`, §22.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeatAllocation {
    /// Rule name: `"dhondt"` or `"brazil-2021"`.
    pub rule: String,
    /// Seats won by every list, as `(list index, seats)`, in list order.
    pub seats_per_list: Vec<(u64, u64)>,
    /// Elected candidate option indices, in award order.
    pub elected: Vec<u64>,
    /// Electoral quotient (brazil rule only).
    pub qe: Option<u64>,
    /// Seats left unfilled (not encoded; derived from the contest's seats).
    pub unfilled: u64,
}

impl SeatAllocation {
    /// Encodes the allocation as the CDDL `seat_allocation` map (§22.3).
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            (0, Value::from("seats")),
            (1, Value::from(self.rule.as_str())),
            (
                2,
                Value::Array(
                    self.seats_per_list
                        .iter()
                        .map(|&(l, s)| Value::Array(vec![Value::Uint(l), Value::Uint(s)]))
                        .collect(),
                ),
            ),
            (
                3,
                Value::Array(self.elected.iter().map(|&c| Value::Uint(c)).collect()),
            ),
        ];
        if let Some(qe) = self.qe {
            entries.push((4, Value::Uint(qe)));
        }
        record(entries)
    }

    /// Decodes a `seat_allocation` for a contest with `seats` seats. `unfilled`
    /// is derived as `seats − elected.len()`, since it is not encoded.
    ///
    /// Rejects more elected candidates than seats, and seats per list that do not
    /// add up to the elected count. The CDDL `[+ uint]` for `elected` is relaxed
    /// to `[* uint]`, because a zero-award result (no valid votes) must still
    /// round-trip.
    pub fn from_value(v: &Value, seats: u64) -> Result<Self, Error> {
        let f = cbor::record_fields_opt(v, "seats", 4, &[4])?;
        let rule = f[1]
            .ok_or_else(|| schema("seat_allocation has no rule"))?
            .as_text()?;
        if rule != "dhondt" && rule != "brazil-2021" {
            return Err(schema("unknown seat_allocation rule"));
        }
        let seats_per_list = f[2]
            .ok_or_else(|| schema("seat_allocation has no list seats"))?
            .as_array()?
            .iter()
            .map(|pair| match pair.as_array()? {
                [list, won] => Ok((list.as_uint()?, won.as_uint()?)),
                _ => Err(schema("list seats must be a [list, seats] pair")),
            })
            .collect::<Result<Vec<(u64, u64)>, Error>>()?;
        let elected = f[3]
            .ok_or_else(|| schema("seat_allocation has no elected candidates"))?
            .as_array()?
            .iter()
            .map(Value::as_uint)
            .collect::<Result<Vec<u64>, CborError>>()?;
        let qe = f[4].map(Value::as_uint).transpose()?;

        let n = elected.len() as u64;
        if n > seats {
            return Err(tally(format!("{n} elected candidates for {seats} seats")));
        }
        let won: u64 = seats_per_list.iter().map(|&(_, s)| s).sum();
        if won != n {
            return Err(tally("seats per list do not sum to the elected count"));
        }
        Ok(SeatAllocation {
            rule: rule.to_owned(),
            seats_per_list,
            elected,
            qe,
            unfilled: seats - n,
        })
    }
}

fn tally(msg: impl Into<String>) -> Error {
    Error::Tally(msg.into())
}

fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b)
        .ok_or_else(|| tally("vote total overflows u64"))
}

/// Checks the preconditions shared by every function here: a proportional
/// contest, and one vote count per option.
fn check_contest(contest: &Contest, votes: &[u64]) -> Result<(), Error> {
    if contest.kind != ContestKind::Proportional {
        return Err(tally(format!(
            "contest {} is not proportional",
            contest.index
        )));
    }
    if votes.len() != contest.options.len() {
        return Err(tally(format!(
            "contest {}: {} vote counts for {} options",
            contest.index,
            votes.len(),
            contest.options.len()
        )));
    }
    Ok(())
}

fn vote_of(votes: &[u64], opt: &BallotOption) -> Result<u64, Error> {
    votes
        .get(opt.index as usize)
        .copied()
        .ok_or_else(|| tally(format!("option {} has no vote count", opt.index)))
}

/// `party_total(p)` (§22.1) for every party index, `None` for a party with no
/// option in this contest. Blank and null options belong to no party.
fn party_totals_by_index(
    manifest: &Manifest,
    contest: &Contest,
    votes: &[u64],
) -> Result<Vec<Option<u64>>, Error> {
    check_contest(contest, votes)?;
    let mut totals = vec![None; manifest.parties.len()];
    for opt in &contest.options {
        if !matches!(opt.kind, OptionKind::Candidate | OptionKind::Party) {
            continue;
        }
        let p = opt
            .party_index
            .ok_or_else(|| tally(format!("option {} has no party_index", opt.index)))?;
        let slot = totals
            .get_mut(p as usize)
            .ok_or_else(|| tally(format!("option {} names unknown party {p}", opt.index)))?;
        *slot = Some(add(slot.unwrap_or(0), vote_of(votes, opt)?)?);
    }
    Ok(totals)
}

/// `party_total(p)` for each party used in the contest (§22.1), as
/// `(party index, total)` in ascending party index.
pub fn party_totals(
    manifest: &Manifest,
    contest: &Contest,
    votes: &[u64],
) -> Result<Vec<(u64, u64)>, Error> {
    let totals = party_totals_by_index(manifest, contest, votes)?;
    Ok(totals
        .into_iter()
        .enumerate()
        .filter_map(|(p, t)| t.map(|t| (p as u64, t)))
        .collect())
}

/// The lists of the contest (§22.1, §22.4): federations first in manifest order,
/// then the parties in no federation in manifest order. Each list's total is the
/// sum of its parties' totals, and its candidates are the candidate options of
/// those parties.
pub fn lists(manifest: &Manifest, contest: &Contest, votes: &[u64]) -> Result<Vec<List>, Error> {
    let totals = party_totals_by_index(manifest, contest, votes)?;

    let mut in_federation = vec![false; manifest.parties.len()];
    let mut groups: Vec<Vec<u64>> = Vec::new();
    for f in &manifest.federations {
        for &p in &f.parties {
            let slot = in_federation
                .get_mut(p as usize)
                .ok_or_else(|| tally(format!("federation {} names unknown party {p}", f.index)))?;
            *slot = true;
        }
        groups.push(f.parties.clone());
    }
    for (p, &federated) in in_federation.iter().enumerate() {
        if !federated {
            groups.push(vec![p as u64]);
        }
    }

    let mut out = Vec::with_capacity(groups.len());
    for parties in groups {
        let mut total = 0u64;
        for &p in &parties {
            total = add(total, totals[p as usize].unwrap_or(0))?;
        }
        let candidates = contest
            .options
            .iter()
            .filter(|o| {
                o.kind == OptionKind::Candidate
                    && o.party_index.is_some_and(|p| parties.contains(&p))
            })
            .map(|o| o.index)
            .collect();
        out.push(List {
            index: out.len() as u64,
            parties,
            total,
            candidates,
        });
    }
    Ok(out)
}

/// Electoral quotient QE (§22.3 step 1): `q = V div seats`, plus one when
/// `2·rem > seats`.
fn electoral_quotient(v: u64, seats: u64) -> u64 {
    let q = v / seats;
    if 2 * u128::from(v % seats) > u128::from(seats) {
        q + 1
    } else {
        q
    }
}

/// A candidate with its vote count, tiebreak rank and list.
struct Cand {
    option: u64,
    votes: u64,
    rank: u64,
    list: usize,
}

/// Seat-awarding state shared by both rules.
struct Pool<'a> {
    lists: &'a [List],
    cands: Vec<Cand>,
    /// Per list: candidate indices (into `cands`), by votes descending then rank ascending.
    order: Vec<Vec<usize>>,
    /// Per list: lowest tiebreak rank among its candidates (§22.5).
    min_rank: Vec<u64>,
    seated: Vec<bool>,
    won: Vec<u64>,
    elected: Vec<u64>,
    seats: u64,
}

impl<'a> Pool<'a> {
    fn new(lists: &'a [List], contest: &Contest, votes: &[u64], seats: u64) -> Result<Self, Error> {
        let mut cands = Vec::new();
        for opt in contest
            .options
            .iter()
            .filter(|o| o.kind == OptionKind::Candidate)
        {
            let rank = opt.tiebreak_rank.ok_or_else(|| {
                tally(format!(
                    "candidate {} has no tiebreak_rank (§22.5)",
                    opt.index
                ))
            })?;
            let list = lists
                .iter()
                .position(|l| l.candidates.contains(&opt.index))
                .ok_or_else(|| tally(format!("candidate {} is in no list", opt.index)))?;
            cands.push(Cand {
                option: opt.index,
                votes: vote_of(votes, opt)?,
                rank,
                list,
            });
        }

        let mut order: Vec<Vec<usize>> = vec![Vec::new(); lists.len()];
        for (c, cand) in cands.iter().enumerate() {
            order[cand.list].push(c);
        }
        for idx in &mut order {
            idx.sort_by_key(|&c| (Reverse(cands[c].votes), cands[c].rank));
        }
        let min_rank: Vec<u64> = order
            .iter()
            .map(|idx| idx.iter().map(|&c| cands[c].rank).min().unwrap_or(u64::MAX))
            .collect();

        let n = cands.len();
        Ok(Pool {
            lists,
            cands,
            order,
            min_rank,
            seated: vec![false; n],
            won: vec![0; lists.len()],
            elected: Vec::new(),
            seats,
        })
    }

    fn remaining(&self) -> u64 {
        self.seats - self.elected.len() as u64
    }

    fn seat(&mut self, l: usize, c: usize) {
        self.seated[c] = true;
        self.won[l] += 1;
        self.elected.push(self.cands[c].option);
    }

    /// Whether list `a` beats list `b` for the next seat (§22.2 step 2, §22.5):
    /// higher `total/(won+1)` wins; then higher `list_total`; then the list whose
    /// best-ranked candidate has the lower tiebreak rank.
    fn prefers(&self, a: usize, b: usize) -> bool {
        let (ta, tb) = (self.lists[a].total as u128, self.lists[b].total as u128);
        let (wa, wb) = (self.won[a] as u128 + 1, self.won[b] as u128 + 1);
        // ta/wa > tb/wb  <=>  ta·wb > tb·wa
        let ord = (ta * wb)
            .cmp(&(tb * wa))
            .then(self.lists[a].total.cmp(&self.lists[b].total))
            .then(self.min_rank[b].cmp(&self.min_rank[a]));
        ord == Ordering::Greater || (ord == Ordering::Equal && a < b)
    }

    /// The best next seat: among lists passing `list_ok` with an unseated
    /// candidate passing `cand_ok`, the preferred list and its first such
    /// candidate in vote order.
    fn best(
        &self,
        list_ok: impl Fn(usize) -> bool,
        cand_ok: impl Fn(&Cand) -> bool,
    ) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;
        for (l, order) in self.order.iter().enumerate() {
            if !list_ok(l) {
                continue;
            }
            let Some(&c) = order
                .iter()
                .find(|&&c| !self.seated[c] && cand_ok(&self.cands[c]))
            else {
                continue;
            };
            let better = match best {
                None => true,
                Some((bl, _)) => self.prefers(l, bl),
            };
            if better {
                best = Some((l, c));
            }
        }
        best
    }

    /// Highest averages (§22.2 step 2, §22.3 steps 5–6): awards seats one at a
    /// time until none remain or no eligible seat is left.
    fn by_averages(&mut self, list_ok: impl Fn(usize) -> bool, cand_ok: impl Fn(&Cand) -> bool) {
        while self.remaining() > 0 {
            let Some((l, c)) = self.best(&list_ok, &cand_ok) else {
                break;
            };
            self.seat(l, c);
        }
    }

    /// Step 2 of §22.3 (and the QE = 0 guard): the most-voted candidates
    /// regardless of list, ties by tiebreak rank.
    fn most_voted(&mut self) {
        let mut idx: Vec<usize> = (0..self.cands.len()).collect();
        idx.sort_by_key(|&c| (Reverse(self.cands[c].votes), self.cands[c].rank));
        for c in idx {
            if self.remaining() == 0 {
                break;
            }
            let l = self.cands[c].list;
            self.seat(l, c);
        }
    }

    /// §22.2 `dhondt`: lists below the threshold are excluded, then highest averages.
    fn dhondt(&mut self, threshold_bp: Option<u64>, v: u64) {
        let lists = self.lists;
        self.by_averages(
            |l| match threshold_bp {
                None => true,
                Some(bp) => (lists[l].total as u128) * 10_000 >= (bp as u128) * (v as u128),
            },
            |_| true,
        );
    }
}

/// §22.3 `brazil-2021`, steps 2–6. Step 1 (the quotient) is computed by the caller.
///
/// Spec gap: when QE = 0 (V < seats/2 roughly), step 3 divides by zero, so the
/// step-2 path is used instead (most-voted candidates regardless of list).
fn brazil(
    pool: &mut Pool<'_>,
    qe: u64,
    cand_quotient_bp: u64,
    list_remainder_bp: u64,
    cand_remainder_bp: u64,
    final_phase_open: bool,
) {
    let lists = pool.lists;
    if qe == 0 || !lists.iter().any(|l| l.total >= qe) {
        pool.most_voted();
        return;
    }
    let qe128 = qe as u128;
    // votes · 10000 ≥ bp · QE
    let reaches = |bp: u64, votes: u64| (votes as u128) * 10_000 >= (bp as u128) * qe128;

    // Steps 3–4: QP(F) = list_total div QE quotient seats per list, from its
    // candidates with at least the candidate minimum. Unused places fall into
    // the remainder pool, which is simply the seats still unfilled after this.
    // Spec gap: Σ QP can exceed `seats` when QE is rounded down to a small
    // value (e.g. V=4, seats=3, QE=1); awards then stop at `seats`, in list order.
    for (l, list) in lists.iter().enumerate() {
        for _ in 0..list.total / qe {
            if pool.remaining() == 0 {
                break;
            }
            let found = pool.order[l]
                .iter()
                .copied()
                .find(|&c| !pool.seated[c] && reaches(cand_quotient_bp, pool.cands[c].votes));
            let Some(c) = found else {
                break;
            };
            pool.seat(l, c);
        }
    }

    // Step 5: remainder seats by highest averages, with list and candidate minimums.
    pool.by_averages(
        |l| reaches(list_remainder_bp, lists[l].total),
        |c| reaches(cand_remainder_bp, c.votes),
    );

    // Step 6: final phase, if seats remain.
    if pool.remaining() > 0 {
        if final_phase_open {
            pool.by_averages(|_| true, |_| true);
        } else {
            pool.by_averages(|l| lists[l].total >= qe, |_| true);
        }
    }
}

/// Runs the contest's apportionment rule (§22.2, §22.3) on the votes.
///
/// Errors with `Error::Tally` if the contest is not proportional, the vote count
/// does not match the options, a candidate lacks a tiebreak rank, or the contest
/// has no rule or no seats. With zero valid votes (V = 0) no seats are awarded
/// for either rule. The spec is silent on this case, so this is a decision.
pub fn apportion(
    manifest: &Manifest,
    contest: &Contest,
    votes: &[u64],
) -> Result<SeatAllocation, Error> {
    let lists = lists(manifest, contest, votes)?;
    let rule = contest.apportionment.as_ref().ok_or_else(|| {
        tally(format!(
            "contest {} has no apportionment rule",
            contest.index
        ))
    })?;
    let seats = contest
        .seats
        .ok_or_else(|| tally(format!("contest {} has no seats", contest.index)))?;
    if seats == 0 {
        return Err(tally(format!("contest {} has zero seats", contest.index)));
    }
    let v = lists.iter().try_fold(0u64, |acc, l| add(acc, l.total))?;

    let mut pool = Pool::new(&lists, contest, votes, seats)?;
    let (name, qe) = match *rule {
        ApportionmentRule::Dhondt { threshold_bp } => {
            if v > 0 {
                pool.dhondt(threshold_bp, v);
            }
            ("dhondt", None)
        }
        ApportionmentRule::Brazil2021 {
            cand_min_quotient_bp,
            list_min_remainder_bp,
            cand_min_remainder_bp,
            final_phase_open,
        } => {
            let qe = electoral_quotient(v, seats);
            if v > 0 {
                brazil(
                    &mut pool,
                    qe,
                    cand_min_quotient_bp,
                    list_min_remainder_bp,
                    cand_min_remainder_bp,
                    final_phase_open,
                );
            }
            ("brazil-2021", Some(qe))
        }
    };

    let unfilled = pool.remaining();
    let seats_per_list = lists
        .iter()
        .enumerate()
        .map(|(i, l)| (l.index, pool.won[i]))
        .collect();
    Ok(SeatAllocation {
        rule: name.to_owned(),
        seats_per_list,
        elected: pool.elected,
        qe,
        unfilled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::sample_manifest;
    use crate::manifest::{Federation, Method, Party};

    fn dhondt_rule(threshold_bp: Option<u64>) -> ApportionmentRule {
        ApportionmentRule::Dhondt { threshold_bp }
    }

    fn brazil_rule(final_phase_open: bool) -> ApportionmentRule {
        ApportionmentRule::Brazil2021 {
            cand_min_quotient_bp: 1000,
            list_min_remainder_bp: 8000,
            cand_min_remainder_bp: 2000,
            final_phase_open,
        }
    }

    /// A manifest with one proportional contest (index 0). Option i < cands.len()
    /// is candidate i with `(party, tiebreak_rank)`. Then one party option per
    /// party, then blank and null. Parties 0..n_parties have no names of note.
    fn election(
        n_parties: u64,
        cands: &[(u64, u64)],
        federations: &[&[u64]],
        rule: ApportionmentRule,
        seats: u64,
    ) -> Manifest {
        let (mut m, _) = sample_manifest(7);
        let n = cands.len() as u64;
        let mut options: Vec<BallotOption> = cands
            .iter()
            .enumerate()
            .map(|(i, &(party, rank))| BallotOption {
                index: i as u64,
                name: format!("Cand{i}"),
                kind: OptionKind::Candidate,
                number: None,
                party_index: Some(party),
                tiebreak_rank: Some(rank),
            })
            .collect();
        for p in 0..n_parties {
            options.push(BallotOption {
                index: n + p,
                name: format!("Party{p}"),
                kind: OptionKind::Party,
                number: None,
                party_index: Some(p),
                tiebreak_rank: None,
            });
        }
        let blank = n + n_parties;
        options.push(BallotOption {
            index: blank,
            name: "Branco".to_owned(),
            kind: OptionKind::Blank,
            number: None,
            party_index: None,
            tiebreak_rank: None,
        });
        options.push(BallotOption {
            index: blank + 1,
            name: "Nulo".to_owned(),
            kind: OptionKind::Null,
            number: None,
            party_index: None,
            tiebreak_rank: None,
        });
        m.contests = vec![Contest {
            index: 0,
            name: "Deputado".to_owned(),
            kind: ContestKind::Proportional,
            method: Method::Homomorphic,
            limit: 1,
            options,
            apportionment: Some(rule),
            seats: Some(seats),
            regional_mix: false,
        }];
        m.parties = (0..n_parties)
            .map(|p| Party {
                index: p,
                name: format!("Party{p}"),
                number: format!("{}", p + 10),
                key: None,
            })
            .collect();
        m.federations = federations
            .iter()
            .enumerate()
            .map(|(i, ps)| Federation {
                index: i as u64,
                name: format!("Fed{i}"),
                parties: ps.to_vec(),
            })
            .collect();
        m
    }

    /// Vote vector in option order: candidates, party options, blank, null.
    fn votes(cands: &[u64], parties: &[u64], blank: u64, null: u64) -> Vec<u64> {
        let mut v = cands.to_vec();
        v.extend_from_slice(parties);
        v.push(blank);
        v.push(null);
        v
    }

    fn run(m: &Manifest, votes: &[u64]) -> SeatAllocation {
        apportion(m, &m.contests[0], votes).expect("apportion")
    }

    #[test]
    fn fixture_party_totals_and_lists_without_federation() {
        // Options: Dora 0 (P0), Edu 1 (P0), Fabi 2 (P1), Gil 3 (P1), Partido Azul 4 (P0),
        // Partido Verde 5 (P1), Branco 6, Nulo 7.
        let m = sample_manifest(1).0;
        let contest = &m.contests[2];
        let v = [10, 20, 5, 7, 3, 4, 1, 2];
        // P0 = 10 + 20 + 3 = 33; P1 = 5 + 7 + 4 = 16. Blank and null are excluded.
        assert_eq!(
            party_totals(&m, contest, &v).unwrap(),
            vec![(0, 33), (1, 16)]
        );
        let l = lists(&m, contest, &v).unwrap();
        assert_eq!(
            l,
            vec![
                List {
                    index: 0,
                    parties: vec![0],
                    total: 33,
                    candidates: vec![0, 1],
                },
                List {
                    index: 1,
                    parties: vec![1],
                    total: 16,
                    candidates: vec![2, 3],
                },
            ]
        );
    }

    #[test]
    fn federations_come_first_and_absorb_their_parties() {
        let mut m = sample_manifest(1).0;
        let v = [10, 20, 5, 7, 3, 4, 1, 2];
        // Federation of P1 only: it is list 0, the unfederated P0 is list 1.
        m.federations = vec![Federation {
            index: 0,
            name: "F".to_owned(),
            parties: vec![1],
        }];
        let l = lists(&m, &m.contests[2], &v).unwrap();
        assert_eq!(l[0].parties, vec![1]);
        assert_eq!((l[0].index, l[0].total), (0, 16));
        assert_eq!(l[0].candidates, vec![2, 3]);
        assert_eq!(l[1].parties, vec![0]);
        assert_eq!((l[1].index, l[1].total), (1, 33));

        // Federation of both parties: one list of 49 votes with all four candidates.
        m.federations[0].parties = vec![0, 1];
        let l = lists(&m, &m.contests[2], &v).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].total, 49);
        assert_eq!(l[0].candidates, vec![0, 1, 2, 3]);
        // Party totals are unaffected by federations.
        assert_eq!(
            party_totals(&m, &m.contests[2], &v).unwrap(),
            vec![(0, 33), (1, 16)]
        );
    }

    #[test]
    fn dhondt_textbook_example() {
        // Lists with 100000, 80000, 30000 and 20000 votes, 8 seats (the Wikipedia
        // example). The quotients in descending order are 100000 (A), 80000 (B),
        // 50000 (A), 40000 (B), 33333 (A), 30000 (C), 26667 (B), 25000 (A), so the
        // seats go 4, 3, 1, 0. Each list has 8 candidates with 0 votes.
        let cands: Vec<(u64, u64)> = (0..4u64)
            .flat_map(|p| (0..8u64).map(move |i| (p, p * 8 + i + 1)))
            .collect();
        let m = election(4, &cands, &[], dhondt_rule(None), 8);
        let v = votes(&vec![0; 32], &[100_000, 80_000, 30_000, 20_000], 0, 0);
        let a = run(&m, &v);
        assert_eq!(a.seats_per_list, vec![(0, 4), (1, 3), (2, 1), (3, 0)]);
        assert_eq!(a.elected.len(), 8);
        assert_eq!(a.unfilled, 0);
        assert_eq!(a.qe, None);
    }

    #[test]
    fn dhondt_threshold_excludes_small_list() {
        // P0 = 48 (one candidate, rank 1), P1 = 48 (one candidate, rank 2),
        // P2 = 4 (three candidates). V = 100, 3 seats.
        // Without threshold: seat 1 is a tie 48 vs 48, broken by rank to P0.
        // Seat 2 goes to P1 (48/1). Seat 3: P0 and P1 have no candidates left,
        // so P2 gets it (4/1). Result 1, 1, 1.
        // With a 5% threshold (500 bp): P2 has 4·10000 = 40000 < 500·100 = 50000,
        // so it is excluded. Result 1, 1, 0 with one unfilled seat.
        let cands = [(0, 1), (1, 2), (2, 3), (2, 4), (2, 5)];
        let v = votes(&[0; 5], &[48, 48, 4], 0, 0);

        let open = election(3, &cands, &[], dhondt_rule(None), 3);
        let a = run(&open, &v);
        assert_eq!(a.seats_per_list, vec![(0, 1), (1, 1), (2, 1)]);
        assert_eq!(a.unfilled, 0);

        let thresh = election(3, &cands, &[], dhondt_rule(Some(500)), 3);
        let a = run(&thresh, &v);
        assert_eq!(a.seats_per_list, vec![(0, 1), (1, 1), (2, 0)]);
        assert_eq!(a.unfilled, 1);
    }

    #[test]
    fn dhondt_unfilled_seats_when_lists_run_out() {
        // Two lists with one candidate each, 3 seats: 2 elected, 1 unfilled.
        let m = election(2, &[(0, 1), (1, 2)], &[], dhondt_rule(None), 3);
        let a = run(&m, &votes(&[0, 0], &[10, 5], 0, 0));
        assert_eq!(a.elected, vec![0, 1]);
        assert_eq!(a.seats_per_list, vec![(0, 1), (1, 1)]);
        assert_eq!(a.unfilled, 1);
    }

    #[test]
    fn electoral_quotient_rounding() {
        // V=1000, 3 seats: q=333, rem=1, 2 ≤ 3, so QE=333.
        assert_eq!(electoral_quotient(1000, 3), 333);
        // V=1001, 3 seats: q=333, rem=2, 4 > 3, so QE=334.
        assert_eq!(electoral_quotient(1001, 3), 334);
        // V=1002, 4 seats: rem=2, 4 ≤ 4 (the half is dropped), so QE=250.
        assert_eq!(electoral_quotient(1002, 4), 250);
        // V=1003, 4 seats: rem=3, 6 > 4, so QE=251.
        assert_eq!(electoral_quotient(1003, 4), 251);
        assert_eq!(electoral_quotient(0, 3), 0);
    }

    #[test]
    fn brazil_quotient_seats_need_candidate_minimum() {
        // Candidates A=60, B=2, C=8 (P0, total 70) and D=30 (P1). V=100, 3 seats.
        // QE = 33 (q=33, rem=1). Candidate minimum 10% of QE = 3.3 votes.
        // QP(P0) = 70 div 33 = 2. Eligible for quotient seats: A (60) and C (8);
        // B (2) is below the minimum. So A and C take P0's two quotient seats.
        // QP(P1) = 0. Remainder: 1 seat left. P0 has no unseated candidate with
        // ≥ 6.6 votes (20% of QE), so P1 is the only eligible list and D takes it.
        // Expected: elected [A, C, D], seats P0 = 2, P1 = 1. B is never elected.
        let m = election(
            2,
            &[(0, 1), (0, 2), (0, 3), (1, 4)],
            &[],
            brazil_rule(true),
            3,
        );
        let a = run(&m, &votes(&[60, 2, 8, 30], &[0, 0], 0, 0));
        assert_eq!(a.qe, Some(33));
        assert_eq!(a.elected, vec![0, 2, 3]);
        assert_eq!(a.seats_per_list, vec![(0, 2), (1, 1)]);
        assert_eq!(a.unfilled, 0);
    }

    #[test]
    fn brazil_unused_quotient_place_goes_to_remainder_pool() {
        // A=60, B=2 (P0, with party option 8, total 70), D=30 (P1). V=100, 3 seats, QE=33.
        // QP(P0) = 2, but only A is eligible (B < 3.3), so one quotient place is
        // unused and joins the remainder pool. Remaining seats = 2.
        // Step 5: P0 has no eligible unseated candidate (B). P1 (30 ≥ 26.4)
        // with D (30 ≥ 6.6) gets the seat. One seat remains.
        // Step 5 again: no eligible list.
        // Step 6: with final phase open to all, or limited to lists ≥ QE (70 ≥ 33),
        // P0's B is the only candidate left, so B gets it either way.
        // Expected: elected [A, D, B], seats P0 = 2, P1 = 1, for both values of param 4.
        for open in [true, false] {
            let m = election(2, &[(0, 1), (0, 2), (1, 4)], &[], brazil_rule(open), 3);
            let a = run(&m, &votes(&[60, 2, 30], &[8, 0], 0, 0));
            assert_eq!(a.elected, vec![0, 2, 1], "open={open}");
            assert_eq!(a.seats_per_list, vec![(0, 2), (1, 1)], "open={open}");
            assert_eq!(a.unfilled, 0);
        }
    }

    #[test]
    fn brazil_remainder_seats_need_list_minimum_and_final_phase_param() {
        // P0 = A60 + B40 = 100 (two candidates). P1 = C65 (one candidate).
        // P2 = 5 (party option) + D30 = 35. V = 200, 4 seats, QE = 50 (rem 0).
        // Quotient: QP(P0) = 2 → A, B. QP(P1) = 1 → C. QP(P2) = 0. One seat remains.
        // Step 5: list minimum 80% of QE = 40. P2 has 35 < 40, so it is ineligible.
        // P0 and P1 have no unseated candidates. No eligible list, so step 6.
        //   param 4 = false: only lists with total ≥ QE = 50. P2 is below it, so
        //     the seat stays unfilled. Expected: elected [A, B, C], unfilled 1.
        //   param 4 = true: every list and every candidate. D gets it.
        //     Expected: elected [A, B, C, D], seats P0 = 2, P1 = 1, P2 = 1.
        let cands = [(0, 1), (0, 2), (1, 3), (2, 4)];
        let v = votes(&[60, 40, 65, 30], &[0, 0, 5], 0, 0);

        let closed = run(&election(3, &cands, &[], brazil_rule(false), 4), &v);
        assert_eq!(closed.qe, Some(50));
        assert_eq!(closed.elected, vec![0, 1, 2]);
        assert_eq!(closed.seats_per_list, vec![(0, 2), (1, 1), (2, 0)]);
        assert_eq!(closed.unfilled, 1);

        let open = run(&election(3, &cands, &[], brazil_rule(true), 4), &v);
        assert_eq!(open.elected, vec![0, 1, 2, 3]);
        assert_eq!(open.seats_per_list, vec![(0, 2), (1, 1), (2, 1)]);
        assert_eq!(open.unfilled, 0);
    }

    #[test]
    fn brazil_remainder_seats_need_candidate_minimum() {
        // Same shape as above, but P2 = 40 (party option 32, candidate D = 8).
        // V = 200, QE = 50. Quotient: A, B (P0), C (P1). QP(P2) = 0.
        // Step 5: P2 has 40 ≥ 40 (list minimum met, exactly on the boundary),
        // but D has 8 < 20% of QE = 10, so no eligible candidate.
        // Step 6: param 4 = false leaves the seat unfilled (P2 is below QE).
        // param 4 = true gives it to D.
        let cands = [(0, 1), (0, 2), (1, 3), (2, 4)];
        let v = votes(&[60, 40, 60, 8], &[0, 0, 32], 0, 0);

        let closed = run(&election(3, &cands, &[], brazil_rule(false), 4), &v);
        assert_eq!(closed.elected, vec![0, 1, 2]);
        assert_eq!(closed.unfilled, 1);

        let open = run(&election(3, &cands, &[], brazil_rule(true), 4), &v);
        assert_eq!(open.elected, vec![0, 1, 2, 3]);
        assert_eq!(open.seats_per_list, vec![(0, 2), (1, 1), (2, 1)]);
    }

    #[test]
    fn brazil_no_list_reaches_qe_elects_most_voted_across_lists() {
        // Candidates X=25 (P0), Y=28 (P1), Z=20 (P2), W=18 (P3). Party options 5, 2, 0, 2.
        // List totals: P0 30, P1 30, P2 20, P3 20. V = 100, 3 seats, QE = 33.
        // No list reaches 33, so step 2 applies: the most-voted candidates
        // regardless of list are elected in order Y (28), X (25), Z (20).
        let m = election(
            4,
            &[(0, 1), (1, 2), (2, 3), (3, 4)],
            &[],
            brazil_rule(true),
            3,
        );
        let a = run(&m, &votes(&[25, 28, 20, 18], &[5, 2, 0, 2], 0, 0));
        assert_eq!(a.qe, Some(33));
        assert_eq!(a.elected, vec![1, 0, 2]);
        assert_eq!(a.seats_per_list, vec![(0, 1), (1, 1), (2, 1), (3, 0)]);
        assert_eq!(a.unfilled, 0);
    }

    #[test]
    fn brazil_qe_zero_uses_most_voted_path() {
        // V = 1, 3 seats: q = 0, rem = 1, 2 ≤ 3, so QE = 0. Dividing by QE is
        // impossible, so step 2 runs. The only candidate is elected and 2 seats
        // stay unfilled.
        let m = election(1, &[(0, 1)], &[], brazil_rule(true), 3);
        let a = run(&m, &votes(&[1], &[0], 0, 0));
        assert_eq!(a.qe, Some(0));
        assert_eq!(a.elected, vec![0]);
        assert_eq!(a.unfilled, 2);
    }

    #[test]
    fn zero_valid_votes_award_no_seats() {
        let m = election(2, &[(0, 1), (1, 2)], &[], brazil_rule(true), 2);
        let a = run(&m, &votes(&[0, 0], &[0, 0], 0, 0));
        assert_eq!(a.elected, Vec::<u64>::new());
        assert_eq!(a.seats_per_list, vec![(0, 0), (1, 0)]);
        assert_eq!(a.unfilled, 2);
        assert_eq!(a.qe, Some(0));

        let m = election(2, &[(0, 1), (1, 2)], &[], dhondt_rule(None), 2);
        let a = run(&m, &votes(&[0, 0], &[0, 0], 0, 0));
        assert_eq!(a.elected, Vec::<u64>::new());
        assert_eq!(a.unfilled, 2);
        assert_eq!(a.qe, None);
    }

    #[test]
    fn list_tie_broken_by_candidate_rank() {
        // P0 and P1 both total 50 with one candidate each. The seat goes to the
        // list whose candidate has the lower rank (P1, rank 1, over P0, rank 2).
        let m = election(2, &[(0, 2), (1, 1)], &[], dhondt_rule(None), 1);
        let a = run(&m, &votes(&[0, 0], &[50, 50], 0, 0));
        assert_eq!(a.seats_per_list, vec![(0, 0), (1, 1)]);
        assert_eq!(a.elected, vec![1]);
    }

    #[test]
    fn list_tie_on_ratio_broken_by_higher_list_total_first() {
        // P0 = X1 (60, rank 5) + X2 (0, rank 6) = 60. P1 = Y (0, rank 1) + 30 = 30.
        // Seat 1: P0 60 > P1 30, so X1. Seat 2: P0 60/2 = 30 ties with P1 30/1 = 30.
        // The higher list_total (P0) wins before the rank tiebreak, even though P1's
        // candidate has rank 1. Expected: X2 elected; seats P0 = 2, P1 = 0.
        let m = election(2, &[(0, 5), (0, 6), (1, 1)], &[], dhondt_rule(None), 2);
        let a = run(&m, &votes(&[60, 0, 0], &[0, 30], 0, 0));
        assert_eq!(a.elected, vec![0, 1]);
        assert_eq!(a.seats_per_list, vec![(0, 2), (1, 0)]);
    }

    #[test]
    fn candidate_tie_broken_by_rank_and_votes_come_first() {
        // Same list, same votes (10 each): lower rank wins, so candidate 1 (rank 3).
        let m = election(1, &[(0, 7), (0, 3)], &[], dhondt_rule(None), 1);
        assert_eq!(run(&m, &votes(&[10, 10], &[0], 0, 0)).elected, vec![1]);
        // More votes beat a lower rank: candidate 0 (11 votes, rank 7).
        assert_eq!(run(&m, &votes(&[11, 10], &[0], 0, 0)).elected, vec![0]);
    }

    #[test]
    fn missing_tiebreak_rank_is_an_error() {
        let mut m = election(1, &[(0, 1)], &[], dhondt_rule(None), 1);
        m.contests[0].options[0].tiebreak_rank = None;
        let r = apportion(&m, &m.contests[0], &votes(&[1], &[0], 0, 0));
        assert!(matches!(r, Err(Error::Tally(_))));
    }

    #[test]
    fn rejects_non_proportional_and_bad_vote_length() {
        let m = sample_manifest(1).0;
        assert!(matches!(
            party_totals(&m, &m.contests[0], &[0; 4]),
            Err(Error::Tally(_))
        ));
        assert!(matches!(
            lists(&m, &m.contests[2], &[1, 2, 3]),
            Err(Error::Tally(_))
        ));
        assert!(matches!(
            apportion(&m, &m.contests[2], &[1, 2, 3]),
            Err(Error::Tally(_))
        ));
    }

    #[test]
    fn seat_allocation_round_trip() {
        let cands = [(0, 1), (0, 2), (1, 3), (2, 4)];
        let v = votes(&[60, 40, 60, 8], &[0, 0, 32], 0, 0);
        let m = election(3, &cands, &[], brazil_rule(true), 4);
        let a = run(&m, &v);
        let decoded = cbor::decode(&cbor::encode(&a.to_value())).unwrap();
        assert_eq!(SeatAllocation::from_value(&decoded, 4).unwrap(), a);

        let m = election(2, &[(0, 1), (1, 2)], &[], dhondt_rule(None), 3);
        let a = run(&m, &votes(&[0, 0], &[10, 5], 0, 0));
        assert_eq!(a.qe, None);
        assert_eq!(a.unfilled, 1);
        let decoded = cbor::decode(&cbor::encode(&a.to_value())).unwrap();
        assert_eq!(SeatAllocation::from_value(&decoded, 3).unwrap(), a);
        // More elected candidates than the contest has seats is rejected.
        assert!(SeatAllocation::from_value(&decoded, 1).is_err());
    }
}
