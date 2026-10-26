// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! Binary diff of two byte sequences into ordered `Match`, `Modified`,
//! `InsertedA` and `InsertedB` regions that partition both inputs.
//!
//! Small inputs are diffed byte by byte with Myers under a time budget; large
//! ones are first split at content-defined anchors both sides share and each
//! segment between anchors is diffed the same way, so no single Myers run
//! exceeds its working-set limit or its deadline.

use std::cmp::Ordering;
use std::collections::HashMap;

use adler2::Adler32;
use std::time::{Duration, Instant};

use similar::{capture_diff_slices_deadline, Algorithm, DiffOp};

/// How a region of the two inputs relates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffType {
    /// The bytes are identical on both sides.
    Match,
    /// Bytes on both sides differ (a substitution, possibly of unequal length).
    Modified,
    /// Bytes present only in A.
    InsertedA,
    /// Bytes present only in B.
    InsertedB,
}

/// One region of an edit script; regions partition both inputs in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRegion {
    /// Start of the region in A.
    pub offset_a: usize,
    /// Start of the region in B.
    pub offset_b: usize,
    /// `max(length_a, length_b)`: the span on the longer side, which for a
    /// folded change region includes the equal bytes folded into it, so it is
    /// not the region's edit cost. Use `length_a`/`length_b` to walk the
    /// inputs, and `DiffResult::total_differences` for the edit cost.
    pub length: usize,
    /// Bytes the region covers in A.
    pub length_a: usize,
    /// Bytes the region covers in B.
    pub length_b: usize,
    /// How the two sides relate.
    pub diff_type: DiffType,
}

/// Shortest equal run kept as its own `Match` region by default: every equal
/// run is at least one byte, so by default nothing is folded away.
pub const DEFAULT_MIN_MATCH: usize = 1;

/// Most regions a comparison stores by default.
///
/// Two 1 MiB inputs that differ at every other byte have about a million
/// regions; as Python dicts and tree rows that would exhaust memory long
/// before it helped anyone, so the list is cut here while the counts stay
/// exact.
pub const DEFAULT_MAX_REGIONS: usize = 100_000;

/// How a comparison groups and bounds its output; neither field changes which
/// bytes are reported as different.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffOptions {
    /// An equal run shorter than this that sits between two changes is folded
    /// into one change region covering both sides. `0` and `1` fold nothing.
    pub min_match: usize,
    /// Most regions stored. Regions past it are still counted but not kept, so
    /// memory stays bounded; `0` keeps none and only counts.
    pub max_regions: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            min_match: DEFAULT_MIN_MATCH,
            max_regions: DEFAULT_MAX_REGIONS,
        }
    }
}

/// A complete comparison of two inputs.
#[derive(Debug)]
pub struct DiffResult {
    /// The first `max_regions` regions, in ascending order on both sides.
    pub regions: Vec<DiffRegion>,
    /// Every region the comparison produced, stored or not.
    pub region_count: usize,
    /// Every non-`Match` region the comparison produced, stored or not.
    pub change_count: usize,
    /// Total edit cost: the sum over the change regions of the larger of their
    /// two differing sides, with any equal runs folded in by `min_match`
    /// excluded, and counted over regions that were not stored too, so it never
    /// depends on either option. This is not the sum of `length`, which for a
    /// folded region counts the folded equal bytes.
    pub total_differences: usize,
    /// `true` exactly when the inputs are byte-identical.
    pub files_identical: bool,
}

impl DiffResult {
    /// `true` when regions were counted but not stored because of `max_regions`.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.region_count > self.regions.len()
    }
}

const BYTE_LEVEL_THRESHOLD: usize = 1_048_576;
const ANCHOR_WINDOW: usize = 1024;
/// Number of top bits of the mixed hash that must all be zero for an anchor,
/// which makes about one window in `2^ANCHOR_BITS` an anchor.
const ANCHOR_BITS: u32 = 10;
/// Odd multiplier of the anchor test.
///
/// The Adler-32 of a window of one constant byte `c` is fixed by `c`, and for
/// a 1024-byte window it never has its low ten bits clear, so a mask on the
/// raw hash can never anchor padding. Multiplying spreads both halves of the
/// hash into the top bits that are tested instead. The constant was found by
/// exhaustive search over the 2^31 odd multipliers for one that anchors the
/// two common padding fills, `0x00` and `0xFF`, and it also anchors every
/// seventh byte value around them; re-derive it if `ANCHOR_WINDOW` changes.
const ANCHOR_MIX: u32 = 0x3439_6133;
const ADLER_MOD: u32 = 65_521;
/// Largest combined length of a differing middle that Myers may diff.
///
/// Myers keeps working vectors of about `len_a + len_b` words, roughly 16
/// bytes per input byte, and Rust aborts the process when such an allocation
/// fails, so a larger middle is reported as one `Modified` region instead, with
/// its shared prefix and suffix still emitted as `Match` regions.
const MYERS_WORKING_SET_LIMIT: usize = 8 * 1024 * 1024;

/// Wall-clock budget for the Myers searches of one comparison.
///
/// Size alone does not predict Myers' cost: a 1 MiB pair differing at every
/// other byte diffs in well under a second, while 256 KiB whose every byte is
/// replaced by a value the other side also contains took ~85 s. Past the
/// deadline `similar` stops searching and reports the unresolved spans as
/// coarse changes, so the regions still partition both inputs and every
/// differing byte is still inside a change region; only the grouping inside
/// those spans becomes approximate. Diffs that finish in time stay byte-exact.
const MYERS_TIME_BUDGET: Duration = Duration::from_secs(5);

/// How much work a segment's Myers search may do: the working-set ceiling and
/// the deadline shared by every segment of one comparison.
#[derive(Debug, Clone, Copy)]
struct MyersBudget {
    working_set: usize,
    deadline: Option<Instant>,
}

/// A span of both inputs, anchored at where it starts on each side.
#[derive(Debug, Clone, Copy)]
struct Span {
    offset_a: usize,
    offset_b: usize,
    len_a: usize,
    len_b: usize,
}

impl Span {
    fn end(self) -> (usize, usize) {
        (self.offset_a + self.len_a, self.offset_b + self.len_b)
    }
}

/// A change region being assembled.
///
/// `span` is everything the region will cover, folded-in equal runs included;
/// the cost of the real differences is kept apart so folding never inflates
/// `total_differences`.
#[derive(Debug, Clone, Copy)]
struct OpenChange {
    span: Span,
    settled_cost: usize,
    run_a: usize,
    run_b: usize,
}

impl OpenChange {
    fn new(offset_a: usize, offset_b: usize, len_a: usize, len_b: usize) -> Self {
        Self {
            span: Span {
                offset_a,
                offset_b,
                len_a,
                len_b,
            },
            settled_cost: 0,
            run_a: len_a,
            run_b: len_b,
        }
    }

    /// Appends a contiguous difference to the run in progress.
    fn extend(&mut self, len_a: usize, len_b: usize) {
        self.span.len_a += len_a;
        self.span.len_b += len_b;
        self.run_a += len_a;
        self.run_b += len_b;
    }

    /// Swallows an equal run: it joins the span but ends the cost run.
    fn fold_match(&mut self, len: usize) {
        self.span.len_a += len;
        self.span.len_b += len;
        self.settled_cost += self.run_a.max(self.run_b);
        self.run_a = 0;
        self.run_b = 0;
    }

    fn cost(self) -> usize {
        self.settled_cost + self.run_a.max(self.run_b)
    }
}

/// Receives the edit script in order and turns it into regions.
///
/// Adjacent equal runs and adjacent changes are merged, so the region list
/// does not depend on where the anchored path happened to cut the inputs, and
/// equal runs shorter than `min_match` between two changes are folded into
/// them. Past `max_regions` it keeps counting but stops storing.
struct RegionSink {
    options: DiffOptions,
    regions: Vec<DiffRegion>,
    region_count: usize,
    change_count: usize,
    total_differences: usize,
    change: Option<OpenChange>,
    gap: Option<Span>,
}

impl RegionSink {
    fn new(options: DiffOptions) -> Self {
        Self {
            options,
            regions: Vec::new(),
            region_count: 0,
            change_count: 0,
            total_differences: 0,
            change: None,
            gap: None,
        }
    }

    fn store(&mut self, region: DiffRegion) {
        self.region_count += 1;
        if self.regions.len() < self.options.max_regions {
            self.regions.push(region);
        }
    }

    fn emit_match(&mut self, gap: Span) {
        self.store(DiffRegion {
            offset_a: gap.offset_a,
            offset_b: gap.offset_b,
            length: gap.len_a,
            length_a: gap.len_a,
            length_b: gap.len_b,
            diff_type: DiffType::Match,
        });
    }

    fn emit_change(&mut self, open: OpenChange) {
        let Span {
            offset_a,
            offset_b,
            len_a,
            len_b,
        } = open.span;
        let diff_type = match (len_a, len_b) {
            (_, 0) => DiffType::InsertedA,
            (0, _) => DiffType::InsertedB,
            _ => DiffType::Modified,
        };
        self.total_differences += open.cost();
        self.change_count += 1;
        self.store(DiffRegion {
            offset_a,
            offset_b,
            length: len_a.max(len_b),
            length_a: len_a,
            length_b: len_b,
            diff_type,
        });
    }

    /// Adds `len` bytes both inputs share, starting at the given offsets.
    fn push_match(&mut self, (offset_a, offset_b): (usize, usize), len: usize) {
        if len == 0 {
            return;
        }
        match &mut self.gap {
            Some(gap) => {
                debug_assert_eq!(gap.end(), (offset_a, offset_b));
                gap.len_a += len;
                gap.len_b += len;
            }
            None => {
                self.gap = Some(Span {
                    offset_a,
                    offset_b,
                    len_a: len,
                    len_b: len,
                });
            }
        }
    }

    /// Adds a difference covering `len_a` bytes of A and `len_b` bytes of B.
    fn push_change(&mut self, (offset_a, offset_b): (usize, usize), len_a: usize, len_b: usize) {
        if len_a == 0 && len_b == 0 {
            return;
        }
        match (self.change.take(), self.gap.take()) {
            (None, None) => {
                self.change = Some(OpenChange::new(offset_a, offset_b, len_a, len_b));
            }
            (None, Some(gap)) => {
                self.emit_match(gap);
                self.change = Some(OpenChange::new(offset_a, offset_b, len_a, len_b));
            }
            (Some(mut open), None) => {
                debug_assert_eq!(open.span.end(), (offset_a, offset_b));
                open.extend(len_a, len_b);
                self.change = Some(open);
            }
            (Some(mut open), Some(gap)) => {
                if gap.len_a < self.options.min_match {
                    open.fold_match(gap.len_a);
                    open.extend(len_a, len_b);
                    self.change = Some(open);
                } else {
                    self.emit_change(open);
                    self.emit_match(gap);
                    self.change = Some(OpenChange::new(offset_a, offset_b, len_a, len_b));
                }
            }
        }
    }

    /// Feeds one Myers operation, which is relative to the segment's bases.
    fn push_op(&mut self, op: &DiffOp, (base_a, base_b): (usize, usize)) {
        match *op {
            DiffOp::Equal {
                old_index,
                new_index,
                len,
            } => self.push_match((base_a + old_index, base_b + new_index), len),
            DiffOp::Delete {
                old_index,
                old_len,
                new_index,
            } => self.push_change((base_a + old_index, base_b + new_index), old_len, 0),
            DiffOp::Insert {
                old_index,
                new_index,
                new_len,
            } => self.push_change((base_a + old_index, base_b + new_index), 0, new_len),
            DiffOp::Replace {
                old_index,
                old_len,
                new_index,
                new_len,
            } => self.push_change((base_a + old_index, base_b + new_index), old_len, new_len),
        }
    }

    fn finish(mut self, files_identical: bool) -> DiffResult {
        if let Some(open) = self.change.take() {
            self.emit_change(open);
        }
        if let Some(gap) = self.gap.take() {
            self.emit_match(gap);
        }
        DiffResult {
            regions: self.regions,
            region_count: self.region_count,
            change_count: self.change_count,
            total_differences: self.total_differences,
            files_identical,
        }
    }
}

/// Compares two buffers and returns an ordered edit script.
///
/// Buffers up to 1 MiB each are compared directly; larger ones are first split
/// at content-defined anchors both sides share, and each segment is diffed on
/// its own. Either way a segment's shared prefix and suffix are trimmed and
/// only the differing middle is handed to Myers, within a working-set ceiling
/// and a wall-clock budget for the whole comparison (see
/// [`MYERS_TIME_BUDGET`]). `options` groups and bounds the output without
/// changing which bytes are reported as different.
#[must_use]
pub fn diff_data(data_a: &[u8], data_b: &[u8], options: DiffOptions) -> DiffResult {
    let budget = MyersBudget {
        working_set: MYERS_WORKING_SET_LIMIT,
        deadline: Instant::now().checked_add(MYERS_TIME_BUDGET),
    };
    diff_within(data_a, data_b, options, budget)
}

/// [`diff_data`] with an explicit Myers budget.
fn diff_within(
    data_a: &[u8],
    data_b: &[u8],
    options: DiffOptions,
    budget: MyersBudget,
) -> DiffResult {
    let mut sink = RegionSink::new(options);
    let identical = data_a == data_b;
    if identical {
        sink.push_match((0, 0), data_a.len());
    } else if data_a.len() <= BYTE_LEVEL_THRESHOLD && data_b.len() <= BYTE_LEVEL_THRESHOLD {
        diff_segment(data_a, data_b, (0, 0), budget, &mut sink);
    } else {
        diff_data_anchored(data_a, data_b, budget, &mut sink);
    }
    sink.finish(identical)
}

/// Diffs one segment, handing Myers only its differing middle.
///
/// When the segment is larger than the working-set ceiling its shared prefix
/// and suffix are trimmed and emitted as `Match` regions, and only the
/// differing middle is handed to Myers, so a sparse edit inside a large
/// segment is still located byte-exact. A middle that is itself past the
/// ceiling is reported as one change region rather than diffed.
fn diff_segment(
    data_a: &[u8],
    data_b: &[u8],
    (base_a, base_b): (usize, usize),
    budget: MyersBudget,
    sink: &mut RegionSink,
) {
    let myers_limit = budget.working_set;
    if data_a.len().saturating_add(data_b.len()) > myers_limit {
        let prefix = data_a
            .iter()
            .zip(data_b)
            .take_while(|(a, b)| a == b)
            .count();
        let suffix = data_a[prefix..]
            .iter()
            .rev()
            .zip(data_b[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        let mid_a = data_a.len() - prefix - suffix;
        let mid_b = data_b.len() - prefix - suffix;
        sink.push_match((base_a, base_b), prefix);
        let (mid_start_a, mid_start_b) = (base_a + prefix, base_b + prefix);
        if mid_a.saturating_add(mid_b) > myers_limit {
            sink.push_change((mid_start_a, mid_start_b), mid_a, mid_b);
        } else {
            diff_middle(
                &data_a[prefix..prefix + mid_a],
                &data_b[prefix..prefix + mid_b],
                (mid_start_a, mid_start_b),
                budget.deadline,
                sink,
            );
        }
        sink.push_match((mid_start_a + mid_a, mid_start_b + mid_b), suffix);
        return;
    }
    diff_middle(data_a, data_b, (base_a, base_b), budget.deadline, sink);
}

/// Runs Myers over a segment already known to fit the working-set ceiling,
/// after the empty and identical fast paths, stopping at `deadline`.
fn diff_middle(
    data_a: &[u8],
    data_b: &[u8],
    (base_a, base_b): (usize, usize),
    deadline: Option<Instant>,
    sink: &mut RegionSink,
) {
    if data_a == data_b {
        sink.push_match((base_a, base_b), data_a.len());
        return;
    }
    if data_a.is_empty() || data_b.is_empty() {
        sink.push_change((base_a, base_b), data_a.len(), data_b.len());
        return;
    }
    for op in &capture_diff_slices_deadline(Algorithm::Myers, data_a, data_b, deadline) {
        sink.push_op(op, (base_a, base_b));
    }
}

fn initial_adler32(window: &[u8]) -> (u32, u32) {
    let mut hasher = Adler32::new();
    hasher.write_slice(window);
    let checksum = hasher.checksum();
    (checksum & 0xFFFF, checksum >> 16)
}

fn roll_adler32(a: u32, b: u32, out_byte: u8, in_byte: u8, window: u32) -> (u32, u32) {
    let out = u32::from(out_byte);
    let inv = u32::from(in_byte);
    let new_a = (a + inv + ADLER_MOD - out) % ADLER_MOD;
    let window_mod = window % ADLER_MOD;
    let decrement = (window_mod * out) % ADLER_MOD;
    let new_b = (b + new_a + 2 * ADLER_MOD - decrement - 1) % ADLER_MOD;
    (new_a, new_b)
}

/// Whether a window hash marks a content-defined boundary.
///
/// Both halves of the Adler-32 reach the tested top bits through the
/// multiplication, so a window of one repeated byte can anchor.
fn is_anchor(hash: u32) -> bool {
    hash.wrapping_mul(ANCHOR_MIX) >> (u32::BITS - ANCHOR_BITS) == 0
}

/// The Adler-32 of a window of `byte` repeated, laid out as `(b << 16) | a`.
fn flat_window_hash(byte: u8) -> u32 {
    let window = u64::try_from(ANCHOR_WINDOW).expect("ANCHOR_WINDOW constant must fit in u64");
    let modulus = u64::from(ADLER_MOD);
    let byte = u64::from(byte);
    let a = (1 + window * byte) % modulus;
    let b = (window + byte * (window * (window + 1) / 2)) % modulus;
    u32::try_from((b << 16) | a).expect("both halves are below 65521, so they fit in 32 bits")
}

/// Every hash a window of one repeated byte can have, sorted for lookup.
fn flat_window_hashes() -> [u32; 256] {
    let mut hashes = [0u32; 256];
    for (byte, slot) in (0..=u8::MAX).zip(hashes.iter_mut()) {
        *slot = flat_window_hash(byte);
    }
    hashes.sort_unstable();
    hashes
}

/// Finds the content-defined anchors of `data`: `(hash, end)` of each
/// non-overlapping window that passes [`is_anchor`], left to right.
///
/// A window of one repeated byte says nothing about where in its run it
/// sits, so it anchors only where its start is a multiple of the window size
/// in `data` itself. Two inputs compared at the same offsets then agree on
/// which windows of a run anchor even where an edit interrupts the run,
/// whereas a chain that restarts after every interruption drifts out of phase
/// with the other input's.
fn compute_anchors(data: &[u8]) -> Vec<(u32, usize)> {
    if data.len() < ANCHOR_WINDOW {
        return Vec::new();
    }

    let window = ANCHOR_WINDOW;
    let window_u32 = u32::try_from(window).expect("ANCHOR_WINDOW constant must fit in u32");
    let mut anchors: Vec<(u32, usize)> = Vec::new();

    let mut idx: usize = 0;
    let (mut a, mut b) = initial_adler32(&data[0..window]);
    loop {
        let hash = (b << 16) | a;
        if is_anchor(hash) && (idx.is_multiple_of(window) || hash != flat_window_hash(data[idx])) {
            anchors.push((hash, idx + window));
            let next_idx = idx + window;
            if next_idx + window > data.len() {
                break;
            }
            idx = next_idx;
            let (na, nb) = initial_adler32(&data[idx..idx + window]);
            a = na;
            b = nb;
        } else {
            let next_idx = idx + 1;
            if next_idx + window > data.len() {
                break;
            }
            let out_byte = data[idx];
            let in_byte = data[idx + window];
            let (na, nb) = roll_adler32(a, b, out_byte, in_byte, window_u32);
            a = na;
            b = nb;
            idx = next_idx;
        }
    }

    anchors
}

/// Indexes into `anchors` of every anchor with each hash, ascending.
fn indexes_by_hash(anchors: &[(u32, usize)]) -> HashMap<u32, Vec<usize>> {
    let mut by_hash: HashMap<u32, Vec<usize>> = HashMap::new();
    for (index, &(hash, _)) in anchors.iter().enumerate() {
        by_hash.entry(hash).or_default().push(index);
    }
    by_hash
}

/// The first index after `after` holding `hash`, if any.
fn next_index_of(by_hash: &HashMap<u32, Vec<usize>>, hash: u32, after: usize) -> Option<usize> {
    let indexes = by_hash.get(&hash)?;
    indexes
        .get(indexes.partition_point(|&index| index <= after))
        .copied()
}

/// Whether `by_hash` holds more than one anchor with `hash`.
fn repeats(by_hash: &HashMap<u32, Vec<usize>>, hash: u32) -> bool {
    by_hash.get(&hash).is_some_and(|indexes| indexes.len() > 1)
}

/// Pairs up anchors both inputs share into `(pos_a, pos_b)` sync points.
///
/// Equal hashes pair in order. When they differ, the cursor that is behind
/// jumps to the nearest later anchor carrying the other side's hash, however
/// far away: an insertion of any size is skipped over rather than only the
/// first few anchors of it.
///
/// A weak anchor is one whose hash repeats within either input, or is that of
/// a window of one repeated byte: where it sits in its run says nothing about
/// where the same run is in the other input. A pair of weak anchors is
/// accepted only when it keeps the distance from the last sync point equal on
/// both sides, and a weak anchor is never jumped to. A pair that did not keep
/// the distance would assert that the run shifted, and the segment between the
/// sync points would then report a shift that is not in either input.
fn find_sync_points(anchors_a: &[(u32, usize)], anchors_b: &[(u32, usize)]) -> Vec<(usize, usize)> {
    if anchors_a.is_empty() || anchors_b.is_empty() {
        return Vec::new();
    }

    let flat = flat_window_hashes();
    let by_hash_a = indexes_by_hash(anchors_a);
    let by_hash_b = indexes_by_hash(anchors_b);
    let is_weak = |hash: u32| {
        flat.binary_search(&hash).is_ok() || repeats(&by_hash_a, hash) || repeats(&by_hash_b, hash)
    };

    let mut sync: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = 0;
    let mut j: usize = 0;
    let mut last_a: usize = 0;
    let mut last_b: usize = 0;

    while i < anchors_a.len() && j < anchors_b.len() {
        let (hash_a, pos_a) = anchors_a[i];
        let (hash_b, pos_b) = anchors_b[j];
        if hash_a == hash_b {
            let ahead_a = pos_a.saturating_sub(last_a);
            let ahead_b = pos_b.saturating_sub(last_b);
            let ordering = if is_weak(hash_a) {
                ahead_a.cmp(&ahead_b)
            } else {
                Ordering::Equal
            };
            if ordering == Ordering::Equal {
                if pos_a >= last_a && pos_b >= last_b {
                    sync.push((pos_a, pos_b));
                    last_a = pos_a;
                    last_b = pos_b;
                }
                i += 1;
                j += 1;
            } else if ordering == Ordering::Less {
                i += 1;
            } else {
                j += 1;
            }
            continue;
        }
        let jump_b = if is_weak(hash_a) {
            None
        } else {
            next_index_of(&by_hash_b, hash_a, j)
        };
        let jump_a = if is_weak(hash_b) {
            None
        } else {
            next_index_of(&by_hash_a, hash_b, i)
        };
        match (jump_b, jump_a) {
            (Some(to_j), Some(to_i)) if to_j - j <= to_i - i => j = to_j,
            (_, Some(to_i)) => i = to_i,
            (Some(to_j), None) => j = to_j,
            (None, None) => {
                i += 1;
                j += 1;
            }
        }
    }

    sync
}

fn diff_data_anchored(data_a: &[u8], data_b: &[u8], budget: MyersBudget, sink: &mut RegionSink) {
    let anchors_a = compute_anchors(data_a);
    let anchors_b = compute_anchors(data_b);
    let sync_points = find_sync_points(&anchors_a, &anchors_b);

    let mut prev_a: usize = 0;
    let mut prev_b: usize = 0;

    for (sync_a, sync_b) in &sync_points {
        diff_segment(
            &data_a[prev_a..*sync_a],
            &data_b[prev_b..*sync_b],
            (prev_a, prev_b),
            budget,
            sink,
        );
        prev_a = *sync_a;
        prev_b = *sync_b;
    }

    diff_segment(
        &data_a[prev_a..],
        &data_b[prev_b..],
        (prev_a, prev_b),
        budget,
        sink,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diff_default(data_a: &[u8], data_b: &[u8]) -> DiffResult {
        diff_data(data_a, data_b, DiffOptions::default())
    }

    fn diff_with(data_a: &[u8], data_b: &[u8], min_match: usize, max_regions: usize) -> DiffResult {
        diff_data(
            data_a,
            data_b,
            DiffOptions {
                min_match,
                max_regions,
            },
        )
    }

    /// Deterministic noise: xorshift32, top byte of each state.
    fn pseudo_random(seed: u32, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                u8::try_from(state >> 24).expect("a u32 shifted right by 24 fits in u8")
            })
            .collect()
    }

    type Shape = Vec<(DiffType, usize, usize, usize, usize)>;

    /// `(type, offset_a, offset_b, length_a, length_b)` of every stored region.
    fn shape(result: &DiffResult) -> Shape {
        result
            .regions
            .iter()
            .map(|r| (r.diff_type, r.offset_a, r.offset_b, r.length_a, r.length_b))
            .collect()
    }

    /// Runs one segment through a sink with default options.
    fn segment_result(
        data_a: &[u8],
        data_b: &[u8],
        bases: (usize, usize),
        myers_limit: usize,
    ) -> DiffResult {
        let mut sink = RegionSink::new(DiffOptions::default());
        let budget = MyersBudget {
            working_set: myers_limit,
            deadline: None,
        };
        diff_segment(data_a, data_b, bases, budget, &mut sink);
        sink.finish(data_a == data_b)
    }

    /// Walks the regions with one cursor per input: every region must start
    /// where the previous one ended on both sides, `Match` regions must cover
    /// equal bytes, and the walk must end exactly at both input lengths.
    fn assert_regions_reconstruct(result: &DiffResult, a: &[u8], b: &[u8]) {
        let (mut cursor_a, mut cursor_b) = (0usize, 0usize);
        let mut rebuilt_b: Vec<u8> = Vec::with_capacity(b.len());
        for region in &result.regions {
            assert_eq!(
                (region.offset_a, region.offset_b),
                (cursor_a, cursor_b),
                "{region:?}"
            );
            assert_eq!(region.length, region.length_a.max(region.length_b));
            if region.diff_type == DiffType::Match {
                assert_eq!(
                    &a[cursor_a..cursor_a + region.length_a],
                    &b[cursor_b..cursor_b + region.length_b]
                );
            }
            rebuilt_b.extend_from_slice(&b[cursor_b..cursor_b + region.length_b]);
            cursor_a += region.length_a;
            cursor_b += region.length_b;
        }
        assert_eq!((cursor_a, cursor_b), (a.len(), b.len()));
        assert_eq!(rebuilt_b, b);
    }

    /// Two periodic buffers (period 64, bytes below 128) where every seventh
    /// byte from offset 3 has its top bit set in the second. A flipped byte
    /// matches nothing in the first buffer, so each edit is the only minimal
    /// alignment: `flips` isolated one-byte substitutions, `2 * flips + 1`
    /// regions.
    fn flipped_pair(flips: usize) -> (Vec<u8>, Vec<u8>) {
        let len = 3 + 7 * flips + 4;
        let a: Vec<u8> = (0..len)
            .map(|i| u8::try_from(i % 64).expect("a value below 64 fits in u8"))
            .collect();
        let mut b = a.clone();
        for edit in 0..flips {
            b[3 + 7 * edit] |= 0x80;
        }
        (a, b)
    }

    #[test]
    fn test_identical_files() {
        let data = b"Hello World";
        let result = diff_default(data, data);
        assert!(result.files_identical);
        assert_eq!(result.total_differences, 0);
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].diff_type, DiffType::Match);
    }

    #[test]
    fn test_single_byte_diff() {
        let a = b"Hello World";
        let mut b = a.to_vec();
        b[0] = b'J';
        let result = diff_default(a, &b);
        assert!(!result.files_identical);
        assert_eq!(result.total_differences, 1);
    }

    #[test]
    fn test_completely_different() {
        let a = vec![0x00u8; 32];
        let b = vec![0xFFu8; 32];
        let result = diff_default(&a, &b);
        assert!(!result.files_identical);
        assert_eq!(result.total_differences, 32);
    }

    #[test]
    fn test_different_lengths_a_longer() {
        let a = b"Hello World Extra";
        let b = b"Hello World";
        let result = diff_default(a, b);
        assert!(!result.files_identical);
        let has_inserted_a = result
            .regions
            .iter()
            .any(|r| r.diff_type == DiffType::InsertedA);
        assert!(has_inserted_a);
    }

    #[test]
    fn test_different_lengths_b_longer() {
        let a = b"Hello";
        let b = b"Hello World";
        let result = diff_default(a, b);
        assert!(!result.files_identical);
        let has_inserted_b = result
            .regions
            .iter()
            .any(|r| r.diff_type == DiffType::InsertedB);
        assert!(has_inserted_b);
    }

    #[test]
    fn test_empty_files() {
        let result = diff_default(b"", b"");
        assert!(result.files_identical);
        assert_eq!(result.region_count, 0);
        assert_eq!(result.regions.len(), 0);
    }

    #[test]
    fn test_one_empty() {
        let result = diff_default(b"ABC", b"");
        assert!(!result.files_identical);
        assert_eq!(result.total_differences, 3);
    }

    #[test]
    fn test_block_aligned_diff() {
        let a = vec![0x00u8; 64];
        let mut b = vec![0x00u8; 64];
        b[32] = 0xFF;
        let result = diff_default(&a, &b);
        assert!(!result.files_identical);
        assert_eq!(result.total_differences, 1);
        assert_eq!(
            shape(&result),
            vec![
                (DiffType::Match, 0, 0, 32, 32),
                (DiffType::Modified, 32, 32, 1, 1),
                (DiffType::Match, 33, 33, 31, 31),
            ]
        );
    }

    #[test]
    fn test_single_byte_insertion() {
        let a = b"ABCDEF";
        let mut b = Vec::from(&a[..]);
        b.insert(3, b'X');
        let result = diff_default(a, &b);
        assert!(!result.files_identical);
        let has_insert = result
            .regions
            .iter()
            .any(|r| r.diff_type == DiffType::InsertedB);
        assert!(
            has_insert,
            "Expected InsertedB region for single byte insertion, got: {:?}",
            result.regions
        );
        let match_count = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .count();
        assert!(match_count >= 1, "Expected at least one Match region");
    }

    #[test]
    fn test_insertion_at_offset_zero() {
        let a = b"ABCDEFGHIJ";
        let mut b: Vec<u8> = Vec::new();
        b.push(b'X');
        b.extend_from_slice(a);
        let result = diff_default(a, &b);
        assert!(!result.files_identical);

        let first_non_empty = result
            .regions
            .iter()
            .find(|r| r.length > 0)
            .expect("Expected at least one region with length > 0");
        assert_eq!(first_non_empty.diff_type, DiffType::InsertedB);
        assert_eq!(first_non_empty.offset_a, 0);
        assert_eq!(first_non_empty.offset_b, 0);
        assert_eq!(first_non_empty.length, 1);

        let match_region = result
            .regions
            .iter()
            .find(|r| r.diff_type == DiffType::Match)
            .expect("Expected a Match region for the shared suffix");
        assert_eq!(match_region.length, a.len());
        assert_eq!(match_region.offset_a, 0);
        assert_eq!(match_region.offset_b, 1);
    }

    #[test]
    fn test_deletion_in_middle() {
        let a = b"ABCDEFGHIJ";
        let mut b: Vec<u8> = Vec::new();
        b.extend_from_slice(&a[..4]);
        b.extend_from_slice(&a[6..]);
        let result = diff_default(a, &b);
        assert!(!result.files_identical);

        let types: Vec<DiffType> = result
            .regions
            .iter()
            .filter(|r| r.length > 0)
            .map(|r| r.diff_type)
            .collect();
        assert!(types.contains(&DiffType::Match));
        assert!(types.contains(&DiffType::InsertedA));

        let deleted = result
            .regions
            .iter()
            .find(|r| r.diff_type == DiffType::InsertedA)
            .expect("Expected InsertedA for middle deletion");
        assert_eq!(deleted.length, 2);
        assert_eq!(deleted.offset_a, 4);
    }

    #[test]
    fn test_replace_middle_bytes() {
        let a = b"ABCDEFGHIJ";
        let mut b = a.to_vec();
        b[4] = b'!';
        b[5] = b'?';
        let result = diff_default(a, &b);
        assert!(!result.files_identical);

        let has_modification = result.regions.iter().any(|r| {
            r.diff_type == DiffType::Modified
                || r.diff_type == DiffType::InsertedA
                || r.diff_type == DiffType::InsertedB
        });
        assert!(
            has_modification,
            "Expected a non-match region for replaced bytes, got {:?}",
            result.regions
        );

        let match_count = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .count();
        assert!(match_count >= 2, "Expected surrounding Match regions");
    }

    #[test]
    fn test_large_identical_files() {
        let size = BYTE_LEVEL_THRESHOLD + 256;
        let data_a = vec![0xAAu8; size];
        let data_b = data_a.clone();
        let result = diff_default(&data_a, &data_b);
        assert!(result.files_identical);
        assert_eq!(result.total_differences, 0);
        assert_eq!(result.regions.len(), 1);
        assert_eq!(result.regions[0].diff_type, DiffType::Match);
        assert_eq!(result.regions[0].length, size);
    }

    #[test]
    fn test_large_files_small_middle_change() {
        let size = BYTE_LEVEL_THRESHOLD + 4096;
        let mut data_a = vec![0u8; size];
        for (idx, byte) in data_a.iter_mut().enumerate() {
            *byte = u8::try_from((idx * 31 + 7) & 0xFF)
                .expect("mask with 0xFF guarantees value fits in u8");
        }
        let mut data_b = data_a.clone();
        let change_offset = size / 2;
        data_b[change_offset] ^= 0xFF;
        data_b[change_offset + 1] ^= 0xFF;
        data_b[change_offset + 2] ^= 0xFF;

        let result = diff_default(&data_a, &data_b);
        assert!(!result.files_identical);

        let match_bytes: usize = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .map(|r| r.length)
            .sum();
        assert!(
            match_bytes > size - 4096,
            "Expected anchored diff to keep most of the file as Match, got {match_bytes} match bytes out of {size}"
        );

        let non_match_bytes: usize = result
            .regions
            .iter()
            .filter(|r| r.diff_type != DiffType::Match)
            .map(|r| r.length)
            .sum();
        assert!(
            non_match_bytes < 4096,
            "Expected localized diff, got {non_match_bytes} non-match bytes"
        );
    }

    #[test]
    fn test_byte_level_edit_script_not_giant_replace() {
        let a: Vec<u8> = (0..200u32)
            .map(|i| u8::try_from(i & 0xFF).expect("mask with 0xFF guarantees value fits in u8"))
            .collect();
        let mut b: Vec<u8> = Vec::new();
        b.push(0xFF);
        b.extend_from_slice(&a);
        let result = diff_default(&a, &b);
        assert!(!result.files_identical);

        let match_bytes: usize = result
            .regions
            .iter()
            .filter(|r| r.diff_type == DiffType::Match)
            .map(|r| r.length)
            .sum();
        assert!(
            match_bytes >= a.len(),
            "Expected a proper edit script with the original body as Match (got {match_bytes} match bytes, body is {})",
            a.len()
        );
        assert_eq!(result.total_differences, 1);
    }

    /// Large-file diff dispatch takes the anchored path directly: for buffers
    /// above `BYTE_LEVEL_THRESHOLD` the anchored algorithm produces region
    /// offsets at byte granularity (not block-aligned multiples of 64) and emits
    /// a real edit script.
    #[test]
    fn test_large_file_dispatch_uses_anchored_byte_offsets() {
        let size = BYTE_LEVEL_THRESHOLD + 1024;
        let mut data_a = vec![0u8; size];
        for (idx, byte) in data_a.iter_mut().enumerate() {
            *byte = u8::try_from((idx * 17 + 3) & 0xFF)
                .expect("mask with 0xFF guarantees value fits in u8");
        }
        let mut data_b = data_a.clone();
        let change_offset = size / 3 + 5;
        data_b[change_offset] ^= 0xFF;

        let result = diff_default(&data_a, &data_b);
        assert!(!result.files_identical);

        let mismatch_region = result
            .regions
            .iter()
            .find(|r| r.diff_type != DiffType::Match && r.length > 0)
            .expect("anchored diff must surface the modified region");
        // A one-byte substitution between equal-length inputs has a unique
        // minimal alignment, so the region is forced exactly.
        assert_eq!(
            mismatch_region,
            &DiffRegion {
                offset_a: change_offset,
                offset_b: change_offset,
                length: 1,
                length_a: 1,
                length_b: 1,
                diff_type: DiffType::Modified,
            }
        );
        assert_eq!(result.total_differences, 1);
        assert_regions_reconstruct(&result, &data_a, &data_b);
    }

    #[test]
    fn test_regions_reconstruct_both_inputs() {
        for (a, b) in [
            (&b"abcdefghi"[..], &b"abXYcdefghiZZ"[..]),
            (b"123456789", b"12"),
            (b"", b"new"),
            (b"same", b"same"),
        ] {
            assert_regions_reconstruct(&diff_default(a, b), a, b);
        }
    }

    /// An anchorless segment must not be handed to Myers whole. Its working set is
    /// about 16 bytes per input byte, so two unrelated 256 MiB files would ask for
    /// ~8 GiB and an allocation failure would abort the process. Past the limit the
    /// differing middle is one region, with the common prefix and suffix still
    /// reported as matches.
    #[test]
    fn test_oversized_middle_reports_single_region_with_exact_context() {
        let mut a = b"PREFIX".to_vec();
        let mut b = b"PREFIX".to_vec();
        a.extend((0..50u8).map(|i| i.wrapping_mul(37)));
        b.extend((0..50u8).map(|i| i.wrapping_mul(91).wrapping_add(1)));
        a.extend_from_slice(b"SUFFIX");
        b.extend_from_slice(b"SUFFIX");
        let result = segment_result(&a, &b, (0, 0), 64);
        assert_eq!(
            shape(&result),
            vec![
                (DiffType::Match, 0, 0, 6, 6),
                (DiffType::Modified, 6, 6, 50, 50),
                (DiffType::Match, 56, 56, 6, 6),
            ]
        );
        assert_eq!(result.total_differences, 50);
    }

    /// A dense diff that Myers resolves quickly keeps byte precision: two
    /// 100 KB buffers that differ at every other byte report each differing
    /// byte as its own change, not one region spanning the middle.
    #[test]
    fn test_dense_but_fast_middle_keeps_byte_precision() {
        let a: Vec<u8> = (0..100_000u32)
            .map(|i| if i % 2 == 0 { b'A' } else { b'B' })
            .collect();
        let b: Vec<u8> = (0..100_000u32)
            .map(|i| if i % 2 == 0 { b'A' } else { b'C' })
            .collect();
        let result = diff_data(&a, &b, DiffOptions::default());
        assert_eq!(result.change_count, 50_000);
        assert_eq!(result.total_differences, 50_000);
        assert_eq!(result.region_count, 100_000);
    }

    /// Myers' cost is not predicted by size: when every byte is replaced by a
    /// value the other side also contains, the search is close to quadratic
    /// (256 KiB took ~85 s unbounded). The comparison's deadline caps it; past
    /// the deadline the unresolved spans become coarse change regions, which
    /// still partition both inputs exactly.
    #[test]
    fn test_pathological_middle_is_bounded_by_the_deadline() {
        let a = pseudo_random(0x1234_5678, 256 * 1024);
        let b: Vec<u8> = a.iter().map(|byte| byte.wrapping_add(1)).collect();
        let budget = MyersBudget {
            working_set: MYERS_WORKING_SET_LIMIT,
            deadline: Instant::now().checked_add(Duration::from_millis(200)),
        };
        let started = Instant::now();
        let result = diff_within(&a, &b, DiffOptions::default(), budget);
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "a 200 ms deadline still took {elapsed:?}"
        );
        assert_regions_reconstruct(&result, &a, &b);
        assert!(!result.files_identical);
    }

    #[test]
    fn test_push_op_replace_reports_true_per_side_lengths() {
        // old_len < new_len: the region covers 3 bytes of A and 5 of B, and
        // its edit cost is the larger side.
        let mut sink = RegionSink::new(DiffOptions::default());
        sink.push_op(
            &DiffOp::Replace {
                old_index: 2,
                old_len: 3,
                new_index: 4,
                new_len: 5,
            },
            (100, 200),
        );
        let result = sink.finish(false);
        assert_eq!(shape(&result), vec![(DiffType::Modified, 102, 204, 3, 5)]);
        assert_eq!(result.regions[0].length, 5);
        assert_eq!(result.total_differences, 5);

        // old_len > new_len: length is still the max.
        let mut sink = RegionSink::new(DiffOptions::default());
        sink.push_op(
            &DiffOp::Replace {
                old_index: 0,
                old_len: 9,
                new_index: 0,
                new_len: 2,
            },
            (0, 0),
        );
        let result = sink.finish(false);
        assert_eq!(shape(&result), vec![(DiffType::Modified, 0, 0, 9, 2)]);
        assert_eq!(result.regions[0].length, 9);
        assert_eq!(result.total_differences, 9);
    }

    #[test]
    fn test_push_op_delete_insert_report_zero_length_on_absent_side() {
        let mut sink = RegionSink::new(DiffOptions::default());
        sink.push_op(
            &DiffOp::Delete {
                old_index: 4,
                old_len: 2,
                new_index: 4,
            },
            (0, 0),
        );
        let deleted = sink.finish(false);
        assert_eq!(shape(&deleted), vec![(DiffType::InsertedA, 4, 4, 2, 0)]);
        assert_eq!(deleted.total_differences, 2);

        let mut sink = RegionSink::new(DiffOptions::default());
        sink.push_op(
            &DiffOp::Insert {
                old_index: 4,
                new_index: 4,
                new_len: 3,
            },
            (0, 0),
        );
        let inserted = sink.finish(false);
        assert_eq!(shape(&inserted), vec![(DiffType::InsertedB, 4, 4, 0, 3)]);
        assert_eq!(inserted.total_differences, 3);
    }

    #[test]
    fn test_diff_segment_fast_paths() {
        // both empty -> no region, no diff
        let result = segment_result(b"", b"", (0, 0), MYERS_WORKING_SET_LIMIT);
        assert_eq!(result.regions.len(), 0);
        assert_eq!(result.total_differences, 0);

        // data_a empty -> InsertedB at the provided base offsets
        let result = segment_result(b"", b"XY", (5, 7), MYERS_WORKING_SET_LIMIT);
        assert_eq!(shape(&result), vec![(DiffType::InsertedB, 5, 7, 0, 2)]);
        assert_eq!(result.total_differences, 2);

        // data_b empty -> InsertedA
        let result = segment_result(b"XYZ", b"", (5, 7), MYERS_WORKING_SET_LIMIT);
        assert_eq!(shape(&result), vec![(DiffType::InsertedA, 5, 7, 3, 0)]);
        assert_eq!(result.total_differences, 3);

        // equal segment -> single Match, no diffs
        let result = segment_result(b"AB", b"AB", (3, 4), MYERS_WORKING_SET_LIMIT);
        assert_eq!(shape(&result), vec![(DiffType::Match, 3, 4, 2, 2)]);
        assert_eq!(result.total_differences, 0);
    }

    #[test]
    fn test_find_sync_points_resync_look_ahead_in_b() {
        // hash_a matches an anchor a few positions ahead in b -> j advances.
        let anchors_a = [(100u32, 10usize)];
        let anchors_b = [(50u32, 5usize), (100u32, 12usize)];
        let sync = find_sync_points(&anchors_a, &anchors_b);
        assert_eq!(sync, vec![(10, 12)]);
    }

    #[test]
    fn test_find_sync_points_resync_look_ahead_in_a() {
        // hash_b matches an anchor a few positions ahead in a -> i advances.
        let anchors_a = [(50u32, 5usize), (100u32, 10usize)];
        let anchors_b = [(100u32, 12usize)];
        let sync = find_sync_points(&anchors_a, &anchors_b);
        assert_eq!(sync, vec![(10, 12)]);
    }

    #[test]
    fn test_find_sync_points_no_resync_advances_both() {
        // Neither look-ahead finds a match -> !advanced fallback advances i and j.
        let anchors_a = [(50u32, 5usize), (60u32, 6usize)];
        let anchors_b = [(70u32, 7usize), (80u32, 8usize)];
        let sync = find_sync_points(&anchors_a, &anchors_b);
        assert_eq!(sync.len(), 0);
    }

    #[test]
    fn test_roll_adler32_matches_direct_window_recompute() {
        // Cross-check the incremental rolling update against a from-scratch
        // Adler-32 computed over the shifted window, byte by byte, for
        // several windows. If `b`'s subtrahend were the running `a`, this would
        // diverge almost immediately
        // because the error term depends on the specific bytes seen.
        let mut data = [0u8; 64];
        for (idx, byte) in data.iter_mut().enumerate() {
            *byte = u8::try_from((idx * 37 + 11) & 0xFF)
                .expect("mask with 0xFF guarantees value fits in u8");
        }
        let window = 8usize;
        let window_u32 = u32::try_from(window).expect("window fits in u32");

        let (mut a, mut b) = initial_adler32(&data[0..window]);
        for start in 0..(data.len() - window) {
            let out_byte = data[start];
            let in_byte = data[start + window];
            let (na, nb) = roll_adler32(a, b, out_byte, in_byte, window_u32);
            let (expected_a, expected_b) = initial_adler32(&data[start + 1..start + 1 + window]);
            let next_start = start + 1;
            assert_eq!(na, expected_a, "a mismatch at window start {next_start}");
            assert_eq!(nb, expected_b, "b mismatch at window start {next_start}");
            a = na;
            b = nb;
        }
    }

    #[test]
    fn test_find_sync_points_rejects_non_monotonic_positions() {
        // Second matching anchor has pos_a < last_a -> monotonicity guard rejects it.
        let anchors_a = [(100u32, 10usize), (200u32, 5usize)];
        let anchors_b = [(100u32, 20usize), (200u32, 3usize)];
        let sync = find_sync_points(&anchors_a, &anchors_b);
        assert_eq!(sync, vec![(10, 20)]);
    }

    /// The anchor test must not rely on the low ten bits of the Adler `a` alone.
    /// A window of one repeated byte can never clear them, so padding would produce
    /// no anchor and large padded files would fall into one huge unanchored
    /// segment. The mixed test lets padding anchor, on the grid.
    #[test]
    fn test_padding_windows_anchor() {
        assert_eq!(
            compute_anchors(&[0u8; 4096]),
            vec![
                (0x0400_0001, 1024),
                (0x0400_0001, 2048),
                (0x0400_0001, 3072),
                (0x0400_0001, 4096),
            ]
        );
        assert_eq!(
            compute_anchors(&[0xFFu8; 2048]),
            vec![(0x79A6_FC2E, 1024), (0x79A6_FC2E, 2048)]
        );
    }

    /// The padding-window test relies on recognizing the hash of a
    /// window of one repeated byte without reading the window.
    #[test]
    fn test_flat_window_hash_is_the_adler_of_the_window() {
        for byte in 0..=u8::MAX {
            let (a, b) = initial_adler32(&[byte; ANCHOR_WINDOW]);
            assert_eq!(flat_window_hash(byte), (b << 16) | a, "byte {byte:#04x}");
        }
        assert_eq!(flat_window_hash(0), 0x0400_0001);
        assert_eq!(flat_window_hash(0xFF), 0x79A6_FC2E);
    }

    /// The anchors of a fixed noise buffer, as computed by an
    /// independent reference (zlib's Adler-32 over every window, the same
    /// multiplier and the same jump rule).
    #[test]
    fn test_pinned_anchor_vector() {
        assert_eq!(
            compute_anchors(&pseudo_random(0x2545_F491, 65_536)),
            vec![
                (0x8223_0611, 1866),
                (0x1F5A_05E9, 5090),
                (0x2077_FAFC, 6311),
                (0x645F_0192, 7490),
                (0xE6C3_0CD5, 8905),
                (0x401B_FBB9, 9971),
                (0xDFF8_05AD, 11430),
                (0x119B_FA52, 15333),
                (0x1963_FA95, 16509),
                (0x31D3_07BD, 18353),
                (0x4AEA_02BF, 19912),
                (0x4B8E_00EC, 21084),
                (0x63CE_F9A3, 24437),
                (0x64DD_01BA, 27070),
                (0xCB4B_F7B4, 28717),
                (0x886F_F282, 29818),
                (0x27E0_0CDF, 31818),
                (0xB034_F546, 33737),
                (0x4805_F69B, 34993),
                (0xDE7A_00D5, 36938),
                (0x1643_FBE6, 39839),
                (0x8090_F06C, 40993),
                (0x30B2_F6E5, 42265),
                (0x7C20_FD6E, 43950),
                (0xE92C_04F5, 47424),
                (0xB9DF_FD5C, 49198),
                (0x0D1E_01F9, 50245),
                (0x0350_038B, 51742),
                (0x322E_F69F, 53669),
                (0xEF46_0A2A, 57763),
                (0x204D_F4AF, 59400),
                (0x94BF_0419, 64084),
            ]
        );
    }

    /// The density of anchors on noise is what keeps segments small.
    #[test]
    fn test_anchor_density_on_noise() {
        assert_eq!(
            compute_anchors(&pseudo_random(0x2545_F491, 1_048_576)).len(),
            505
        );
    }

    /// A chain that restarts after every interruption would anchor a
    /// run at `start + 1024 * n`, which drifts out of phase with the other
    /// input as soon as an edit interrupts the run there.
    #[test]
    fn test_run_anchors_do_not_depend_on_where_the_run_starts() {
        let mut data = pseudo_random(7, 777);
        data.extend(vec![0u8; 6000]);
        data.extend(pseudo_random(9, 777));
        assert_eq!(
            compute_anchors(&data),
            vec![
                (0x0400_0001, 2048),
                (0x0400_0001, 3072),
                (0x0400_0001, 4096),
                (0x0400_0001, 5120),
                (0x0400_0001, 6144),
            ]
        );
    }

    fn padded_pair(pad: usize, edits: &[usize]) -> (Vec<u8>, Vec<u8>) {
        let mut a = pseudo_random(1, 64 * 1024);
        a.extend(vec![0u8; pad]);
        a.extend(pseudo_random(2, 64 * 1024));
        let mut b = a.clone();
        for &edit in edits {
            b[64 * 1024 + edit] = 0x5A;
        }
        (a, b)
    }

    /// A single edit inside a padded run is reported as one changed byte,
    /// with the padding on either side anchored so the run stays in phase.
    #[test]
    fn test_one_edit_inside_padding_is_one_byte() {
        let (a, b) = padded_pair(2 * 1024 * 1024, &[300_001]);
        let result = diff_default(&a, &b);
        let at = 64 * 1024 + 300_001;
        assert_eq!(
            shape(&result),
            vec![
                (DiffType::Match, 0, 0, at, at),
                (DiffType::Modified, at, at, 1, 1),
                (
                    DiffType::Match,
                    at + 1,
                    at + 1,
                    a.len() - at - 1,
                    a.len() - at - 1
                ),
            ]
        );
        assert_eq!(result.total_differences, 1);
        assert_eq!(result.region_count, 3);
    }

    /// Two edits farther apart than Myers may diff in one piece stay separate
    /// regions, because the padded run between them is anchored and split.
    #[test]
    fn test_distant_edits_in_huge_padding_stay_separate() {
        let (a, b) = padded_pair(12 * 1024 * 1024, &[1_000_003, 11_000_007]);
        let result = diff_default(&a, &b);
        let first = 64 * 1024 + 1_000_003;
        let second = 64 * 1024 + 11_000_007;
        assert_eq!(
            shape(&result),
            vec![
                (DiffType::Match, 0, 0, first, first),
                (DiffType::Modified, first, first, 1, 1),
                (
                    DiffType::Match,
                    first + 1,
                    first + 1,
                    second - first - 1,
                    second - first - 1
                ),
                (DiffType::Modified, second, second, 1, 1),
                (
                    DiffType::Match,
                    second + 1,
                    second + 1,
                    a.len() - second - 1,
                    a.len() - second - 1
                ),
            ]
        );
        assert_eq!(result.total_differences, 2);
        assert_eq!(result.region_count, 5);
    }

    /// When padding grows by more anchors than a short look-ahead spans, the
    /// anchor lists still realign, so a change far beyond the padding is found.
    #[test]
    fn test_resized_padding_is_found_wherever_it_is() {
        let before = pseudo_random(11, 64 * 1024);
        let between = pseudo_random(12, 5 * 1024 * 1024);
        let after = pseudo_random(13, 64 * 1024);
        let build = |pad: usize| {
            let mut data = before.clone();
            data.extend(vec![0u8; pad]);
            data.extend_from_slice(&between);
            data.extend(vec![0u8; pad]);
            data.extend_from_slice(&after);
            data
        };
        let a = build(30 * 1024);
        let b = build(60 * 1024);
        let result = diff_default(&a, &b);
        let changes: Vec<(DiffType, usize, usize)> = result
            .regions
            .iter()
            .filter(|r| r.diff_type != DiffType::Match)
            .map(|r| (r.diff_type, r.length_a, r.length_b))
            .collect();
        assert_eq!(
            changes,
            vec![
                (DiffType::InsertedB, 0, 30 * 1024),
                (DiffType::InsertedB, 0, 30 * 1024),
            ]
        );
        assert_eq!(result.total_differences, 60 * 1024);
        assert_regions_reconstruct(&result, &a, &b);
    }

    /// The rules `find_sync_points` applies to the anchors of
    /// padding, and the unbounded look-ahead.
    #[test]
    fn test_sync_point_rules() {
        let flat = flat_window_hash(0);

        // A run anchor the other side lacks is skipped, not paired with the
        // next one a window further on.
        let sync = find_sync_points(
            &[(flat, 1024), (flat, 2048), (flat, 3072)],
            &[(flat, 1024), (flat, 3072)],
        );
        assert_eq!(sync, vec![(1024, 1024), (3072, 3072)]);

        // Run anchors that sit on a different diagonal from the last sync
        // point are never paired: that would assert a shift of 12 bytes.
        assert_eq!(
            find_sync_points(&[(flat, 2048)], &[(flat, 2060)]),
            Vec::new()
        );

        // A hash that repeats is weak even when it is not padding: its pairs
        // must keep the diagonal too.
        assert_eq!(
            find_sync_points(&[(500, 1000), (500, 2000)], &[(500, 1000), (500, 2500)]),
            vec![(1000, 1000)]
        );

        // A run anchor is never the target of a look-ahead jump: the other
        // side's distinctive anchor is.
        let sync = find_sync_points(&[(flat, 1024), (777, 5000)], &[(777, 3000), (flat, 9000)]);
        assert_eq!(sync, vec![(5000, 3000)]);

        // The look-ahead is not limited to a few anchors.
        let mut anchors_a: Vec<(u32, usize)> = (0..20u32)
            .map(|junk| {
                (
                    1000 + junk,
                    2048 * usize::try_from(junk + 1).expect("small"),
                )
            })
            .collect();
        anchors_a.push((777, 100_000));
        assert_eq!(
            find_sync_points(&anchors_a, &[(777, 100)]),
            vec![(100_000, 100)]
        );
    }

    /// An equal run shorter than `min_match` between two
    /// changes folds them into one region covering both sides.
    #[test]
    fn test_min_match_folds_short_gaps() {
        let a = b"AAAA-B-CCCC-D-EEEE";
        let b = b"AAAA-X-CCCC-Y-EEEE";
        let unfolded = vec![
            (DiffType::Match, 0, 0, 5, 5),
            (DiffType::Modified, 5, 5, 1, 1),
            (DiffType::Match, 6, 6, 6, 6),
            (DiffType::Modified, 12, 12, 1, 1),
            (DiffType::Match, 13, 13, 5, 5),
        ];
        let folded = diff_with(a, b, 7, usize::MAX);
        assert_eq!(
            shape(&folded),
            vec![
                (DiffType::Match, 0, 0, 5, 5),
                (DiffType::Modified, 5, 5, 8, 8),
                (DiffType::Match, 13, 13, 5, 5),
            ]
        );
        assert_eq!(folded.regions[1].length, 8);
        assert_eq!(folded.region_count, 3);
        assert_eq!(folded.change_count, 1);
        assert_eq!(folded.total_differences, 2);
        assert_regions_reconstruct(&folded, a, b);

        // The gap is six bytes: only a minimum above six folds it.
        assert_eq!(shape(&diff_with(a, b, 6, usize::MAX)), unfolded);
        assert_eq!(shape(&diff_with(a, b, 7, usize::MAX)), shape(&folded));
    }

    /// Only a run between two changes folds; the runs before the
    /// first change and after the last are the context around the edit.
    #[test]
    fn test_min_match_never_folds_edge_runs() {
        let result = diff_with(b"x_Y_z", b"x_Q_z", 100, usize::MAX);
        assert_eq!(
            shape(&result),
            vec![
                (DiffType::Match, 0, 0, 2, 2),
                (DiffType::Modified, 2, 2, 1, 1),
                (DiffType::Match, 3, 3, 2, 2),
            ]
        );
    }

    /// Folding chains across several short gaps and stops at the
    /// first long one.
    #[test]
    fn test_min_match_chains_across_gaps() {
        let a = b"S1ab2cd3EEEEEEEEEE4T";
        let b = b"SWabXcdYEEEEEEEEEEZT";
        // Gaps are 2, 2 and 10 bytes.
        let result = diff_with(a, b, 5, usize::MAX);
        assert_eq!(
            shape(&result),
            vec![
                (DiffType::Match, 0, 0, 1, 1),
                (DiffType::Modified, 1, 1, 7, 7),
                (DiffType::Match, 8, 8, 10, 10),
                (DiffType::Modified, 18, 18, 1, 1),
                (DiffType::Match, 19, 19, 1, 1),
            ]
        );
        assert_eq!(result.total_differences, 4);
        let everything = diff_with(a, b, 11, usize::MAX);
        assert_eq!(
            shape(&everything),
            vec![
                (DiffType::Match, 0, 0, 1, 1),
                (DiffType::Modified, 1, 1, 18, 18),
                (DiffType::Match, 19, 19, 1, 1),
            ]
        );
        assert_eq!(everything.total_differences, 4);
    }

    /// The default minimum folds nothing.
    #[test]
    fn test_min_match_zero_and_one_fold_nothing() {
        // The gaps between the changes are one byte each.
        let a = b"aXbYc";
        let b = b"aPbQc";
        let unfolded = vec![
            (DiffType::Match, 0, 0, 1, 1),
            (DiffType::Modified, 1, 1, 1, 1),
            (DiffType::Match, 2, 2, 1, 1),
            (DiffType::Modified, 3, 3, 1, 1),
            (DiffType::Match, 4, 4, 1, 1),
        ];
        assert_eq!(shape(&diff_with(a, b, 1, usize::MAX)), unfolded);
        assert_eq!(shape(&diff_with(a, b, 0, usize::MAX)), unfolded);
        assert_eq!(shape(&diff_default(a, b)), unfolded);
        assert_eq!(
            shape(&diff_with(a, b, 2, usize::MAX)),
            vec![
                (DiffType::Match, 0, 0, 1, 1),
                (DiffType::Modified, 1, 1, 3, 3),
                (DiffType::Match, 4, 4, 1, 1),
            ]
        );
    }

    /// Past `max_regions` the regions are counted, not kept.
    #[test]
    fn test_max_regions_stops_storing_but_keeps_counting() {
        let (a, b) = flipped_pair(200);
        let full = diff_with(&a, &b, 1, usize::MAX);
        assert_eq!(full.region_count, 401);
        assert!(!full.truncated());

        let capped = diff_with(&a, &b, 1, 50);
        assert_eq!(capped.regions.len(), 50);
        assert_eq!(capped.region_count, 401);
        assert_eq!(capped.change_count, 200);
        assert_eq!(capped.total_differences, 200);
        assert!(capped.truncated());
        assert!(!capped.files_identical);
        assert_eq!(capped.regions[..], full.regions[..50]);
    }

    /// The cap applies to the default options, and a comparison
    /// that is exactly at the cap is not truncated.
    #[test]
    fn test_default_cap_is_one_hundred_thousand() {
        assert_eq!(
            DiffOptions::default(),
            DiffOptions {
                min_match: 1,
                max_regions: 100_000,
            }
        );
        let mut sink = RegionSink::new(DiffOptions::default());
        let mut at = 0;
        for _ in 0..50_001 {
            sink.push_match((at, at), 1);
            sink.push_change((at + 1, at + 1), 1, 1);
            at += 2;
        }
        sink.push_match((at, at), 1);
        let result = sink.finish(false);
        assert_eq!(result.regions.len(), 100_000);
        assert_eq!(result.region_count, 100_003);
        assert_eq!(result.change_count, 50_001);
        assert_eq!(result.total_differences, 50_001);
        assert!(result.truncated());

        let (a, b) = flipped_pair(3);
        let exact = diff_with(&a, &b, 1, 7);
        assert_eq!(exact.region_count, 7);
        assert!(!exact.truncated());
        assert!(diff_with(&a, &b, 1, 6).truncated());
    }

    /// A cap of zero stores nothing and still reports everything.
    #[test]
    fn test_zero_cap_counts_without_storing() {
        let same = diff_with(b"same", b"same", 1, 0);
        assert_eq!(same.regions.len(), 0);
        assert_eq!(same.region_count, 1);
        assert_eq!(same.change_count, 0);
        assert!(same.truncated());
        assert!(same.files_identical);

        let different = diff_with(b"ab1", b"ab2", 1, 0);
        assert_eq!(different.regions.len(), 0);
        assert_eq!(different.region_count, 2);
        assert_eq!(different.change_count, 1);
        assert_eq!(different.total_differences, 1);
        assert!(different.truncated());
        assert!(!different.files_identical);
    }

    /// Neither option changes how many bytes differ.
    #[test]
    fn test_options_never_change_total_differences() {
        let a = b"S1ab2cd3EEEEEEEEEE4T";
        let b = b"SWabXcdYEEEEEEEEEEZT";
        for min_match in [0, 1, 2, 3, 5, 11, 100] {
            for max_regions in [0, 1, 3, usize::MAX] {
                let result = diff_with(a, b, min_match, max_regions);
                assert_eq!(
                    result.total_differences, 4,
                    "min_match={min_match} max_regions={max_regions}"
                );
                assert!(!result.files_identical);
            }
        }
        let folded = diff_with(a, b, 100, usize::MAX);
        assert_eq!(folded.regions[1].length, 18);
    }

    /// Adjacent equal runs merge, and so do adjacent changes, whose
    /// cost is the larger side as one region.
    #[test]
    fn test_sink_merges_neighbors() {
        let mut sink = RegionSink::new(DiffOptions::default());
        sink.push_match((0, 0), 3);
        sink.push_match((3, 3), 2);
        sink.push_change((5, 5), 2, 0);
        sink.push_change((7, 5), 0, 3);
        sink.push_match((7, 8), 4);
        let result = sink.finish(false);
        assert_eq!(
            shape(&result),
            vec![
                (DiffType::Match, 0, 0, 5, 5),
                (DiffType::Modified, 5, 5, 2, 3),
                (DiffType::Match, 7, 8, 4, 4),
            ]
        );
        assert_eq!(result.regions[1].length, 3);
        assert_eq!(result.total_differences, 3);
        assert_eq!(result.region_count, 3);
    }

    /// The anchored path cuts the inputs at every sync point; the
    /// equal runs between them must still come out as one region.
    #[test]
    fn test_anchored_path_reports_one_match_per_gap() {
        let a = pseudo_random(21, 1_572_864);
        let mut b = a.clone();
        let at = 700_001;
        b[at] ^= 0xFF;
        let result = diff_default(&a, &b);
        assert_eq!(
            shape(&result),
            vec![
                (DiffType::Match, 0, 0, at, at),
                (DiffType::Modified, at, at, 1, 1),
                (
                    DiffType::Match,
                    at + 1,
                    at + 1,
                    a.len() - at - 1,
                    a.len() - at - 1
                ),
            ]
        );
        assert_eq!(result.region_count, 3);
        assert_eq!(result.total_differences, 1);
    }

    /// Truncation on the anchored path keeps the exact counts.
    #[test]
    fn test_anchored_path_truncates_with_exact_counts() {
        let a = pseudo_random(22, 1_572_864);
        let mut b = a.clone();
        for edit in 0..30 {
            b[edit * 50_000 + 17] ^= 0xFF;
        }
        let full = diff_with(&a, &b, 1, usize::MAX);
        assert_eq!(full.region_count, 61);
        assert_eq!(full.change_count, 30);
        assert_eq!(full.total_differences, 30);

        let capped = diff_with(&a, &b, 1, 10);
        assert_eq!(capped.regions.len(), 10);
        assert_eq!(capped.region_count, 61);
        assert_eq!(capped.change_count, 30);
        assert_eq!(capped.total_differences, 30);
        assert!(capped.truncated());
        assert_eq!(capped.regions[..], full.regions[..10]);
    }
}
