// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! The piece table that holds a document's bytes: an immutable original
//! buffer (owned, or a read-only file mapping) plus an append-only buffer of
//! edited bytes, with edits recorded as a list of slices of the two. The add
//! buffer and piece list are compacted as edits accumulate.

use memmap2::Mmap;
use std::collections::TryReserveError;
use std::io::{self, Write};
use std::sync::Arc;

/// Compaction slack: the add buffer is left alone until it holds more than
/// twice the live add-bytes plus this many bytes. Deleting or re-inserting a
/// run orphans the add-buffer bytes it used (undo/redo re-append is the common
/// case), and those dead bytes are never overwritten in place, so without a
/// bound a long session grows the add buffer without limit while the live
/// document stays small. The slack keeps small documents from compacting on
/// every edit.
const COMPACT_SLACK: usize = 64 * 1024;

/// An empty buffer with room for `len` document bytes, or the allocation
/// failure; `Vec::with_capacity` would abort the process instead.
fn reserve_document(len: usize) -> Result<Vec<u8>, TryReserveError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(len)?;
    Ok(buffer)
}

/// Which backing buffer a [`Piece`] reads from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceSource {
    /// The immutable buffer the table was built from.
    Original,
    /// The append-only buffer that holds every inserted or overwritten byte.
    AddBuffer,
}

/// A contiguous run of document bytes taken from one backing buffer.
#[derive(Debug, Clone)]
pub struct Piece {
    /// Buffer the bytes come from.
    pub source: PieceSource,
    /// Offset of the first byte within that buffer.
    pub start: usize,
    /// Number of bytes in the run; never zero for a piece in the table.
    pub length: usize,
}

/// The bytes a document was opened with.
#[derive(Debug, Clone)]
pub enum OriginalBuffer {
    /// An in-memory copy owned by the table.
    Owned(Vec<u8>),
    /// A read-only file mapping, read in place without copying.
    Mapped(Arc<Mmap>),
}

/// Piece table over an original buffer plus an append-only add buffer.
///
/// The document is the concatenation of `pieces`, each a slice of one of the
/// two buffers, and `total_length` is always the sum of their lengths. Every
/// add-buffer byte is referenced by at most one piece, which is what lets
/// [`PieceTable::overwrite`] rewrite such bytes in place.
pub struct PieceTable {
    pieces: Vec<Piece>,
    original: OriginalBuffer,
    add_buffer: Vec<u8>,
    total_length: usize,
    /// Piece count above which [`PieceTable::maybe_compact`] rebuilds the
    /// table. Recomputed after each compaction as twice the compacted count,
    /// so a session that only edits backwards (whose pieces never coalesce at
    /// the edit site) still cannot grow the list without bound.
    compact_pieces: usize,
}

/// Piece count a freshly built table may reach before the first compaction,
/// so a lightly edited document never pays for a rebuild.
const COMPACT_MIN_PIECES: usize = 16;

impl PieceTable {
    /// Builds a table over a copy of `data`.
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        Self::from_vec(data.to_vec())
    }

    /// Builds a table that takes ownership of `data` without copying it.
    #[must_use]
    pub fn from_vec(data: Vec<u8>) -> Self {
        let length = data.len();
        let pieces = if length > 0 {
            vec![Piece {
                source: PieceSource::Original,
                start: 0,
                length,
            }]
        } else {
            Vec::new()
        };

        Self {
            pieces,
            original: OriginalBuffer::Owned(data),
            add_buffer: Vec::new(),
            total_length: length,
            compact_pieces: COMPACT_MIN_PIECES,
        }
    }

    /// Builds a table that reads `mmap` in place as its original buffer.
    #[must_use]
    pub fn from_mmap(mmap: Arc<Mmap>) -> Self {
        let length = mmap.len();
        let pieces = if length > 0 {
            vec![Piece {
                source: PieceSource::Original,
                start: 0,
                length,
            }]
        } else {
            Vec::new()
        };

        Self {
            pieces,
            original: OriginalBuffer::Mapped(mmap),
            add_buffer: Vec::new(),
            total_length: length,
            compact_pieces: COMPACT_MIN_PIECES,
        }
    }

    /// Returns the document length in bytes.
    #[must_use]
    pub fn length(&self) -> usize {
        self.total_length
    }

    /// Returns `true` when the document holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_length == 0
    }

    /// Locates the piece holding document byte `offset`.
    ///
    /// Returns the piece index and the offset within that piece, or `None`
    /// when `offset` is at or past the end of the document.
    #[must_use]
    pub fn find_piece(&self, offset: usize) -> Option<(usize, usize)> {
        if offset >= self.total_length || self.pieces.is_empty() {
            return None;
        }

        let mut accumulated: usize = 0;
        for (idx, piece) in self.pieces.iter().enumerate() {
            if offset < accumulated + piece.length {
                return Some((idx, offset - accumulated));
            }
            accumulated += piece.length;
        }
        None
    }

    /// Returns the address of the original buffer's first byte.
    ///
    /// Callers use this to confirm the table reads an existing mapping in place
    /// rather than a copy of it.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn original_ptr(&self) -> *const u8 {
        match &self.original {
            OriginalBuffer::Owned(vec) => vec.as_ptr(),
            OriginalBuffer::Mapped(mmap) => mmap.as_ptr(),
        }
    }

    /// Returns the current number of pieces in the table.
    ///
    /// Test-only: the current number of pieces, so a test can confirm that
    /// adjacent edits coalesce.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn piece_count(&self) -> usize {
        self.pieces.len()
    }

    /// Test-only: panics unless every piece is non-empty and inside its
    /// buffer, and the piece lengths sum to the document length.
    #[cfg(test)]
    pub(crate) fn assert_invariants(&self) {
        for piece in &self.pieces {
            assert!(piece.length > 0, "zero-length piece {piece:?}");
            assert!(
                piece.start + piece.length <= self.get_buffer(piece.source).len(),
                "piece {piece:?} runs past its buffer"
            );
        }
        assert_eq!(
            self.pieces.iter().map(|piece| piece.length).sum::<usize>(),
            self.total_length,
            "piece lengths do not sum to the document length"
        );
    }

    /// Merges `self.pieces[idx]` into `self.pieces[idx + 1]` when both
    /// describe contiguous bytes from the same source buffer, collapsing
    /// runs of pieces produced by adjacent edits (e.g. repeated single-byte
    /// overwrites) so the piece list does not grow without bound. No-op if
    /// `idx + 1` is out of range or the pair cannot be merged.
    fn try_merge_at(&mut self, idx: usize) {
        let Some(next) = self.pieces.get(idx + 1) else {
            return;
        };
        let cur = &self.pieces[idx];
        if cur.source != next.source || cur.start + cur.length != next.start {
            return;
        }
        let next_length = next.length;
        self.pieces[idx].length += next_length;
        self.pieces.remove(idx + 1);
    }

    /// Attempts to coalesce the piece at `idx` with both of its neighbors.
    ///
    /// Called after `insert`/`delete` touch the piece list around `idx`, the
    /// only place a new adjacency could have been created.
    fn coalesce_neighbors(&mut self, idx: usize) {
        if idx + 1 < self.pieces.len() {
            self.try_merge_at(idx);
        }
        if idx > 0 {
            self.try_merge_at(idx - 1);
        }
    }

    /// Rebuilds the table: reclaims add-buffer bytes no live piece references
    /// and coalesces adjacent pieces that read contiguous bytes from one
    /// buffer.
    ///
    /// The add buffer is append-only, so deleting or re-inserting a run leaves
    /// its old bytes behind as dead weight, and a backwards edit run leaves a
    /// separate piece per edit that `coalesce_neighbors` cannot merge because
    /// the runs are out of order in the add buffer. This walks the pieces in
    /// document order, re-appends each add-buffer run (so runs that are
    /// adjacent in the document become adjacent in the buffer) and merges a
    /// run onto the previous piece whenever they are the same source and
    /// contiguous. The document the table represents is byte-for-byte
    /// unchanged; the backing storage and the piece count shrink. The
    /// piece-count trigger is reset to twice the compacted count.
    fn compact(&mut self) {
        let old_add = std::mem::take(&mut self.add_buffer);
        let live: usize = self
            .pieces
            .iter()
            .filter(|p| p.source == PieceSource::AddBuffer)
            .map(|p| p.length)
            .sum();
        let mut new_add = Vec::with_capacity(live);
        let mut new_pieces: Vec<Piece> = Vec::with_capacity(self.pieces.len());
        for piece in &self.pieces {
            let start = match piece.source {
                PieceSource::AddBuffer => {
                    let new_start = new_add.len();
                    new_add.extend_from_slice(&old_add[piece.start..piece.start + piece.length]);
                    new_start
                }
                PieceSource::Original => piece.start,
            };
            if let Some(last) = new_pieces.last_mut() {
                if last.source == piece.source && last.start + last.length == start {
                    last.length += piece.length;
                    continue;
                }
            }
            new_pieces.push(Piece {
                source: piece.source,
                start,
                length: piece.length,
            });
        }
        self.add_buffer = new_add;
        self.pieces = new_pieces;
        self.compact_pieces = self.pieces.len().saturating_mul(2).max(COMPACT_MIN_PIECES);
    }

    /// Rebuilds the table once its dead bytes or its piece count grows past a
    /// bound proportional to the live data.
    ///
    /// A cheap test skips the piece scan while the buffer is small and the
    /// piece list is short, so a modestly edited document pays nothing. The
    /// byte trigger (buffer past twice the live add-bytes plus [`COMPACT_SLACK`])
    /// bounds a session's add-buffer size to `O(live add-bytes)`; the
    /// piece-count trigger bounds a backwards-edit session's piece list, where
    /// the bytes stay small but every edit adds a piece. Both amortize, since
    /// each fires only after the table grows by a constant multiple of its
    /// compacted size.
    fn maybe_compact(&mut self) {
        if self.add_buffer.len() <= COMPACT_SLACK && self.pieces.len() <= self.compact_pieces {
            return;
        }
        let live: usize = self
            .pieces
            .iter()
            .filter(|p| p.source == PieceSource::AddBuffer)
            .map(|p| p.length)
            .sum();
        let bytes_bloated =
            self.add_buffer.len() > live.saturating_mul(2).saturating_add(COMPACT_SLACK);
        if bytes_bloated || self.pieces.len() > self.compact_pieces {
            self.compact();
        }
    }

    fn get_buffer(&self, source: PieceSource) -> &[u8] {
        match source {
            PieceSource::Original => match &self.original {
                OriginalBuffer::Owned(vec) => vec.as_slice(),
                OriginalBuffer::Mapped(mmap) => &mmap[..],
            },
            PieceSource::AddBuffer => &self.add_buffer,
        }
    }

    /// Returns the byte at `offset`, or `None` past the end of the document.
    ///
    /// # Panics
    ///
    /// Panics only if the table is internally corrupt, i.e. a piece points
    /// outside its backing buffer.
    #[must_use]
    pub fn read_byte(&self, offset: usize) -> Option<u8> {
        let (piece_idx, inner_offset) = self.find_piece(offset)?;
        let piece = &self.pieces[piece_idx];
        let buf = self.get_buffer(piece.source);
        Some(buf[piece.start + inner_offset])
    }

    /// Reads up to `length` bytes starting at `offset`.
    ///
    /// The read is clamped to the end of the document; an `offset` at or past
    /// the end yields an empty vector. The starting piece is located once and
    /// the following pieces are walked in order, so a read spanning `k` pieces
    /// costs `O(k)` rather than one lookup per piece.
    ///
    /// # Panics
    ///
    /// Panics only if the table is internally corrupt, i.e. a piece points
    /// outside its backing buffer.
    #[must_use]
    pub fn read(&self, offset: usize, length: usize) -> Vec<u8> {
        if length == 0 || offset >= self.total_length {
            return Vec::new();
        }
        let Some((first_piece, first_inner)) = self.find_piece(offset) else {
            return Vec::new();
        };

        let actual_length = length.min(self.total_length - offset);
        let mut result = Vec::with_capacity(actual_length);
        let mut remaining = actual_length;
        let mut inner_offset = first_inner;

        for piece in &self.pieces[first_piece..] {
            if remaining == 0 {
                break;
            }
            let buf = self.get_buffer(piece.source);
            let to_copy = remaining.min(piece.length - inner_offset);
            let buf_start = piece.start + inner_offset;
            result.extend_from_slice(&buf[buf_start..buf_start + to_copy]);
            remaining -= to_copy;
            inner_offset = 0;
        }

        result
    }

    /// Inserts data at the given offset.
    ///
    /// # Panics
    ///
    /// Panics if `find_piece` returns `None` for a valid in-range offset, which
    /// indicates internal state corruption.
    pub fn insert(&mut self, offset: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let add_start = self.add_buffer.len();
        self.add_buffer.extend_from_slice(data);

        let new_piece = Piece {
            source: PieceSource::AddBuffer,
            start: add_start,
            length: data.len(),
        };

        let new_piece_idx = if self.pieces.is_empty() || offset >= self.total_length {
            self.pieces.push(new_piece);
            self.pieces.len() - 1
        } else if offset == 0 {
            self.pieces.insert(0, new_piece);
            0
        } else {
            let (piece_idx, inner_offset) = self
                .find_piece(offset)
                .expect("invariant: offset within bounds after guard");

            if inner_offset == 0 {
                self.pieces.insert(piece_idx, new_piece);
                piece_idx
            } else {
                let old_piece = self.pieces[piece_idx].clone();

                let left = Piece {
                    source: old_piece.source,
                    start: old_piece.start,
                    length: inner_offset,
                };
                let right = Piece {
                    source: old_piece.source,
                    start: old_piece.start + inner_offset,
                    length: old_piece.length - inner_offset,
                };

                self.pieces[piece_idx] = left;
                self.pieces.insert(piece_idx + 1, new_piece);
                self.pieces.insert(piece_idx + 2, right);
                piece_idx + 1
            }
        };

        self.total_length += data.len();
        self.coalesce_neighbors(new_piece_idx);
        self.maybe_compact();
    }

    /// Overwrites bytes starting at `offset` without changing the length.
    ///
    /// `data` is clamped to the bytes that already exist, so an overwrite
    /// never grows the document; an empty `data` or an `offset` at or past
    /// the end is a no-op. When the whole range already lives inside one
    /// add-buffer piece, those bytes are rewritten in place instead of
    /// appending fresh ones, so repeated edits to the same bytes do not grow
    /// the add buffer.
    ///
    /// # Panics
    ///
    /// Panics only if the table is internally corrupt; see
    /// [`PieceTable::insert`] and [`PieceTable::delete`].
    pub fn overwrite(&mut self, offset: usize, data: &[u8]) {
        if data.is_empty() || offset >= self.total_length {
            return;
        }

        let actual_len = data.len().min(self.total_length - offset);
        if let Some((piece_idx, inner_offset)) = self.find_piece(offset) {
            let piece = &self.pieces[piece_idx];
            if piece.source == PieceSource::AddBuffer && inner_offset + actual_len <= piece.length {
                let start = piece.start + inner_offset;
                self.add_buffer[start..start + actual_len].copy_from_slice(&data[..actual_len]);
                return;
            }
        }
        self.delete(offset, actual_len);
        self.insert(offset, &data[..actual_len]);
    }

    /// Deletes `length` bytes starting at the given offset.
    ///
    /// # Panics
    ///
    /// Panics if internal state is corrupt: either `pieces.last()` returns
    /// `None` when `total_length > 0`, or `find_piece(end)` returns `None`
    /// when `end < total_length`.
    pub fn delete(&mut self, offset: usize, length: usize) {
        if length == 0 || offset >= self.total_length {
            return;
        }

        let actual_length = length.min(self.total_length - offset);
        let end = offset + actual_length;

        let Some((start_piece_idx, start_inner)) = self.find_piece(offset) else {
            return;
        };

        let (end_piece_idx, end_inner) = if end >= self.total_length {
            (
                self.pieces.len() - 1,
                self.pieces
                    .last()
                    .expect("invariant: pieces non-empty after length guard")
                    .length,
            )
        } else {
            self.find_piece(end)
                .expect("find_piece(end) must succeed when end < total_length")
        };

        let mut new_pieces: Vec<Piece> = Vec::new();

        new_pieces.extend_from_slice(&self.pieces[..start_piece_idx]);

        if start_inner > 0 {
            let piece = &self.pieces[start_piece_idx];
            new_pieces.push(Piece {
                source: piece.source,
                start: piece.start,
                length: start_inner,
            });
        }

        let left_len = new_pieces.len();

        let piece = &self.pieces[end_piece_idx];
        if end_inner < piece.length {
            new_pieces.push(Piece {
                source: piece.source,
                start: piece.start + end_inner,
                length: piece.length - end_inner,
            });
        }

        if end_piece_idx + 1 < self.pieces.len() {
            new_pieces.extend_from_slice(&self.pieces[end_piece_idx + 1..]);
        }

        self.pieces = new_pieces;
        self.total_length -= actual_length;

        if left_len > 0 {
            self.coalesce_neighbors(left_len - 1);
        }
        self.maybe_compact();
    }

    /// Copies the whole document into one contiguous vector.
    ///
    /// # Panics
    ///
    /// Panics only if the table is internally corrupt, i.e. a piece points
    /// outside its backing buffer.
    #[must_use]
    pub fn materialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_length);
        self.extend_into(&mut result);
        result
    }

    /// Copies the whole document into one contiguous vector, reporting an
    /// allocation failure instead of aborting the process.
    ///
    /// # Errors
    ///
    /// Returns the [`TryReserveError`] when a buffer the size of the document
    /// cannot be allocated.
    ///
    /// # Panics
    ///
    /// Panics only if the table is internally corrupt, i.e. a piece points
    /// outside its backing buffer.
    pub fn try_materialize(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut result = reserve_document(self.total_length)?;
        self.extend_into(&mut result);
        Ok(result)
    }

    /// Writes the whole document to `writer` one piece at a time, without
    /// building a contiguous copy, so writing a document out costs no memory
    /// proportional to its size.
    ///
    /// # Errors
    ///
    /// Returns the first error `writer` reports.
    ///
    /// # Panics
    ///
    /// Panics only if the table is internally corrupt, i.e. a piece points
    /// outside its backing buffer.
    pub fn write_to<W: Write + ?Sized>(&self, writer: &mut W) -> io::Result<()> {
        for piece in &self.pieces {
            let buf = self.get_buffer(piece.source);
            writer.write_all(&buf[piece.start..piece.start + piece.length])?;
        }
        Ok(())
    }

    /// Reports whether the document's bytes are exactly `other`, comparing
    /// piece by piece without building a copy of the document.
    ///
    /// # Panics
    ///
    /// Panics only if the table is internally corrupt, i.e. a piece points
    /// outside its backing buffer.
    #[must_use]
    pub fn content_equals(&self, other: &[u8]) -> bool {
        if other.len() != self.total_length {
            return false;
        }
        let mut position = 0;
        self.pieces.iter().all(|piece| {
            let buf = self.get_buffer(piece.source);
            let matches = buf[piece.start..piece.start + piece.length]
                == other[position..position + piece.length];
            position += piece.length;
            matches
        })
    }

    /// Appends every piece's bytes to `out` in document order.
    fn extend_into(&self, out: &mut Vec<u8>) {
        for piece in &self.pieces {
            let buf = self.get_buffer(piece.source);
            out.extend_from_slice(&buf[piece.start..piece.start + piece.length]);
        }
    }

    /// Reports whether the document's bytes differ from the original buffer.
    ///
    /// A piece that still reads the original buffer at its own position is
    /// equal by construction and is not compared, so an untouched table
    /// answers after one piece. Add-buffer pieces, and original pieces that an
    /// insert or delete moved, are compared byte for byte, so the cost grows
    /// with the bytes written or moved rather than with the document.
    ///
    /// # Panics
    ///
    /// Panics only if the table is internally corrupt, i.e. a piece points
    /// outside its backing buffer.
    #[must_use]
    pub fn differs_from_original(&self) -> bool {
        let original = self.get_buffer(PieceSource::Original);
        if self.total_length != original.len() {
            return true;
        }
        let mut position = 0;
        for piece in &self.pieces {
            let in_place = piece.source == PieceSource::Original && piece.start == position;
            if !in_place {
                let bytes = &self.get_buffer(piece.source)[piece.start..piece.start + piece.length];
                if bytes != &original[position..position + piece.length] {
                    return true;
                }
            }
            position += piece.length;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_empty() {
        let pt = PieceTable::new(&[]);
        assert_eq!(pt.length(), 0);
        assert!(pt.is_empty());
        assert_eq!(pt.read(0, 10), Vec::<u8>::new());
    }

    #[test]
    fn test_new_with_data() {
        let data = b"Hello, World!";
        let pt = PieceTable::new(data);
        assert_eq!(pt.length(), 13);
        assert_eq!(pt.read(0, 13), data.to_vec());
    }

    #[test]
    fn test_read_byte() {
        let pt = PieceTable::new(b"ABCDE");
        assert_eq!(pt.read_byte(0), Some(b'A'));
        assert_eq!(pt.read_byte(4), Some(b'E'));
        assert_eq!(pt.read_byte(5), None);
    }

    #[test]
    fn test_read_partial() {
        let pt = PieceTable::new(b"Hello, World!");
        assert_eq!(pt.read(7, 5), b"World".to_vec());
    }

    #[test]
    fn test_read_beyond_end() {
        let pt = PieceTable::new(b"ABC");
        assert_eq!(pt.read(1, 100), b"BC".to_vec());
    }

    #[test]
    fn test_insert_at_start() {
        let mut pt = PieceTable::new(b"World");
        pt.insert(0, b"Hello ");
        assert_eq!(pt.length(), 11);
        assert_eq!(pt.read(0, 11), b"Hello World".to_vec());
    }

    #[test]
    fn test_insert_at_end() {
        let mut pt = PieceTable::new(b"Hello");
        pt.insert(5, b" World");
        assert_eq!(pt.length(), 11);
        assert_eq!(pt.read(0, 11), b"Hello World".to_vec());
    }

    #[test]
    fn test_insert_in_middle() {
        let mut pt = PieceTable::new(b"abcd");
        pt.insert(2, b"XX");
        assert_eq!(pt.length(), 6);
        assert_eq!(pt.read(0, 6), b"abXXcd".to_vec());
    }

    #[test]
    fn test_insert_into_empty() {
        let mut pt = PieceTable::new(&[]);
        pt.insert(0, b"ABC");
        assert_eq!(pt.length(), 3);
        assert_eq!(pt.read(0, 3), b"ABC".to_vec());
    }

    #[test]
    fn test_overwrite() {
        let mut pt = PieceTable::new(b"Hello World");
        pt.overwrite(6, b"Rust!");
        assert_eq!(pt.length(), 11);
        assert_eq!(pt.read(0, 11), b"Hello Rust!".to_vec());
    }

    #[test]
    fn test_overwrite_at_boundary() {
        let mut pt = PieceTable::new(b"AABB");
        pt.overwrite(0, b"XX");
        assert_eq!(pt.read(0, 4), b"XXBB".to_vec());
    }

    #[test]
    fn test_delete_from_start() {
        let mut pt = PieceTable::new(b"Hello World");
        pt.delete(0, 6);
        assert_eq!(pt.length(), 5);
        assert_eq!(pt.read(0, 5), b"World".to_vec());
    }

    #[test]
    fn test_delete_from_end() {
        let mut pt = PieceTable::new(b"Hello World");
        pt.delete(5, 6);
        assert_eq!(pt.length(), 5);
        assert_eq!(pt.read(0, 5), b"Hello".to_vec());
    }

    #[test]
    fn test_delete_from_middle() {
        let mut pt = PieceTable::new(b"Hello World");
        pt.delete(5, 1);
        assert_eq!(pt.length(), 10);
        assert_eq!(pt.read(0, 10), b"HelloWorld".to_vec());
    }

    #[test]
    fn test_delete_all() {
        let mut pt = PieceTable::new(b"ABC");
        pt.delete(0, 3);
        assert_eq!(pt.length(), 0);
        assert!(pt.is_empty());
    }

    #[test]
    fn test_multiple_operations() {
        let mut pt = PieceTable::new(b"ABCDEF");
        pt.insert(3, b"XY");
        assert_eq!(pt.read(0, 8), b"ABCXYDEF".to_vec());
        pt.delete(1, 2);
        assert_eq!(pt.read(0, 6), b"AXYDEF".to_vec());
        pt.overwrite(0, b"Z");
        assert_eq!(pt.read(0, 6), b"ZXYDEF".to_vec());
    }

    #[test]
    fn test_cross_piece_read() {
        let mut pt = PieceTable::new(b"AABBCC");
        pt.insert(2, b"XX");
        let data = pt.read(1, 4);
        assert_eq!(data, b"AXXB".to_vec());
    }

    #[test]
    fn test_materialize() {
        let mut pt = PieceTable::new(b"Hello");
        pt.insert(5, b" World");
        pt.overwrite(0, b"h");
        let mat = pt.materialize();
        assert_eq!(mat, b"hello World".to_vec());
    }

    /// `insert` and `delete` merge adjacent, contiguous pieces from the same
    /// source, so a run of sequential single-byte overwrites (each internally
    /// a delete+insert pair) coalesces into one `AddBuffer` run.
    #[test]
    fn test_adjacent_single_byte_overwrites_coalesce_pieces() {
        let mut pt = PieceTable::new(&[0u8; 8]);
        let before = pt.piece_count();

        for i in 0..8 {
            pt.overwrite(i, &[0xFFu8]);
        }

        assert_eq!(pt.read(0, 8), vec![0xFFu8; 8]);
        assert_eq!(before, 1);
        assert_eq!(
            pt.piece_count(),
            1,
            "8 adjacent single-byte overwrites must coalesce into one run"
        );
    }

    #[test]
    fn test_non_adjacent_edits_do_not_incorrectly_merge() {
        let mut pt = PieceTable::new(b"AAAAAAAAAA");
        pt.overwrite(1, b"X");
        pt.overwrite(5, b"Y");
        assert_eq!(pt.read(0, 10), b"AXAAAYAAAA".to_vec());
    }

    /// `overwrite` rewrites bytes in place when the range already lives inside
    /// one add-buffer piece, so rewriting the same byte many times keeps the
    /// add buffer at one byte rather than one per rewrite.
    #[test]
    fn test_overwrite_inside_add_buffer_piece_reuses_bytes_in_place() {
        let mut pt = PieceTable::new(&[0u8; 8]);
        pt.overwrite(0, &[0xFF]);
        for value in 0..100u8 {
            pt.overwrite(0, &[value]);
        }
        assert_eq!(pt.add_buffer.len(), 1);
        assert_eq!(pt.read(0, 8), vec![99, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(pt.length(), 8);
    }

    /// Building a table from an owned vector must not copy it
    /// (`PieceTable::new(&data)` after `materialize`), because every save and
    /// `close()` would briefly hold two full copies of the document.
    #[test]
    fn test_from_vec_takes_ownership_without_copying() {
        let data = b"OwnedBufferBytes".to_vec();
        let source_ptr = data.as_ptr();
        let pt = PieceTable::from_vec(data);
        assert!(std::ptr::eq(pt.original_ptr(), source_ptr));
        assert_eq!(pt.read(0, 16), b"OwnedBufferBytes".to_vec());
    }

    #[test]
    fn test_read_spanning_many_pieces_returns_exact_bytes() {
        let mut pt = PieceTable::new(b"0123456789");
        pt.insert(2, b"ab");
        pt.insert(7, b"cd");
        pt.overwrite(11, b"Z");
        assert_eq!(pt.materialize(), b"01ab234cd56Z89".to_vec());
        assert_eq!(pt.read(1, 12), b"1ab234cd56Z8".to_vec());
        assert_eq!(pt.read(13, 50), b"9".to_vec());
    }

    /// Overwrite cuts its data at the end of the document, delete cuts its
    /// length there, and insert past the end appends.
    #[test]
    fn test_edits_past_the_end_clamp_or_append() {
        let mut overwritten = PieceTable::new(b"AB");
        overwritten.overwrite(1, b"XYZ");
        assert_eq!(overwritten.length(), 2);
        assert_eq!(overwritten.materialize(), b"AX".to_vec());

        let mut deleted = PieceTable::new(b"Hello");
        deleted.delete(2, 100);
        assert_eq!(deleted.length(), 2);
        assert_eq!(deleted.materialize(), b"He".to_vec());

        let mut appended = PieceTable::new(b"AB");
        appended.insert(99, b"Z");
        assert_eq!(appended.materialize(), b"ABZ".to_vec());
        for pt in [&overwritten, &deleted, &appended] {
            pt.assert_invariants();
        }
    }

    /// An original piece that moved away from its own position is compared
    /// byte for byte: deleting the `A` of `ABCD` and appending a `D` gives
    /// `BCDD`, where the appended byte matches the original at its position
    /// and only the shifted `BCD` differs.
    #[test]
    fn test_differs_from_original_compares_moved_original_pieces() {
        let mut pt = PieceTable::new(b"ABCD");
        pt.delete(0, 1);
        pt.insert(3, b"D");
        assert_eq!(pt.materialize(), b"BCDD".to_vec());
        assert!(pt.differs_from_original());
    }

    /// A long stream of small edits, including zero-length edits and offsets
    /// past the end, leaves the table equal to a `Vec` applying the same rules,
    /// with every structural invariant holding after each step.
    #[test]
    fn test_random_edit_sequence_matches_vec_model() {
        let mut pt = PieceTable::new(b"0123456789");
        let mut model: Vec<u8> = b"0123456789".to_vec();
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        let mut next = |bound: usize| -> usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state >> 33).unwrap() % bound
        };
        for step in 0..2000 {
            let len = model.len();
            let offset = next(len + 4);
            let count = next(6);
            let byte = u8::try_from(next(256)).unwrap();
            match next(3) {
                0 => {
                    let data = vec![byte; count];
                    pt.insert(offset, &data);
                    let at = offset.min(len);
                    model.splice(at..at, data);
                }
                1 => {
                    pt.delete(offset, count);
                    if offset < len {
                        model.drain(offset..(offset + count).min(len));
                    }
                }
                _ => {
                    pt.overwrite(offset, &vec![byte; count]);
                    if offset < len {
                        model[offset..(offset + count).min(len)].fill(byte);
                    }
                }
            }
            assert_eq!(pt.length(), model.len(), "step {step}");
            assert_eq!(pt.materialize(), model, "step {step}");
            pt.assert_invariants();
        }
    }

    /// Whether the table differs from its original buffer is decided
    /// by the bytes, not by which edits were made.
    #[test]
    fn test_differs_from_original_compares_content() {
        let mut pt = PieceTable::new(b"ABCD");
        assert!(!pt.differs_from_original());
        pt.overwrite(1, b"X");
        assert!(pt.differs_from_original());
        pt.overwrite(1, b"B");
        assert!(!pt.differs_from_original());

        let mut shifted = PieceTable::new(b"AAAA");
        shifted.delete(0, 1);
        shifted.insert(3, b"A");
        assert_eq!(shifted.materialize(), b"AAAA".to_vec());
        assert!(!shifted.differs_from_original());

        let mut shorter = PieceTable::new(b"ABCD");
        shorter.delete(3, 1);
        assert!(shorter.differs_from_original());
    }

    #[test]
    fn test_large_insert() {
        let mut pt = PieceTable::new(&[0u8; 1000]);
        let insert_data = vec![0xFFu8; 500];
        pt.insert(500, &insert_data);
        assert_eq!(pt.length(), 1500);
        assert_eq!(pt.read_byte(499), Some(0x00));
        assert_eq!(pt.read_byte(500), Some(0xFF));
        assert_eq!(pt.read_byte(999), Some(0xFF));
        assert_eq!(pt.read_byte(1000), Some(0x00));
    }

    /// Re-inserting a run after deleting it orphans the add-buffer bytes the
    /// old copy used. Without compaction an append-only buffer grows with the
    /// number of edits (undo/redo is exactly this pattern), so the add buffer
    /// must stay bounded by the live add-bytes rather than by the edit count.
    #[test]
    fn test_add_buffer_compacts_when_dead_bytes_dominate() {
        let mut pt = PieceTable::new(&[0u8; 16]);
        let block = vec![0xABu8; 4096];
        pt.insert(8, &block);
        for _ in 0..200 {
            pt.delete(8, 4096);
            pt.insert(8, &block);
        }
        assert_eq!(pt.length(), 16 + 4096);
        assert_eq!(pt.read(8, 4096), block);
        assert!(
            pt.add_buffer.len() < 256 * 1024,
            "add_buffer grew to {} bytes for 4096 live add-bytes; an un-compacted \
             buffer would reach ~820 KiB after 201 re-inserts",
            pt.add_buffer.len()
        );
    }

    /// A document too large to copy must surface the allocation failure, not
    /// abort the process: an abort here kills every open document along with
    /// whatever the user had not saved.
    #[test]
    fn test_reserve_document_reports_allocation_failure() {
        assert!(reserve_document(usize::MAX).is_err());
        assert_eq!(reserve_document(16).unwrap().capacity(), 16);
    }

    /// The fallible copy and the streaming writer produce exactly the bytes
    /// `materialize` does for a table mixing original and add-buffer pieces.
    #[test]
    fn test_try_materialize_and_write_to_match_materialize() {
        let mut pt = PieceTable::new(b"0123456789");
        pt.insert(2, b"ab");
        pt.delete(6, 2);
        pt.overwrite(0, b"Z");
        let expected = b"Z1ab236789".to_vec();
        assert_eq!(pt.materialize(), expected);
        assert_eq!(pt.try_materialize().unwrap(), expected);
        let mut written = Vec::new();
        pt.write_to(&mut written).unwrap();
        assert_eq!(written, expected);
    }

    /// A backwards edit run leaves one add-buffer piece per edit that cannot
    /// coalesce at the edit site, because each new run sits before the last in
    /// the add buffer. Without the rebuild the piece list — and therefore every
    /// later `find_piece` — grows with the number of edits. Compaction must
    /// bound it: 4096 reversed single-byte overwrites of a 4096-byte document
    /// collapse to a single run, not thousands of pieces.
    #[test]
    fn test_reversed_single_byte_overwrites_keep_the_piece_count_bounded() {
        let size = 4096;
        let mut pt = PieceTable::new(&vec![0u8; size]);
        for i in (0..size).rev() {
            pt.overwrite(i, &[0xFF]);
        }
        assert_eq!(pt.read(0, size), vec![0xFF; size]);
        assert!(
            pt.piece_count() <= COMPACT_MIN_PIECES,
            "{size} reversed overwrites left {} pieces; compaction did not bound the list",
            pt.piece_count()
        );
    }

    /// Compaction rewrites piece offsets into a rebuilt add buffer, so the
    /// document it represents must stay byte-for-byte identical. A deterministic
    /// edit stream (inserts up to 2 KiB churn well past `COMPACT_SLACK`, so
    /// compaction fires repeatedly) is applied to the table and to a `Vec`
    /// oracle, which must agree after every operation.
    #[test]
    fn test_compaction_preserves_content_under_random_edits() {
        let seed = b"seed-document-contents";
        let mut pt = PieceTable::new(seed);
        let mut oracle: Vec<u8> = seed.to_vec();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || -> usize {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state >> 32).unwrap()
        };

        for _ in 0..500 {
            let len = oracle.len();
            match next() % 3 {
                0 => {
                    let pos = next() % (len + 1);
                    let n = 1 + next() % 2048;
                    let data = vec![u8::try_from(next() & 0xFF).unwrap(); n];
                    pt.insert(pos, &data);
                    oracle.splice(pos..pos, data);
                }
                1 if len > 0 => {
                    let pos = next() % len;
                    let n = 1 + next() % (len - pos);
                    pt.delete(pos, n);
                    oracle.drain(pos..pos + n);
                }
                _ if len > 0 => {
                    let pos = next() % len;
                    let n = 1 + next() % (len - pos);
                    let data = vec![u8::try_from(next() & 0xFF).unwrap(); n];
                    pt.overwrite(pos, &data);
                    oracle[pos..pos + n].copy_from_slice(&data);
                }
                _ => {}
            }
            assert_eq!(pt.length(), oracle.len());
            assert_eq!(pt.materialize(), oracle, "content diverged after an edit");
            pt.assert_invariants();
        }

        assert!(
            pt.add_buffer.len() <= pt.length() * 2 + COMPACT_SLACK + 2048,
            "add_buffer {} exceeds the compaction bound for a {}-byte document",
            pt.add_buffer.len(),
            pt.length()
        );
    }
}
