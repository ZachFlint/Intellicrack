use crate::mmap_io::MmapDocument;

#[derive(Debug, Clone)]
pub enum Operation {
    Insert {
        offset: usize,
        data: Vec<u8>,
    },
    Overwrite {
        offset: usize,
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    },
    Delete {
        offset: usize,
        deleted_data: Vec<u8>,
    },
    /// Move of `moved_data.len()` bytes from `src_offset` to `dst_offset`.
    ///
    /// Records both regions touched by the move so undo restores the
    /// original source bytes (which the move zeroed) *and* the original
    /// destination bytes (which the move overwrote). A single
    /// [`Operation::Overwrite`] record could only undo one of the two,
    /// leaving the document inconsistent — see audit1.md F-0001.
    MoveBlock {
        src_offset: usize,
        dst_offset: usize,
        moved_data: Vec<u8>,
        old_dst_data: Vec<u8>,
    },
    /// Atomic swap of `data_a.len()` bytes between `offset_a` and `offset_b`.
    ///
    /// Records the pre-swap bytes of both regions in a single entry so one
    /// `undo()` call restores both sides. Recording a swap as two separate
    /// [`Operation::Overwrite`] entries let a single undo revert only the
    /// second half, leaving the same bytes duplicated at both offsets.
    SwapBlocks {
        offset_a: usize,
        offset_b: usize,
        data_a: Vec<u8>,
        data_b: Vec<u8>,
    },
}

/// Marks the undo-stack state that was last persisted to disk.
///
/// Comparing raw stack *depth* against the depth at save time is not
/// sufficient: undoing past the save point and then recording a different
/// operation can return the stack to the same depth with different content.
/// Tracking the unique id of the operation that was on top of the stack at
/// save time (or `Empty` when the stack was empty) makes the comparison
/// depend on operation identity instead of depth.
#[derive(Debug, Clone, Copy)]
enum SaveMarker {
    /// `mark_unsaved()` was called; always report modified.
    Unset,
    /// Saved while the undo stack was empty.
    Empty,
    /// Saved with this operation id on top of the undo stack.
    Op(u64),
}

pub struct UndoManager {
    undo_stack: Vec<Operation>,
    redo_stack: Vec<Operation>,
    undo_ids: Vec<u64>,
    redo_ids: Vec<u64>,
    next_op_id: u64,
    saved_marker: SaveMarker,
}

impl UndoManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            undo_ids: Vec::new(),
            redo_ids: Vec::new(),
            next_op_id: 0,
            saved_marker: SaveMarker::Empty,
        }
    }

    pub fn record(&mut self, op: Operation) {
        let id = self.next_op_id;
        self.next_op_id += 1;
        self.undo_stack.push(op);
        self.undo_ids.push(id);
        self.redo_stack.clear();
        self.redo_ids.clear();
    }

    /// Reverts the most recently recorded operation.
    ///
    /// # Panics
    ///
    /// Panics if internal state is corrupt: `undo_ids` desynced from `undo_stack`.
    pub fn undo(&mut self, doc: &mut MmapDocument) -> bool {
        let Some(op) = self.undo_stack.pop() else {
            return false;
        };
        let id = self
            .undo_ids
            .pop()
            .expect("undo_ids must stay in sync with undo_stack");

        match &op {
            Operation::Insert { offset, data } => {
                doc.apply_delete(*offset, data.len());
            }
            Operation::Overwrite {
                offset,
                old_data,
                new_data: _,
            } => {
                doc.apply_overwrite(*offset, old_data);
            }
            Operation::Delete {
                offset,
                deleted_data,
            } => {
                doc.apply_insert(*offset, deleted_data);
            }
            Operation::MoveBlock {
                src_offset,
                dst_offset,
                moved_data,
                old_dst_data,
            } => {
                doc.apply_overwrite(*dst_offset, old_dst_data);
                doc.apply_overwrite(*src_offset, moved_data);
            }
            Operation::SwapBlocks {
                offset_a,
                offset_b,
                data_a,
                data_b,
            } => {
                doc.apply_overwrite(*offset_a, data_a);
                doc.apply_overwrite(*offset_b, data_b);
            }
        }

        self.redo_stack.push(op);
        self.redo_ids.push(id);
        true
    }

    /// Reapplies the most recently undone operation.
    ///
    /// # Panics
    ///
    /// Panics if internal state is corrupt: `redo_ids` desynced from `redo_stack`.
    pub fn redo(&mut self, doc: &mut MmapDocument) -> bool {
        let Some(op) = self.redo_stack.pop() else {
            return false;
        };
        let id = self
            .redo_ids
            .pop()
            .expect("redo_ids must stay in sync with redo_stack");

        match &op {
            Operation::Insert { offset, data } => {
                doc.apply_insert(*offset, data);
            }
            Operation::Overwrite {
                offset,
                old_data: _,
                new_data,
            } => {
                doc.apply_overwrite(*offset, new_data);
            }
            Operation::Delete {
                offset,
                deleted_data,
            } => {
                doc.apply_delete(*offset, deleted_data.len());
            }
            Operation::MoveBlock {
                src_offset,
                dst_offset,
                moved_data,
                ..
            } => {
                let zeros = vec![0u8; moved_data.len()];
                doc.apply_overwrite(*src_offset, &zeros);
                doc.apply_overwrite(*dst_offset, moved_data);
            }
            Operation::SwapBlocks {
                offset_a,
                offset_b,
                data_a,
                data_b,
            } => {
                doc.apply_overwrite(*offset_a, data_b);
                doc.apply_overwrite(*offset_b, data_a);
            }
        }

        self.undo_stack.push(op);
        self.undo_ids.push(id);
        true
    }

    #[must_use]
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    #[must_use]
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn mark_saved(&mut self) {
        self.saved_marker = self
            .undo_ids
            .last()
            .copied()
            .map_or(SaveMarker::Empty, SaveMarker::Op);
    }

    pub fn mark_unsaved(&mut self) {
        self.saved_marker = SaveMarker::Unset;
    }

    #[must_use]
    pub fn is_modified(&self) -> bool {
        match self.saved_marker {
            SaveMarker::Unset => true,
            SaveMarker::Empty => !self.undo_ids.is_empty(),
            SaveMarker::Op(id) => self.undo_ids.last().copied() != Some(id),
        }
    }

    pub fn clear(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.undo_ids.clear();
        self.redo_ids.clear();
        self.saved_marker = SaveMarker::Empty;
    }

    #[must_use]
    pub fn get_overwrite_patches(&self) -> Vec<(usize, Vec<u8>)> {
        let mut patches: Vec<(usize, Vec<u8>)> = Vec::new();
        for op in &self.undo_stack {
            match op {
                Operation::Overwrite {
                    offset, new_data, ..
                } => {
                    patches.push((*offset, new_data.clone()));
                }
                Operation::MoveBlock {
                    src_offset,
                    dst_offset,
                    moved_data,
                    ..
                } => {
                    let zeros = vec![0u8; moved_data.len()];
                    patches.push((*src_offset, zeros));
                    patches.push((*dst_offset, moved_data.clone()));
                }
                Operation::SwapBlocks {
                    offset_a,
                    offset_b,
                    data_a,
                    data_b,
                } => {
                    patches.push((*offset_a, data_b.clone()));
                    patches.push((*offset_b, data_a.clone()));
                }
                Operation::Insert { .. } | Operation::Delete { .. } => {}
            }
        }
        patches
    }
}

impl Default for UndoManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let um = UndoManager::new();
        assert!(!um.can_undo());
        assert!(!um.can_redo());
        assert!(!um.is_modified());
    }

    #[test]
    fn test_record_makes_modified() {
        let mut um = UndoManager::new();
        um.record(Operation::Insert {
            offset: 0,
            data: vec![0x41],
        });
        assert!(um.can_undo());
        assert!(!um.can_redo());
        assert!(um.is_modified());
    }

    #[test]
    fn test_undo_insert() {
        let mut doc = MmapDocument::from_bytes(b"Hello");
        let mut um = UndoManager::new();

        doc.apply_insert(5, b" World");
        um.record(Operation::Insert {
            offset: 5,
            data: b" World".to_vec(),
        });

        assert_eq!(doc.document_size(), 11);
        assert!(um.undo(&mut doc));
        assert_eq!(doc.document_size(), 5);
        assert_eq!(doc.read(0, 5), b"Hello".to_vec());
    }

    #[test]
    fn test_undo_overwrite() {
        let mut doc = MmapDocument::from_bytes(b"Hello");
        let mut um = UndoManager::new();

        let old_data = doc.read(0, 1);
        doc.apply_overwrite(0, b"J");
        um.record(Operation::Overwrite {
            offset: 0,
            old_data,
            new_data: vec![b'J'],
        });

        assert_eq!(doc.read(0, 5), b"Jello".to_vec());
        assert!(um.undo(&mut doc));
        assert_eq!(doc.read(0, 5), b"Hello".to_vec());
    }

    #[test]
    fn test_undo_delete() {
        let mut doc = MmapDocument::from_bytes(b"Hello World");
        let mut um = UndoManager::new();

        let deleted = doc.read(5, 6);
        doc.apply_delete(5, 6);
        um.record(Operation::Delete {
            offset: 5,
            deleted_data: deleted,
        });

        assert_eq!(doc.document_size(), 5);
        assert!(um.undo(&mut doc));
        assert_eq!(doc.document_size(), 11);
        assert_eq!(doc.read(0, 11), b"Hello World".to_vec());
    }

    #[test]
    fn test_redo_cycle() {
        let mut doc = MmapDocument::from_bytes(b"ABC");
        let mut um = UndoManager::new();

        doc.apply_insert(3, b"D");
        um.record(Operation::Insert {
            offset: 3,
            data: vec![b'D'],
        });

        assert_eq!(doc.read(0, 4), b"ABCD".to_vec());

        um.undo(&mut doc);
        assert_eq!(doc.read(0, 3), b"ABC".to_vec());
        assert!(um.can_redo());

        um.redo(&mut doc);
        assert_eq!(doc.read(0, 4), b"ABCD".to_vec());
        assert!(!um.can_redo());
    }

    #[test]
    fn test_new_op_clears_redo() {
        let mut um = UndoManager::new();
        let mut doc = MmapDocument::from_bytes(b"AB");

        doc.apply_insert(2, b"C");
        um.record(Operation::Insert {
            offset: 2,
            data: vec![b'C'],
        });

        um.undo(&mut doc);
        assert!(um.can_redo());

        um.record(Operation::Insert {
            offset: 2,
            data: vec![b'D'],
        });
        assert!(!um.can_redo());
    }

    #[test]
    fn test_mark_saved() {
        let mut um = UndoManager::new();
        assert!(!um.is_modified());

        um.record(Operation::Insert {
            offset: 0,
            data: vec![1],
        });
        assert!(um.is_modified());

        um.mark_saved();
        assert!(!um.is_modified());

        um.record(Operation::Insert {
            offset: 1,
            data: vec![2],
        });
        assert!(um.is_modified());
    }

    #[test]
    fn test_mark_unsaved() {
        let mut um = UndoManager::new();
        assert!(!um.is_modified());
        um.mark_unsaved();
        assert!(um.is_modified());
    }

    #[test]
    fn test_undo_empty_returns_false() {
        let mut um = UndoManager::new();
        let mut doc = MmapDocument::from_bytes(b"");
        assert!(!um.undo(&mut doc));
    }

    #[test]
    fn test_redo_empty_returns_false() {
        let mut um = UndoManager::new();
        let mut doc = MmapDocument::from_bytes(b"");
        assert!(!um.redo(&mut doc));
    }

    #[test]
    fn test_multiple_undo_redo() {
        let mut doc = MmapDocument::from_bytes(b"A");
        let mut um = UndoManager::new();

        for b in b"BCD" {
            let len = doc.document_size();
            doc.apply_insert(len, &[*b]);
            um.record(Operation::Insert {
                offset: len,
                data: vec![*b],
            });
        }

        assert_eq!(doc.read_all(), b"ABCD".to_vec());

        um.undo(&mut doc);
        assert_eq!(doc.read_all(), b"ABC".to_vec());
        um.undo(&mut doc);
        assert_eq!(doc.read_all(), b"AB".to_vec());
        um.undo(&mut doc);
        assert_eq!(doc.read_all(), b"A".to_vec());

        um.redo(&mut doc);
        assert_eq!(doc.read_all(), b"AB".to_vec());
        um.redo(&mut doc);
        assert_eq!(doc.read_all(), b"ABC".to_vec());
    }

    /// Audit-1 F-0001 regression: undoing a `MoveBlock` must restore both
    /// the source bytes (zeroed by the move) and the destination bytes
    /// (overwritten by the move). The original `move_block` recorded only
    /// the destination overwrite, so undo left the source clear in place.
    #[test]
    fn test_undo_move_block_restores_source_and_destination() {
        let mut doc = MmapDocument::from_bytes(b"AAAABBBB____");
        let mut um = UndoManager::new();

        let moved = doc.read(0, 4);
        let old_dst = doc.read(8, 4);
        doc.apply_overwrite(0, &[0u8; 4]);
        doc.apply_overwrite(8, &moved);
        um.record(Operation::MoveBlock {
            src_offset: 0,
            dst_offset: 8,
            moved_data: moved.clone(),
            old_dst_data: old_dst,
        });
        assert_eq!(doc.read_all(), b"\0\0\0\0BBBBAAAA".to_vec());

        assert!(um.undo(&mut doc));
        assert_eq!(
            doc.read_all(),
            b"AAAABBBB____".to_vec(),
            "undo of move_block must restore source bytes and old destination bytes",
        );
    }

    /// Audit-1 F-0001 regression: redo of a previously-undone `MoveBlock`
    /// must reapply the destination overwrite *and* re-zero the source.
    #[test]
    fn test_redo_move_block_zeroes_source_and_writes_destination() {
        let mut doc = MmapDocument::from_bytes(b"AAAABBBB____");
        let mut um = UndoManager::new();

        let moved = doc.read(0, 4);
        let old_dst = doc.read(8, 4);
        doc.apply_overwrite(0, &[0u8; 4]);
        doc.apply_overwrite(8, &moved);
        um.record(Operation::MoveBlock {
            src_offset: 0,
            dst_offset: 8,
            moved_data: moved,
            old_dst_data: old_dst,
        });
        um.undo(&mut doc);
        assert_eq!(doc.read_all(), b"AAAABBBB____".to_vec());

        assert!(um.redo(&mut doc));
        assert_eq!(
            doc.read_all(),
            b"\0\0\0\0BBBBAAAA".to_vec(),
            "redo of move_block must re-zero the source and restore destination move",
        );
    }

    /// `get_overwrite_patches` flattens `MoveBlock` into the source-zero
    /// and destination-write pair so external patch consumers see the
    /// same byte mutation set as the in-memory document.
    #[test]
    fn test_get_overwrite_patches_includes_move_block_pair() {
        let mut um = UndoManager::new();
        um.record(Operation::MoveBlock {
            src_offset: 0,
            dst_offset: 16,
            moved_data: vec![0xAA, 0xBB, 0xCC, 0xDD],
            old_dst_data: vec![0x00; 4],
        });
        let patches = um.get_overwrite_patches();
        assert_eq!(patches.len(), 2);
        assert_eq!(patches[0], (0usize, vec![0u8; 4]));
        assert_eq!(patches[1], (16usize, vec![0xAA, 0xBB, 0xCC, 0xDD]));
    }

    #[test]
    fn test_clear_resets_stacks_and_saved_state() {
        let mut doc = MmapDocument::from_bytes(b"AB");
        let mut um = UndoManager::new();
        doc.apply_insert(2, b"C");
        um.record(Operation::Insert {
            offset: 2,
            data: vec![b'C'],
        });
        um.undo(&mut doc);
        assert!(um.can_redo());

        um.clear();
        assert!(!um.can_undo());
        assert!(!um.can_redo());
        assert!(!um.is_modified());
    }

    #[test]
    fn test_default_matches_new() {
        let um = UndoManager::default();
        assert!(!um.can_undo());
        assert!(!um.can_redo());
        assert!(!um.is_modified());
    }

    #[test]
    fn test_get_overwrite_patches_skips_insert_and_delete() {
        let mut um = UndoManager::new();
        um.record(Operation::Insert {
            offset: 0,
            data: vec![0x11],
        });
        um.record(Operation::Overwrite {
            offset: 4,
            old_data: vec![0x00],
            new_data: vec![0xEE],
        });
        um.record(Operation::Delete {
            offset: 8,
            deleted_data: vec![0x22],
        });

        let patches = um.get_overwrite_patches();
        // Only the Overwrite contributes a patch; Insert/Delete are no-ops here.
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0], (4usize, vec![0xEE]));
    }

    /// F-0017 regression: a single `undo()` after `swap_blocks` must restore
    /// both swapped regions, not just the most recently recorded half. When
    /// `swap_blocks` recorded two independent `Overwrite` entries, one undo
    /// only reverted the second region, leaving the first region's data
    /// duplicated at both offsets.
    #[test]
    fn test_undo_swap_blocks_restores_both_regions_in_one_call() {
        let mut doc = MmapDocument::from_bytes(b"AAAABBBB");
        let mut um = UndoManager::new();

        let data_a = doc.read(0, 4);
        let data_b = doc.read(4, 4);
        doc.apply_overwrite(0, &data_b);
        doc.apply_overwrite(4, &data_a);
        um.record(Operation::SwapBlocks {
            offset_a: 0,
            offset_b: 4,
            data_a: data_a.clone(),
            data_b: data_b.clone(),
        });
        assert_eq!(doc.read_all(), b"BBBBAAAA".to_vec());

        assert!(um.undo(&mut doc));
        assert_eq!(
            doc.read_all(),
            b"AAAABBBB".to_vec(),
            "a single undo of swap_blocks must restore both swapped regions",
        );
    }

    #[test]
    fn test_redo_swap_blocks_reapplies_swap() {
        let mut doc = MmapDocument::from_bytes(b"AAAABBBB");
        let mut um = UndoManager::new();

        let data_a = doc.read(0, 4);
        let data_b = doc.read(4, 4);
        doc.apply_overwrite(0, &data_b);
        doc.apply_overwrite(4, &data_a);
        um.record(Operation::SwapBlocks {
            offset_a: 0,
            offset_b: 4,
            data_a,
            data_b,
        });
        um.undo(&mut doc);
        assert_eq!(doc.read_all(), b"AAAABBBB".to_vec());

        assert!(um.redo(&mut doc));
        assert_eq!(doc.read_all(), b"BBBBAAAA".to_vec());
    }

    #[test]
    fn test_get_overwrite_patches_includes_swap_blocks_pair() {
        let mut um = UndoManager::new();
        um.record(Operation::SwapBlocks {
            offset_a: 0,
            offset_b: 16,
            data_a: vec![0x11, 0x22],
            data_b: vec![0x33, 0x44],
        });
        let patches = um.get_overwrite_patches();
        assert_eq!(patches.len(), 2);
        assert_eq!(patches[0], (0usize, vec![0x33, 0x44]));
        assert_eq!(patches[1], (16usize, vec![0x11, 0x22]));
    }

    /// F-0028 regression: comparing undo-stack *depth* instead of operation
    /// *identity* lets `is_modified()` go false even though the live document
    /// diverged from what was saved. Record A, B; save at depth 2; undo back
    /// to depth 1; record a different C (clearing the redo branch containing
    /// B) which returns the stack to depth 2 with different content.
    #[test]
    fn test_is_modified_detects_redo_branch_truncation_at_same_depth() {
        let mut doc = MmapDocument::from_bytes(b"A");
        let mut um = UndoManager::new();

        doc.apply_insert(1, b"B");
        um.record(Operation::Insert {
            offset: 1,
            data: vec![b'B'],
        });
        um.mark_saved();
        assert!(!um.is_modified());

        assert!(um.undo(&mut doc));
        assert_eq!(doc.read_all(), b"A".to_vec());
        assert!(um.is_modified());

        doc.apply_insert(1, b"C");
        um.record(Operation::Insert {
            offset: 1,
            data: vec![b'C'],
        });
        assert_eq!(doc.read_all(), b"AC".to_vec());

        assert!(
            um.is_modified(),
            "stack returned to the saved depth with a different operation on top; \
             is_modified() must still report true",
        );
    }
}
