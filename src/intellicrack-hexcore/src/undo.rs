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
}

pub struct UndoManager {
    undo_stack: Vec<Operation>,
    redo_stack: Vec<Operation>,
    saved_index: Option<usize>,
}

impl UndoManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            saved_index: Some(0),
        }
    }

    pub fn record(&mut self, op: Operation) {
        self.undo_stack.push(op);
        self.redo_stack.clear();
    }

    pub fn undo(&mut self, doc: &mut MmapDocument) -> bool {
        let Some(op) = self.undo_stack.pop() else {
            return false;
        };

        match &op {
            Operation::Insert { offset, data } => {
                doc.apply_delete(*offset, data.len());
                self.redo_stack.push(op);
            }
            Operation::Overwrite {
                offset,
                old_data,
                new_data: _,
            } => {
                doc.apply_overwrite(*offset, old_data);
                self.redo_stack.push(op);
            }
            Operation::Delete {
                offset,
                deleted_data,
            } => {
                doc.apply_insert(*offset, deleted_data);
                self.redo_stack.push(op);
            }
            Operation::MoveBlock {
                src_offset,
                dst_offset,
                moved_data,
                old_dst_data,
            } => {
                doc.apply_overwrite(*dst_offset, old_dst_data);
                doc.apply_overwrite(*src_offset, moved_data);
                self.redo_stack.push(op);
            }
        }

        true
    }

    pub fn redo(&mut self, doc: &mut MmapDocument) -> bool {
        let Some(op) = self.redo_stack.pop() else {
            return false;
        };

        match &op {
            Operation::Insert { offset, data } => {
                doc.apply_insert(*offset, data);
                self.undo_stack.push(op);
            }
            Operation::Overwrite {
                offset,
                old_data: _,
                new_data,
            } => {
                doc.apply_overwrite(*offset, new_data);
                self.undo_stack.push(op);
            }
            Operation::Delete {
                offset,
                deleted_data,
            } => {
                doc.apply_delete(*offset, deleted_data.len());
                self.undo_stack.push(op);
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
                self.undo_stack.push(op);
            }
        }

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
        self.saved_index = Some(self.undo_stack.len());
    }

    pub fn mark_unsaved(&mut self) {
        self.saved_index = None;
    }

    #[must_use]
    pub fn is_modified(&self) -> bool {
        match self.saved_index {
            Some(idx) => self.undo_stack.len() != idx,
            None => true,
        }
    }

    pub fn clear(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.saved_index = Some(0);
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
}
