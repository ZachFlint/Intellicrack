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
}

pub struct UndoManager {
    undo_stack: Vec<Operation>,
    redo_stack: Vec<Operation>,
    saved_index: Option<usize>,
}

impl UndoManager {
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
        let op = match self.undo_stack.pop() {
            Some(op) => op,
            None => return false,
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
        }

        true
    }

    pub fn redo(&mut self, doc: &mut MmapDocument) -> bool {
        let op = match self.redo_stack.pop() {
            Some(op) => op,
            None => return false,
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
        }

        true
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn mark_saved(&mut self) {
        self.saved_index = Some(self.undo_stack.len());
    }

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

    pub fn get_overwrite_patches(&self) -> Vec<(usize, Vec<u8>)> {
        self.undo_stack
            .iter()
            .filter_map(|op| match op {
                Operation::Overwrite { offset, new_data, .. } => Some((*offset, new_data.clone())),
                _ => None,
            })
            .collect()
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
}
