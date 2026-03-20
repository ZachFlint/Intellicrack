use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use thiserror::Error;

use crate::piece_table::PieceTable;

#[derive(Error, Debug)]
pub enum IoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no file path set for save")]
    NoFilePath,
    #[error("offset out of bounds: {offset} >= {length}")]
    OffsetOutOfBounds { offset: usize, length: usize },
}

pub struct MmapDocument {
    _mmap: Option<Mmap>,
    path: Option<PathBuf>,
    piece_table: PieceTable,
    modified: bool,
}

impl MmapDocument {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, IoError> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::open(&path)?;
        let metadata = file.metadata()?;
        let file_len = metadata.len() as usize;

        if file_len == 0 {
            return Ok(Self {
                _mmap: None,
                path: Some(path),
                piece_table: PieceTable::new(&[]),
                modified: false,
            });
        }

        let mmap = unsafe { Mmap::map(&file)? };
        let piece_table = PieceTable::new(&mmap[..]);

        Ok(Self {
            _mmap: Some(mmap),
            path: Some(path),
            piece_table,
            modified: false,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            _mmap: None,
            path: None,
            piece_table: PieceTable::new(data),
            modified: false,
        }
    }

    pub fn new_empty() -> Self {
        Self {
            _mmap: None,
            path: None,
            piece_table: PieceTable::new(&[]),
            modified: false,
        }
    }

    pub fn document_size(&self) -> usize {
        self.piece_table.length()
    }

    pub fn file_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn is_modified(&self) -> bool {
        self.modified
    }

    pub fn read(&self, offset: usize, length: usize) -> Vec<u8> {
        self.piece_table.read(offset, length)
    }

    pub fn read_byte(&self, offset: usize) -> Result<u8, IoError> {
        self.piece_table.read_byte(offset).ok_or(IoError::OffsetOutOfBounds {
            offset,
            length: self.piece_table.length(),
        })
    }

    pub fn read_all(&self) -> Vec<u8> {
        self.piece_table.materialize()
    }

    pub fn overwrite(&mut self, offset: usize, data: &[u8]) {
        self.piece_table.overwrite(offset, data);
        self.modified = true;
    }

    pub fn insert(&mut self, offset: usize, data: &[u8]) {
        self.piece_table.insert(offset, data);
        self.modified = true;
    }

    pub fn delete(&mut self, offset: usize, length: usize) {
        self.piece_table.delete(offset, length);
        self.modified = true;
    }

    pub fn save<P: AsRef<Path>>(&mut self, path: P) -> Result<(), IoError> {
        let path = path.as_ref().to_path_buf();
        let data = self.piece_table.materialize();

        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let temp_path = dir.join(format!(
            ".{}.tmp",
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ));

        let mut file = fs::File::create(&temp_path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);

        self._mmap = None;

        fs::rename(&temp_path, &path)?;

        self.path = Some(path.clone());
        self.piece_table = PieceTable::new(&data);
        self._mmap = None;

        if let Ok(f) = fs::File::open(&path) {
            if let Ok(m) = unsafe { Mmap::map(&f) } {
                self.piece_table = PieceTable::new(&m[..]);
                self._mmap = Some(m);
            }
        }

        self.modified = false;
        Ok(())
    }

    pub fn save_in_place(&mut self) -> Result<(), IoError> {
        let path = self.path.clone().ok_or(IoError::NoFilePath)?;
        self.save(path)
    }

    pub fn apply_insert(&mut self, offset: usize, data: &[u8]) {
        self.piece_table.insert(offset, data);
    }

    pub fn apply_overwrite(&mut self, offset: usize, data: &[u8]) {
        self.piece_table.overwrite(offset, data);
    }

    pub fn apply_delete(&mut self, offset: usize, length: usize) {
        self.piece_table.delete(offset, length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_from_bytes() {
        let doc = MmapDocument::from_bytes(b"Hello World");
        assert_eq!(doc.document_size(), 11);
        assert_eq!(doc.read(0, 11), b"Hello World".to_vec());
        assert!(!doc.is_modified());
    }

    #[test]
    fn test_new_empty() {
        let doc = MmapDocument::new_empty();
        assert_eq!(doc.document_size(), 0);
        assert!(!doc.is_modified());
    }

    #[test]
    fn test_read_byte() {
        let doc = MmapDocument::from_bytes(b"ABC");
        assert_eq!(doc.read_byte(0).unwrap(), b'A');
        assert_eq!(doc.read_byte(2).unwrap(), b'C');
        assert!(doc.read_byte(3).is_err());
    }

    #[test]
    fn test_overwrite_marks_modified() {
        let mut doc = MmapDocument::from_bytes(b"Hello");
        assert!(!doc.is_modified());
        doc.overwrite(0, b"J");
        assert!(doc.is_modified());
        assert_eq!(doc.read(0, 5), b"Jello".to_vec());
    }

    #[test]
    fn test_insert_and_delete() {
        let mut doc = MmapDocument::from_bytes(b"AC");
        doc.insert(1, b"B");
        assert_eq!(doc.read(0, 3), b"ABC".to_vec());
        assert_eq!(doc.document_size(), 3);

        doc.delete(1, 1);
        assert_eq!(doc.read(0, 2), b"AC".to_vec());
    }

    #[test]
    fn test_open_and_save() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_mmap.bin");

        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"Original content").unwrap();
        }

        let mut doc = MmapDocument::open(&path).unwrap();
        assert_eq!(doc.document_size(), 16);
        assert_eq!(doc.read(0, 8), b"Original".to_vec());

        doc.overwrite(0, b"Modified");
        assert_eq!(doc.read(0, 8), b"Modified".to_vec());

        let save_path = dir.join("hexcore_test_mmap_saved.bin");
        doc.save(&save_path).unwrap();
        assert!(!doc.is_modified());

        let saved = fs::read(&save_path).unwrap();
        assert_eq!(&saved[..8], b"Modified");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&save_path);
    }

    #[test]
    fn test_read_all() {
        let mut doc = MmapDocument::from_bytes(b"Hello");
        doc.insert(5, b" World");
        let all = doc.read_all();
        assert_eq!(all, b"Hello World".to_vec());
    }
}
