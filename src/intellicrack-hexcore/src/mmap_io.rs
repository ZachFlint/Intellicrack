use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    mmap: Option<Arc<Mmap>>,
    path: Option<PathBuf>,
    piece_table: PieceTable,
    modified: bool,
}

impl MmapDocument {
    /// Opens a file and memory-maps it for reading.
    ///
    /// # Errors
    ///
    /// Returns `IoError::Io` if the file cannot be opened or mapped.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, IoError> {
        let path = path.as_ref().to_path_buf();
        let file = fs::File::open(&path)?;
        let metadata = file.metadata()?;
        let file_len = usize::try_from(metadata.len())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if file_len == 0 {
            return Ok(Self {
                mmap: None,
                path: Some(path),
                piece_table: PieceTable::new(&[]),
                modified: false,
            });
        }

        // SAFETY: `Mmap::map` is unsound only if the mapped file is mutated
        // through another handle while mapped. The mapping is exposed solely as
        // `&[u8]` (never aliased into `&mut [u8]`), and edits go to the piece
        // table's separate add-buffer rather than through the map; `save`
        // writes a fresh temp file and remaps the result rather than writing
        // back through this view, so the bytes under the slice never change.
        let mmap = Arc::new(unsafe { Mmap::map(&file)? });
        let piece_table = PieceTable::from_mmap(Arc::clone(&mmap));

        Ok(Self {
            mmap: Some(mmap),
            path: Some(path),
            piece_table,
            modified: false,
        })
    }

    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            mmap: None,
            path: None,
            piece_table: PieceTable::new(data),
            modified: false,
        }
    }

    #[must_use]
    pub fn new_empty() -> Self {
        Self {
            mmap: None,
            path: None,
            piece_table: PieceTable::new(&[]),
            modified: false,
        }
    }

    #[must_use]
    pub fn document_size(&self) -> usize {
        self.piece_table.length()
    }

    #[must_use]
    pub fn file_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    #[must_use]
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    #[must_use]
    pub fn read(&self, offset: usize, length: usize) -> Vec<u8> {
        self.piece_table.read(offset, length)
    }

    /// Reads a single byte at the given offset.
    ///
    /// # Errors
    ///
    /// Returns `IoError::OffsetOutOfBounds` if the offset exceeds the document size.
    pub fn read_byte(&self, offset: usize) -> Result<u8, IoError> {
        self.piece_table
            .read_byte(offset)
            .ok_or(IoError::OffsetOutOfBounds {
                offset,
                length: self.piece_table.length(),
            })
    }

    #[must_use]
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

    /// Saves the document to the specified path via atomic temp-file rename.
    ///
    /// # Errors
    ///
    /// Returns `IoError::Io` if writing, syncing, or renaming the file fails.
    pub fn save<P: AsRef<Path>>(&mut self, path: P) -> Result<(), IoError> {
        let path = path.as_ref().to_path_buf();
        let data = self.piece_table.materialize();

        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let temp_path = dir.join(format!(
            ".{}.tmp",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));

        let mut file = fs::File::create(&temp_path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        drop(file);

        if let Err(e) = fs::rename(&temp_path, &path) {
            let _ = fs::remove_file(&temp_path);
            return Err(e.into());
        }

        self.mmap = None;
        self.path = Some(path.clone());
        self.piece_table = PieceTable::new(&data);

        if let Ok(f) = fs::File::open(&path) {
            // SAFETY: same contract as `open` — the freshly written target is
            // mapped read-only and exposed only as `&[u8]`, never aliased into
            // `&mut [u8]`. The write above finished and synced before this
            // remap, and later edits go to the add-buffer, so the mapped bytes
            // stay stable for the life of the mapping.
            if let Ok(m) = unsafe { Mmap::map(&f) } {
                let mmap = Arc::new(m);
                self.piece_table = PieceTable::from_mmap(Arc::clone(&mmap));
                self.mmap = Some(mmap);
            }
        }

        self.modified = false;
        Ok(())
    }

    /// Saves the document back to its original file path.
    ///
    /// # Errors
    ///
    /// Returns `IoError::NoFilePath` if no path is set, or `IoError::Io` on write failure.
    pub fn save_in_place(&mut self) -> Result<(), IoError> {
        let path = self.path.clone().ok_or(IoError::NoFilePath)?;
        self.save(path)
    }

    /// Releases the memory map backing this document.
    ///
    /// The current content is copied into an owned in-memory buffer and the
    /// piece table is rebuilt from that buffer, dropping every reference into
    /// the mapped file so the underlying `Arc<Mmap>` is freed and the OS file
    /// section is unmapped. The document remains fully usable in memory (reads,
    /// edits, and a later `save`/`save_as` all continue to work); it is simply
    /// no longer backed by, or holding a lock on, the file. On Windows this is
    /// the deterministic way to make a saved or opened file deletable or
    /// replaceable again without waiting for the document to be dropped. The
    /// call is idempotent and leaves the file path and modified flag untouched.
    pub fn close(&mut self) {
        let data = self.piece_table.materialize();
        self.piece_table = PieceTable::new(&data);
        self.mmap = None;
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

    #[test]
    fn test_piece_table_zero_copy_mmap() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_zero_copy_test.bin");
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"ZeroCopyMmapTestBytes").unwrap();
        }

        let doc = MmapDocument::open(&path).unwrap();
        let mmap = doc.mmap.as_ref().expect("open must retain the mapping");

        // The piece table must read the mapping itself, not a copy of it.
        assert!(
            std::ptr::eq(doc.piece_table.original_ptr(), mmap.as_ptr()),
            "original buffer is a copy, not the mapping"
        );

        assert_eq!(doc.document_size(), 21);
        assert_eq!(doc.read(0, 21), b"ZeroCopyMmapTestBytes".to_vec());

        // An in-memory document still owns its buffer, so the two constructors
        // stay distinguishable.
        let owned = MmapDocument::from_bytes(b"ZeroCopyMmapTestBytes");
        assert!(!std::ptr::eq(
            owned.piece_table.original_ptr(),
            mmap.as_ptr()
        ));

        let _ = fs::remove_file(&path);
    }

    /// F-0073 regression: `save()` used to clear `self.mmap` before the
    /// fallible `fs::rename`, so a rename failure (e.g. destination locked
    /// or, as forced here, a directory in the way) left `mmap` cleared even
    /// though nothing was actually saved, and never cleaned up the temp file.
    #[test]
    fn test_save_failed_rename_preserves_mmap_and_removes_temp_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_mmap_rename_fail_src.bin");
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"Original content").unwrap();
        }

        let mut doc = MmapDocument::open(&path).unwrap();
        assert!(doc.mmap.is_some(), "open must retain the mapping");

        let blocked_target = dir.join("hexcore_test_mmap_rename_fail_target_dir");
        let _ = fs::remove_dir_all(&blocked_target);
        fs::create_dir(&blocked_target).unwrap();

        let temp_path = dir.join(format!(
            ".{}.tmp",
            blocked_target.file_name().unwrap().to_string_lossy()
        ));

        let result = doc.save(&blocked_target);
        assert!(
            result.is_err(),
            "renaming a file onto an existing directory must fail"
        );
        assert!(
            doc.mmap.is_some(),
            "mmap must not be cleared when the rename itself failed"
        );
        assert!(
            !temp_path.exists(),
            "the temp file must be cleaned up after a failed rename"
        );

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&blocked_target);
    }

    /// `close()` must drop the memory map while preserving the current content
    /// in an owned buffer. On Windows the released map is observable: a live
    /// mapping refuses a truncating rewrite of the same path (os error 1224),
    /// and only after `close()` does that rewrite succeed. The closed document
    /// keeps its own copy, so the external rewrite does not change its bytes.
    #[test]
    fn test_close_releases_mmap_and_preserves_content() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_close_release.bin");
        let original: &[u8] = b"CLOSE ME PLEASE 0123456789";
        fs::write(&path, original).unwrap();

        let mut doc = MmapDocument::open(&path).unwrap();
        assert!(doc.mmap.is_some(), "open must memory-map a non-empty file");
        assert_eq!(doc.piece_table.materialize(), original);

        doc.close();
        assert!(doc.mmap.is_none(), "close must drop the memory map");
        assert_eq!(
            doc.piece_table.materialize(),
            original,
            "close must preserve the current content in an owned buffer"
        );

        fs::write(&path, b"REPLACED").expect("file must be writable after close releases the map");

        assert_eq!(
            doc.piece_table.materialize(),
            original,
            "the closed document keeps its own copy, unaffected by the rewrite"
        );

        let _ = fs::remove_file(&path);
    }
}
