// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

//! File-backed documents: locked read-only mappings and atomic saves.
//!
//! A document opened from disk keeps every edit in its piece table, so the file
//! is never written in place. On Windows the file is read through a read-only
//! mapping that is locked against writers for as long as it is mapped, and a
//! file that something else can already write is copied into memory instead.
//! Other platforms have no mandatory write lock, so there the file is always
//! copied: a mapping another process truncated would fault the whole process.
//! Saving writes a uniquely named temp file beside the target, flushes it, and
//! renames it over the target, so the target always holds either its old bytes
//! or the new ones.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use memmap2::Mmap;
use thiserror::Error;

use crate::piece_table::PieceTable;

/// How many fresh temp-file names a save tries before giving up.
const TEMP_NAME_ATTEMPTS: u32 = 64;

/// Whether [`open_locked`] can deny every other handle write access.
///
/// Only Windows has a mandatory write lock. Elsewhere nothing stops another
/// process truncating a mapped file, and reading a page past its new end
/// raises `SIGBUS`, which kills the whole process, so files are copied into
/// memory instead of mapped.
const MAPPING_IS_LOCKED: bool = cfg!(windows);

/// Distinguishes the temp files of the saves this process makes.
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Errors raised while opening, reading or saving a document.
#[derive(Error, Debug)]
pub enum IoError {
    /// The operating system reported a failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// `save_in_place` was called on a document with no file path.
    #[error("no file path set for save")]
    NoFilePath,
    /// A single byte was requested at or past the end of the document.
    #[error("offset out of bounds: {offset} >= {length}")]
    OffsetOutOfBounds { offset: usize, length: usize },
}

/// A file's bytes, held so that they cannot change while they are borrowed.
pub(crate) enum FileBytes {
    /// A read-only mapping, locked against writers; Windows only.
    Mapped(Arc<Mmap>),
    /// A copy, for a file that is empty or that another handle can write, and
    /// for every file on a platform with no mandatory write lock.
    Owned(Vec<u8>),
}

impl Deref for FileBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Mapped(mmap) => mmap,
            Self::Owned(data) => data,
        }
    }
}

/// Loads `path` so that its bytes cannot change while they are held.
///
/// On Windows the file is mapped in place when it can be locked against
/// writers, and copied into memory when it is empty or another handle can
/// already write it. Elsewhere it is always copied, since no lock can stop a
/// truncation that would fault a mapping.
///
/// # Errors
///
/// Returns the error from opening, mapping or reading the file, including an
/// `OutOfMemory` error when a copy of it cannot be allocated.
pub(crate) fn load_stable(path: &Path) -> io::Result<FileBytes> {
    match map_locked(path)? {
        Some(mmap) => Ok(FileBytes::Mapped(mmap)),
        None => read_snapshot(path).map(FileBytes::Owned),
    }
}

/// A document held as a piece table over a file mapping or an owned buffer.
///
/// The piece table's original buffer is the document's baseline: the bytes of
/// the file as it was opened or last saved. Edits never change the baseline,
/// which is what lets [`MmapDocument::is_modified`] compare against it.
pub struct MmapDocument {
    /// The mapping the piece table reads, which also holds the write lock.
    mmap: Option<Arc<Mmap>>,
    /// The file the document was opened from or last saved to.
    path: Option<PathBuf>,
    /// The document's bytes: the baseline plus every edit since.
    piece_table: PieceTable,
    /// Set when the baseline was replaced by bytes the file may not hold, so
    /// a document that differed from its file stays modified until saved.
    detached_changes: bool,
}

impl MmapDocument {
    /// Opens a file, mapping it in place when it can be locked against writers.
    ///
    /// An empty file, one another handle can already write, and on platforms
    /// other than Windows every file, is copied into memory instead, so the
    /// document never reads bytes that can change or fault underneath it.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Io`] if the file cannot be opened, mapped or read, or
    /// if a copy of it cannot be allocated.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, IoError> {
        let path = path.as_ref().to_path_buf();
        let (piece_table, mmap) = match load_stable(&path)? {
            FileBytes::Mapped(mmap) => (PieceTable::from_mmap(Arc::clone(&mmap)), Some(mmap)),
            FileBytes::Owned(data) => (PieceTable::from_vec(data), None),
        };
        Ok(Self {
            mmap,
            path: Some(path),
            piece_table,
            detached_changes: false,
        })
    }

    /// Builds an in-memory document over a copy of `data`, with no file path.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self::unbacked(PieceTable::new(data))
    }

    /// Builds an empty in-memory document with no file path.
    #[must_use]
    pub fn new_empty() -> Self {
        Self::unbacked(PieceTable::from_vec(Vec::new()))
    }

    /// Wraps a table that no file backs.
    fn unbacked(piece_table: PieceTable) -> Self {
        Self {
            mmap: None,
            path: None,
            piece_table,
            detached_changes: false,
        }
    }

    /// Returns the document length in bytes.
    #[must_use]
    pub fn document_size(&self) -> usize {
        self.piece_table.length()
    }

    /// Returns the file the document was opened from or last saved to.
    #[must_use]
    pub fn file_path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Reports whether the bytes differ from the ones the document was opened
    /// with or last saved.
    ///
    /// The answer comes from the bytes, not from the edits made, so a no-op
    /// edit or an edit later reversed leaves the document unmodified. After
    /// [`MmapDocument::close`] the file's bytes are no longer held, so a
    /// document modified at that point stays modified until it is saved. The
    /// editor's dirty flag is `UndoManager::is_modified`, which also knows
    /// where in the undo history the last save happened.
    #[must_use]
    pub fn is_modified(&self) -> bool {
        self.detached_changes || self.piece_table.differs_from_original()
    }

    /// Reads up to `length` bytes from `offset`, clamped to the document end.
    #[must_use]
    pub fn read(&self, offset: usize, length: usize) -> Vec<u8> {
        self.piece_table.read(offset, length)
    }

    /// Reads a single byte at the given offset.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::OffsetOutOfBounds`] if the offset is at or past the
    /// end of the document.
    pub fn read_byte(&self, offset: usize) -> Result<u8, IoError> {
        self.piece_table
            .read_byte(offset)
            .ok_or(IoError::OffsetOutOfBounds {
                offset,
                length: self.piece_table.length(),
            })
    }

    /// Copies the whole document into one vector.
    #[must_use]
    pub fn read_all(&self) -> Vec<u8> {
        self.piece_table.materialize()
    }

    /// Overwrites bytes at `offset`, clamped so the document never grows.
    pub fn overwrite(&mut self, offset: usize, data: &[u8]) {
        self.piece_table.overwrite(offset, data);
    }

    /// Inserts `data` at `offset`; an offset past the end appends.
    pub fn insert(&mut self, offset: usize, data: &[u8]) {
        self.piece_table.insert(offset, data);
    }

    /// Deletes up to `length` bytes from `offset`, clamped to the document end.
    pub fn delete(&mut self, offset: usize, length: usize) {
        self.piece_table.delete(offset, length);
    }

    /// Saves the document to `path` through a temp file, then maps the result.
    ///
    /// The bytes go to a uniquely named temp file beside `path`, which is
    /// flushed to disk and then renamed over `path`, so `path` holds either its
    /// old bytes or the new ones, never a mix, and any failure removes the temp
    /// file. When `path` is the file this document maps, the mapping is released
    /// before the rename, since some Windows hosts refuse to replace a mapped
    /// file; the document holds the same bytes in memory meanwhile. On success
    /// the document adopts `path` and maps and locks it, or keeps the saved
    /// bytes in memory when it cannot.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Io`] if a copy of the document cannot be allocated,
    /// if `path` has no file name, if creating, writing, flushing or renaming
    /// the temp file fails, or, on Windows, if another program has `path` open
    /// for writing. The document's bytes, path and modified state are then
    /// unchanged, although a document saving over its own file no longer maps
    /// it.
    pub fn save<P: AsRef<Path>>(&mut self, path: P) -> Result<(), IoError> {
        let path = path.as_ref();
        let data = self.piece_table.try_materialize().map_err(|e| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                format!(
                    "cannot allocate {} bytes to save {}: {e}",
                    self.piece_table.length(),
                    path.display()
                ),
            )
        })?;
        let temp = TempFile::write_beside(path, |file| file.write_all(&data))?;
        let spare = if self.maps_file(path) {
            self.detach(data);
            None
        } else {
            Some(data)
        };
        temp.persist(path)?;

        self.path = Some(path.to_path_buf());
        self.detached_changes = false;
        match (map_locked(path), spare) {
            (Ok(Some(mmap)), _) => self.adopt_mapping(mmap),
            (_, Some(data)) => self.adopt_owned(data),
            (_, None) => {}
        }
        Ok(())
    }

    /// Saves the document back to its own file path.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::NoFilePath`] if the document has no path, or any
    /// error [`MmapDocument::save`] returns.
    pub fn save_in_place(&mut self) -> Result<(), IoError> {
        let path = self.path.clone().ok_or(IoError::NoFilePath)?;
        self.save(path)
    }

    /// Writes the current bytes to `path` without adopting it.
    ///
    /// The copy goes through a temp file renamed into place, as
    /// [`MmapDocument::save`] does, but the document keeps its own path,
    /// mapping and modified state. The bytes are streamed out of the piece
    /// table, so no copy of the document is built in memory.
    ///
    /// # Errors
    ///
    /// Returns [`IoError::Io`] if `path` has no file name, if creating,
    /// writing, flushing or renaming the temp file fails, or, on Windows, if
    /// another program has `path` open for writing.
    pub fn write_copy<P: AsRef<Path>>(&self, path: P) -> Result<(), IoError> {
        let path = path.as_ref();
        TempFile::write_beside(path, |file| {
            let mut out = io::BufWriter::new(file);
            self.piece_table.write_to(&mut out)?;
            out.flush()
        })?
        .persist(path)?;
        Ok(())
    }

    /// Releases the file mapping, keeping the current bytes in memory.
    ///
    /// Dropping the mapping also drops the write lock, so on Windows the file
    /// can be written, replaced or deleted again without waiting for the
    /// document to be dropped. The document stays fully usable: reads, edits
    /// and a later save all work. Its path and modified state are unchanged,
    /// and closing a document that maps nothing does nothing.
    pub fn close(&mut self) {
        if self.mmap.is_some() {
            let data = self.piece_table.materialize();
            self.detach(data);
        }
    }

    /// Replays an insert from the undo history; see [`MmapDocument::insert`].
    pub fn apply_insert(&mut self, offset: usize, data: &[u8]) {
        self.insert(offset, data);
    }

    /// Replays an overwrite from the undo history; see
    /// [`MmapDocument::overwrite`].
    pub fn apply_overwrite(&mut self, offset: usize, data: &[u8]) {
        self.overwrite(offset, data);
    }

    /// Replays a delete from the undo history; see [`MmapDocument::delete`].
    pub fn apply_delete(&mut self, offset: usize, length: usize) {
        self.delete(offset, length);
    }

    /// Reports whether this document maps the file at `path`.
    fn maps_file(&self, path: &Path) -> bool {
        self.mmap.is_some()
            && self
                .path
                .as_deref()
                .is_some_and(|current| same_file(current, path))
    }

    /// Makes `mmap`, the file just saved, the baseline.
    fn adopt_mapping(&mut self, mmap: Arc<Mmap>) {
        self.piece_table = PieceTable::from_mmap(Arc::clone(&mmap));
        self.mmap = Some(mmap);
    }

    /// Makes `data`, the bytes just saved, the baseline.
    fn adopt_owned(&mut self, data: Vec<u8>) {
        self.piece_table = PieceTable::from_vec(data);
        self.mmap = None;
    }

    /// Makes `data`, the current bytes, the baseline although the file may not
    /// hold them, dropping the mapping and its lock.
    ///
    /// A document that differed from its file still does, so the modified
    /// state is carried over.
    fn detach(&mut self, data: Vec<u8>) {
        self.detached_changes = self.is_modified();
        self.adopt_owned(data);
    }
}

/// Reports whether `a` and `b` name the same existing file.
fn same_file(a: &Path, b: &Path) -> bool {
    matches!(
        (fs::canonicalize(a), fs::canonicalize(b)),
        (Ok(a), Ok(b)) if a == b
    )
}

/// Opens `path` for reading, denying every other handle write access.
///
/// The open fails with `ERROR_SHARING_VIOLATION` while any other handle or
/// mapped view can write the file, and while it is open no handle can be
/// opened to write, truncate or extend the file. Delete sharing is kept, so
/// the file can still be renamed, replaced or deleted, none of which changes
/// the bytes of the file this handle has open.
#[cfg(windows)]
fn open_locked(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(path)
}

/// Opens `path` for reading; other platforms have no mandatory write lock.
#[cfg(not(windows))]
fn open_locked(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Reports whether an open failed because another handle can write the file.
#[cfg(windows)]
fn writer_holds(err: &io::Error) -> bool {
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    err.raw_os_error().and_then(|code| u32::try_from(code).ok()) == Some(ERROR_SHARING_VIOLATION)
}

/// Reports whether an open failed because another handle can write the file.
#[cfg(not(windows))]
fn writer_holds(_err: &io::Error) -> bool {
    false
}

/// Maps `path` read-only, locked against writers.
///
/// Returns `Ok(None)`, and the caller copies the bytes instead, when the file
/// is empty, which cannot be mapped, when another handle can already write it,
/// or on a platform where [`MAPPING_IS_LOCKED`] is false.
fn map_locked(path: &Path) -> io::Result<Option<Arc<Mmap>>> {
    if !MAPPING_IS_LOCKED {
        return Ok(None);
    }
    let file = match open_locked(path) {
        Ok(file) => file,
        Err(err) if writer_holds(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    if file.metadata()?.len() == 0 {
        return Ok(None);
    }
    // SAFETY: `Mmap::map` is undefined behavior if the file's bytes change
    // while it is mapped, because the mapping is read as `&[u8]`. On Windows
    // `open_locked` denied every other handle write access. Had any other
    // handle or mapped view been able to write the file, the open would have
    // failed with a sharing violation and returned above, and while this
    // handle is open no handle can be opened to write, truncate or extend it.
    // memmap2 duplicates the handle into the map and closes it only when the
    // map is dropped, so the lock lasts exactly as long as the mapping. This
    // process never writes a mapped file either: edits go to the piece
    // table's add buffer, and saves rename a new temp file into place, which
    // replaces the directory entry but never the bytes of a file already open.
    // Writes that bypass the file system, such as raw volume access, are
    // beyond any share mode. Other platforms have no mandatory lock and never
    // reach this point: `MAPPING_IS_LOCKED` is false there and the file is
    // copied instead.
    let mmap = unsafe { Mmap::map(&file)? };
    Ok(Some(Arc::new(mmap)))
}

/// Copies the whole of `path` into memory.
///
/// Used for a file that cannot be mapped and locked. The bytes are read once,
/// up to the length the file had when it was opened, and a writer that
/// changes the file later does not change the copy.
fn read_snapshot(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let len =
        usize::try_from(file_len).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut data = Vec::new();
    data.try_reserve_exact(len).map_err(|e| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!(
                "cannot allocate {len} bytes to copy {}: {e}",
                path.display()
            ),
        )
    })?;
    file.take(file_len).read_to_end(&mut data)?;
    Ok(data)
}

/// A uniquely named file beside a save target, removed unless persisted.
struct TempFile {
    path: PathBuf,
    persisted: bool,
}

impl TempFile {
    /// Creates a new temp file beside `target`, fills it with `write`, and
    /// flushes it to disk.
    ///
    /// The name joins the target's name, this process's id and a per-process
    /// sequence number, and the file is created with `create_new`, so a save
    /// never opens, truncates or replaces a file that already exists, such as
    /// a stale temp file from an earlier crash or one another save is writing.
    fn write_beside(
        target: &Path,
        write: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<Self> {
        let name = target.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("save path {} has no file name", target.display()),
            )
        })?;
        let dir = target.parent().unwrap_or_else(|| Path::new("."));
        let pid = std::process::id();
        for _ in 0..TEMP_NAME_ATTEMPTS {
            let seq = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!(".{}.{pid}-{seq}.tmp", name.to_string_lossy()));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Self::fill(path, file, write),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "no free temp file name beside {} after {TEMP_NAME_ATTEMPTS} attempts",
                target.display()
            ),
        ))
    }

    /// Takes charge of the new file at `path`, then writes and flushes it.
    ///
    /// The guard exists before the first byte is written, so a failed write
    /// or flush drops it and removes the partial file.
    fn fill(
        path: PathBuf,
        mut file: File,
        write: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<Self> {
        let temp = Self {
            path,
            persisted: false,
        };
        let written = write(&mut file).and_then(|()| file.sync_all());
        drop(file);
        written.map(|()| temp)
    }

    /// Moves the temp file onto `target`; on failure the temp is removed.
    ///
    /// When `target` already exists its access control and attributes are
    /// carried onto the saved file rather than lost to a fresh inode, so a
    /// read-only, hidden or ACL-restricted file keeps those after a save.
    fn persist(mut self, target: &Path) -> io::Result<()> {
        replace_target(&self.path, target)?;
        self.persisted = true;
        Ok(())
    }
}

/// Replaces `target` with `temp`, preserving the existing file's metadata.
///
/// On Windows an existing target is replaced with `ReplaceFileW`, which keeps
/// the replaced file's security descriptor, attributes and alternate data
/// streams; a target that does not exist yet is a plain rename, since there is
/// nothing to preserve.
///
/// A target another handle can write is refused rather than replaced: the
/// replace would orphan that writer's file object, so everything it wrote
/// afterwards would land in a file no longer in the directory and be lost
/// while the save reported success. The target is held with
/// [`open_locked`] for the whole replace, which both detects such a writer
/// (the open fails with a sharing violation) and keeps a new one from opening
/// the file between that check and the replace.
#[cfg(windows)]
fn replace_target(temp: &Path, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    if !target.exists() {
        return fs::rename(temp, target);
    }

    let _writer_lock = match open_locked(target) {
        Ok(file) => Some(file),
        Err(err) if writer_holds(&err) => {
            return Err(io::Error::new(
                err.kind(),
                format!(
                    "cannot replace {}: another program has it open for writing ({err})",
                    target.display()
                ),
            ));
        }
        Err(_) => None,
    };

    let wide = |path: &Path| {
        let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
        units.push(0);
        units
    };
    let target_w = wide(target);
    let temp_w = wide(temp);
    // SAFETY: both arguments are valid null-terminated UTF-16 strings that
    // outlive the call; the backup-file and reserved pointers are null and the
    // flags are zero, the documented "replace in place, preserve metadata,
    // no backup" arguments. ReplaceFileW consumes the replacement file on
    // success, which is why the caller then marks the temp persisted.
    let ok = unsafe {
        ReplaceFileW(
            target_w.as_ptr(),
            temp_w.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replaces `target` with `temp`, preserving the existing file's mode.
///
/// A symlink target is resolved first, so the file it points at is replaced
/// and the link is kept, and the existing file's permission bits are copied
/// onto the saved file rather than left at the creating umask.
#[cfg(not(windows))]
fn replace_target(temp: &Path, target: &Path) -> io::Result<()> {
    let resolved = fs::canonicalize(target).unwrap_or_else(|_| target.to_path_buf());
    if let Ok(metadata) = fs::metadata(&resolved) {
        fs::set_permissions(temp, metadata.permissions())?;
    }
    fs::rename(temp, &resolved)
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};

    /// Lists this process's temp files for the save target named `name`.
    fn leftover_temps(dir: &Path, name: &str) -> Vec<PathBuf> {
        let prefix = format!(".{name}.{}-", std::process::id());
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"))
                    && path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(&prefix))
            })
            .collect()
    }

    /// Asserts that `path` cannot be opened for writing because it is locked.
    #[cfg(windows)]
    fn assert_refuses_writers(path: &Path) {
        use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

        let err = OpenOptions::new()
            .write(true)
            .open(path)
            .expect_err("a mapped file must refuse writers");
        assert_eq!(
            err.raw_os_error(),
            i32::try_from(ERROR_SHARING_VIOLATION).ok(),
            "{}: {err}",
            path.display()
        );
    }

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

        drop(doc);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&save_path);
    }

    /// A save must not replace a file another handle is still writing.
    /// Replacing it orphans that writer's file object, so its later writes go
    /// to a file no longer in the directory and are lost while the save reports
    /// success. The save must fail instead, leaving the file on disk to the
    /// writer and removing its own temp file.
    #[cfg(windows)]
    #[test]
    fn test_save_refuses_target_another_handle_is_writing() {
        let dir = std::env::temp_dir();
        let name = format!("hexcore_writer_held_{}.bin", std::process::id());
        let target = dir.join(&name);
        fs::write(&target, b"ORIGINAL").unwrap();
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&target)
            .unwrap();

        let mut doc = MmapDocument::from_bytes(b"REPLACED");
        let saved = doc.save(&target);
        let copied = doc.write_copy(&target);

        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write_all(b"WRITER!!").unwrap();
        writer.sync_all().unwrap();
        drop(writer);

        let on_disk = fs::read(&target).unwrap();
        let leftovers = leftover_temps(&dir, &name);
        let _ = fs::remove_file(&target);

        assert!(
            saved.is_err(),
            "save replaced a file another handle was writing"
        );
        assert!(
            copied.is_err(),
            "write_copy replaced a file another handle was writing"
        );
        assert_eq!(on_disk, b"WRITER!!".to_vec());
        assert!(
            leftovers.is_empty(),
            "refused saves left temp files: {leftovers:?}"
        );
        assert!(
            doc.path.is_none(),
            "a refused save must not adopt the target path"
        );
    }

    /// `write_copy` writes the edited bytes to a separate file but leaves the
    /// document on its own file: same path, still modified, and a later
    /// `save_in_place` still targets the original.
    #[test]
    fn test_write_copy_writes_edits_without_adopting_the_copy() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let source = dir.join(format!("hexcore_write_copy_src_{pid}.bin"));
        let copy_name = format!("hexcore_write_copy_dst_{pid}.bin");
        let copy = dir.join(&copy_name);
        fs::write(&source, b"0123456789").unwrap();

        let mut doc = MmapDocument::open(&source).unwrap();
        doc.insert(2, b"ab");
        doc.delete(8, 2);
        doc.write_copy(&copy).unwrap();

        let copied = fs::read(&copy).unwrap();
        let original = fs::read(&source).unwrap();
        let leftovers = leftover_temps(&dir, &copy_name);
        let path = doc.file_path().map(Path::to_path_buf);
        let still_modified = doc.is_modified();
        drop(doc);
        let _ = fs::remove_file(&source);
        let _ = fs::remove_file(&copy);

        assert_eq!(copied, b"01ab234589".to_vec());
        assert_eq!(original, b"0123456789".to_vec());
        assert_eq!(path, Some(source));
        assert!(
            still_modified,
            "writing a copy must not mark the document saved"
        );
        assert!(
            leftovers.is_empty(),
            "write_copy left temp files: {leftovers:?}"
        );
    }

    #[test]
    fn test_read_all() {
        let mut doc = MmapDocument::from_bytes(b"Hello");
        doc.insert(5, b" World");
        let all = doc.read_all();
        assert_eq!(all, b"Hello World".to_vec());
    }

    #[cfg(windows)]
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

        drop(doc);
        let _ = fs::remove_file(&path);
    }

    /// `save()` must not clear `self.mmap` before the fallible `fs::rename`: a
    /// rename failure (e.g. destination locked or, as forced here, a directory
    /// in the way) would otherwise leave `mmap` cleared even though nothing
    /// was actually saved, and the temp file uncleaned.
    #[test]
    fn test_save_failed_rename_preserves_mmap_and_removes_temp_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_mmap_rename_fail_src.bin");
        {
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"Original content").unwrap();
        }

        let mut doc = MmapDocument::open(&path).unwrap();
        assert_eq!(
            doc.mmap.is_some(),
            MAPPING_IS_LOCKED,
            "open maps the file exactly where the platform can lock it"
        );

        let target_name = "hexcore_test_mmap_rename_fail_target_dir";
        let blocked_target = dir.join(target_name);
        let _ = fs::remove_dir_all(&blocked_target);
        fs::create_dir(&blocked_target).unwrap();

        let result = doc.save(&blocked_target);
        assert!(
            result.is_err(),
            "renaming a file onto an existing directory must fail"
        );
        assert_eq!(
            doc.mmap.is_some(),
            MAPPING_IS_LOCKED,
            "mmap must not be cleared when the rename itself failed"
        );
        assert_eq!(
            leftover_temps(&dir, target_name),
            Vec::<PathBuf>::new(),
            "the temp file must be cleaned up after a failed rename"
        );

        drop(doc);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&blocked_target);
    }

    /// `close()` must drop the memory map and its write lock while preserving
    /// the current content in an owned buffer. Afterwards the file can be
    /// rewritten, and the closed document keeps its own copy, so the rewrite
    /// does not change its bytes.
    #[test]
    fn test_close_releases_mmap_and_preserves_content() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_close_release.bin");
        let original: &[u8] = b"CLOSE ME PLEASE 0123456789";
        fs::write(&path, original).unwrap();

        let mut doc = MmapDocument::open(&path).unwrap();
        assert_eq!(
            doc.mmap.is_some(),
            MAPPING_IS_LOCKED,
            "open maps a non-empty file exactly where the platform can lock it"
        );
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

        drop(doc);
        let _ = fs::remove_file(&path);
    }

    /// Where no mandatory write lock exists, open copies the file instead of
    /// mapping it. Another process truncating a mapped file makes the next read
    /// of a page past the new end raise `SIGBUS` and kill the process; the copy
    /// keeps every byte readable and unchanged.
    #[cfg(not(windows))]
    #[test]
    fn test_open_copies_so_a_truncated_file_cannot_fault_reads() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("hexcore_unix_truncate_{}.bin", std::process::id()));
        let original = vec![0x5Au8; 3 * 4096];
        fs::write(&path, &original).unwrap();

        let doc = MmapDocument::open(&path).unwrap();
        assert!(
            doc.mmap.is_none(),
            "a file must be copied, not mapped, where no write lock exists"
        );

        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(0)
            .unwrap();

        assert_eq!(doc.read_all(), original);
        drop(doc);
        let _ = fs::remove_file(&path);
    }

    /// A save never opens a file that already exists beside its target.
    #[test]
    fn test_save_leaves_a_stale_temp_name_untouched() {
        let dir = std::env::temp_dir();
        let target = dir.join("hexcore_test_tmpname_target.bin");
        let stale = dir.join(".hexcore_test_tmpname_target.bin.tmp");
        fs::write(&stale, b"STALE").unwrap();

        let mut doc = MmapDocument::from_bytes(b"NEW");
        doc.save(&target).unwrap();

        assert_eq!(fs::read(&stale).unwrap(), b"STALE".to_vec());
        assert_eq!(fs::read(&target).unwrap(), b"NEW".to_vec());

        drop(doc);
        let _ = fs::remove_file(&stale);
        let _ = fs::remove_file(&target);
    }

    /// Temp files beside one target get distinct names, and one that
    /// is never persisted is removed.
    #[test]
    fn test_temp_files_beside_one_target_are_distinct_and_cleaned_up() {
        let dir = std::env::temp_dir();
        let name = "hexcore_test_two_temps_target.bin";
        let target = dir.join(name);

        let first = TempFile::write_beside(&target, |file| file.write_all(b"one")).unwrap();
        let second = TempFile::write_beside(&target, |file| file.write_all(b"two")).unwrap();
        assert_ne!(first.path, second.path);
        assert_eq!(fs::read(&first.path).unwrap(), b"one".to_vec());
        assert_eq!(fs::read(&second.path).unwrap(), b"two".to_vec());

        drop(first);
        drop(second);
        assert_eq!(leftover_temps(&dir, name), Vec::<PathBuf>::new());
        assert!(
            !target.exists(),
            "an unpersisted temp must never reach the target"
        );
    }

    /// A write that fails part-way leaves neither a temp file nor a
    /// changed target.
    #[test]
    fn test_failed_write_removes_the_partial_temp_file() {
        let dir = std::env::temp_dir();
        let name = "hexcore_test_failed_write_target.bin";
        let target = dir.join(name);
        fs::write(&target, b"Original content").unwrap();

        let Err(err) = TempFile::write_beside(&target, |file| {
            file.write_all(b"PART")?;
            Err(io::Error::new(io::ErrorKind::StorageFull, "disk full"))
        }) else {
            panic!("a failing write must fail the save");
        };

        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        assert_eq!(leftover_temps(&dir, name), Vec::<PathBuf>::new());
        assert_eq!(fs::read(&target).unwrap(), b"Original content".to_vec());

        let _ = fs::remove_file(&target);
    }

    /// `is_modified` follows the bytes, not the edit calls.
    #[test]
    fn test_is_modified_follows_the_bytes() {
        let mut doc = MmapDocument::from_bytes(b"AB");
        doc.overwrite(5, b"X");
        doc.overwrite(0, b"A");
        doc.insert(1, b"");
        doc.delete(1, 0);
        assert!(!doc.is_modified());

        doc.overwrite(0, b"Z");
        assert!(doc.is_modified());
        doc.overwrite(0, b"A");
        assert!(
            !doc.is_modified(),
            "restoring the original byte undoes the change"
        );

        doc.apply_insert(2, b"C");
        assert!(doc.is_modified());
        doc.apply_delete(2, 1);
        assert!(!doc.is_modified());
    }

    /// Closing keeps a modified document modified and a clean one clean.
    #[test]
    fn test_close_keeps_the_modified_state() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_close_modified.bin");
        fs::write(&path, b"Original").unwrap();

        let mut clean = MmapDocument::open(&path).unwrap();
        clean.close();
        assert!(!clean.is_modified());

        let mut edited = MmapDocument::open(&path).unwrap();
        edited.overwrite(0, b"Edited!!");
        edited.close();
        assert!(edited.is_modified());
        assert_eq!(edited.read_all(), b"Edited!!".to_vec());

        edited.save(&path).unwrap();
        assert!(!edited.is_modified());
        assert_eq!(fs::read(&path).unwrap(), b"Edited!!".to_vec());

        drop(clean);
        drop(edited);
        let _ = fs::remove_file(&path);
    }

    /// An open document locks its file against writers until the
    /// mapping is released.
    #[cfg(windows)]
    #[test]
    fn test_open_locks_the_file_against_writers_while_mapped() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_write_lock.bin");
        fs::write(&path, b"LOCKED CONTENT").unwrap();

        let mut doc = MmapDocument::open(&path).unwrap();
        assert!(doc.mmap.is_some());
        assert_refuses_writers(&path);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"LOCKED CONTENT".to_vec(),
            "readers stay allowed"
        );

        doc.close();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("closing must release the lock");

        drop(doc);
        let _ = fs::remove_file(&path);
    }

    /// A file that another handle is writing is copied, not mapped.
    #[cfg(windows)]
    #[test]
    fn test_open_copies_a_file_another_handle_is_writing() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_writer_snapshot.bin");
        let mut writer = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"ORIGINAL").unwrap();

        let doc = MmapDocument::open(&path).expect("a file being written must still open");
        assert!(
            doc.mmap.is_none(),
            "a file another handle can write must not be mapped"
        );
        assert_eq!(doc.read_all(), b"ORIGINAL".to_vec());

        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write_all(b"CHANGED!").unwrap();
        assert_eq!(doc.read_all(), b"ORIGINAL".to_vec());

        drop(writer);
        drop(doc);
        let _ = fs::remove_file(&path);
    }

    /// Saving over the mapped file round-trips and locks it again, and
    /// Save As moves the lock to the new file.
    #[cfg(windows)]
    #[test]
    fn test_save_relocks_the_saved_file() {
        let dir = std::env::temp_dir();
        let first = dir.join("hexcore_test_relock_a.bin");
        let second = dir.join("hexcore_test_relock_b.bin");
        fs::write(&first, b"Original content").unwrap();

        let mut doc = MmapDocument::open(&first).unwrap();
        doc.overwrite(0, b"Modified");
        doc.save(&first)
            .expect("saving over the mapped file must succeed");
        assert_eq!(fs::read(&first).unwrap(), b"Modified content".to_vec());
        assert!(!doc.is_modified());
        assert!(doc.mmap.is_some(), "the saved file must be mapped again");
        assert_refuses_writers(&first);

        doc.save(&second).unwrap();
        assert_eq!(doc.file_path(), Some(second.as_path()));
        assert_refuses_writers(&second);
        OpenOptions::new()
            .write(true)
            .open(&first)
            .expect("Save As must release the old file");

        drop(doc);
        let _ = fs::remove_file(&first);
        let _ = fs::remove_file(&second);
    }

    /// Saving over an existing file keeps its attributes, which a plain
    /// rename to a fresh inode would drop.
    #[cfg(windows)]
    #[test]
    fn test_save_preserves_existing_file_attributes() {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};

        let dir = std::env::temp_dir();
        let path = dir.join("hexcore_test_attr_preserved.bin");
        fs::write(&path, b"Original content").unwrap();

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is a valid null-terminated UTF-16 path that outlives
        // the call.
        let set = unsafe { SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) };
        assert_ne!(set, 0, "marking the fixture hidden must succeed");

        let mut doc = MmapDocument::from_bytes(b"Modified content");
        doc.save(&path).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"Modified content".to_vec());
        let attributes = fs::metadata(&path).unwrap().file_attributes();
        assert_ne!(
            attributes & FILE_ATTRIBUTE_HIDDEN,
            0,
            "a save must keep the replaced file hidden, got attributes {attributes:#x}"
        );

        // Clear the attribute so the fixture can be removed.
        // SAFETY: same valid null-terminated path as above.
        unsafe { SetFileAttributesW(wide.as_ptr(), 0x80) };
        drop(doc);
        let _ = fs::remove_file(&path);
    }
}
