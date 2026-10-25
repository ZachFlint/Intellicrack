// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

pub mod bps_ups;
pub mod data_inspector;
pub mod data_source;
pub mod diff;
pub mod encodings;
pub mod entropy;
pub mod hash;
pub mod mmap_io;
pub mod patch_export;
pub mod piece_table;
pub mod search;
pub mod strings;
pub mod templates;
pub mod transforms;
pub mod undo;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use pyo3::exceptions::{PyIOError, PyIndexError, PyRuntimeError, PyValueError};
use pyo3::marker::Ungil;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use mmap_io::MmapDocument;
use templates::TemplateRegistry;
use undo::{Operation, UndoManager};

/// Bytes handed to the data inspector: enough for its widest view, the
/// 32-code-unit UTF-16 string.
const INSPECT_WINDOW: usize = 64;

/// Read size a new document's chunked operations start with.
const DEFAULT_CHUNK_SIZE_HINT: usize = 4 * 1024 * 1024;

/// Memory budget a new document reports until a client sets its own.
const DEFAULT_MEMORY_BUDGET_HINT: usize = 512 * 1024 * 1024;

/// Maps any displayable engine error to a Python `ValueError`.
fn value_error(error: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(error.to_string())
}

/// Rejects a zero block size, which would otherwise yield an empty result
/// indistinguishable from an empty document.
fn check_block_size(block_size: usize) -> PyResult<()> {
    if block_size == 0 {
        return Err(PyValueError::new_err("block_size must be at least 1"));
    }
    Ok(())
}

/// A named, colored byte range the user pinned in a document.
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct Bookmark {
    /// First byte of the range.
    #[pyo3(get, set)]
    pub offset: usize,
    /// Number of bytes in the range.
    #[pyo3(get, set)]
    pub length: usize,
    /// User-visible name.
    #[pyo3(get, set)]
    pub label: String,
    /// Display color, as the UI's color string.
    #[pyo3(get, set)]
    pub color: String,
}

#[pymethods]
impl Bookmark {
    #[new]
    fn new(offset: usize, length: usize, label: String, color: String) -> Self {
        Self {
            offset,
            length,
            label,
            color,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Bookmark(offset={}, length={}, label='{}', color='{}')",
            self.offset, self.length, self.label, self.color
        )
    }
}

/// Everything one open document owns, with no synchronization of its own.
///
/// Only [`HexDocument`] may hold one of these, and only behind its lock, so the
/// methods here are free to take `&mut self`.
pub struct DocumentState {
    inner: MmapDocument,
    undo_mgr: UndoManager,
    bookmarks: Vec<Bookmark>,
    template_registry: TemplateRegistry,
    va_mappings: Vec<(usize, u64, usize)>,
    generation: u64,
}

/// One open document, safe to share across threads.
///
/// This is `frozen` so `PyO3` hands out `&self` and never an exclusive borrow.
/// Without it, the mutating methods would force `PyO3` to take a `RefCell`
/// borrow for the duration of the call, and because the long analyses hold that
/// borrow across `Python::detach`, any second thread touching the same document
/// would get `RuntimeError: Already borrowed`. Serializing every call behind a
/// caller-side lock would also serialize the read-only analyses that can safely
/// run together.
///
/// # Locking
///
/// Every acquisition of `state` **must** happen inside `Python::detach`, which
/// is what the private `lock_read` and `lock_write` helpers do. Taking the lock
/// while still holding the GIL deadlocks: a writer that is inside `detach` has
/// released the GIL but still holds this lock, so a second thread that blocks on
/// the lock *while holding the GIL* stops the writer from ever re-acquiring the
/// GIL to finish and release. Acquiring inside `detach` is why several methods
/// below take a `Python` token they would not otherwise need.
///
/// `parking_lot`'s `send_guard` feature is required because `lock_read` and
/// `lock_write` return the guard *out of* `Python::detach`, and `detach`'s
/// return value must be `Ungil` (which on stable means `Send`); the guard is
/// `Send` only with that feature. `detach` runs the closure on the calling
/// thread, so the guard never actually migrates — the bound is what makes the
/// return type-check.
///
/// For the same reason no `#[pymethods]` function may call another: it would
/// take the lock twice and `RwLock` is not reentrant. The facade delegates to
/// [`DocumentState`] instead, which is where the logic lives.
///
/// The size hints sit outside the lock as atomics. They are tuning values a
/// client may read or change at any moment, and keeping them behind `state`
/// would make a hint update queue a writer behind a long chunked hash, which
/// in turn stalls every reader that arrives after it.
#[pyclass(frozen)]
pub struct HexDocument {
    state: RwLock<DocumentState>,
    chunk_size_hint: AtomicUsize,
    memory_budget_hint: AtomicUsize,
}

impl HexDocument {
    /// Wrap freshly built state.
    fn wrap(state: DocumentState) -> Self {
        Self {
            state: RwLock::new(state),
            chunk_size_hint: AtomicUsize::new(DEFAULT_CHUNK_SIZE_HINT),
            memory_budget_hint: AtomicUsize::new(DEFAULT_MEMORY_BUDGET_HINT),
        }
    }

    /// The read size chunked operations use: the client's hint, but never
    /// below 64 KiB, so a tiny hint cannot turn a hash into millions of reads.
    fn chunk_size(&self) -> usize {
        self.chunk_size_hint.load(Ordering::Relaxed).max(65536)
    }

    /// Borrow the document for reading, releasing the GIL while blocking.
    fn lock_read(&self, py: Python<'_>) -> RwLockReadGuard<'_, DocumentState> {
        py.detach(|| self.state.read())
    }

    /// Borrow the document for writing, releasing the GIL while blocking.
    fn lock_write(&self, py: Python<'_>) -> RwLockWriteGuard<'_, DocumentState> {
        py.detach(|| self.state.write())
    }

    /// The locking core of [`HexDocument::analyze`]: copy the whole document
    /// under a read guard, drop the guard, then run `f` on the owned snapshot.
    ///
    /// The guard is a local that is dropped at the end of the copy statement, so
    /// `f` runs with no lock held. A long read-only analysis therefore cannot
    /// keep a queued writer from acquiring the lock and, through it, stall other
    /// readers behind that writer.
    ///
    /// This acquires the lock directly, so — like every other `state`
    /// acquisition — it must run with the GIL released. `analyze` guarantees
    /// that by only ever calling it inside `Python::detach`; the tests call it
    /// from a non-Python context, where no GIL exists.
    fn analyze_locked<T, F: FnOnce(&[u8]) -> T>(&self, f: F) -> T {
        let data = self.state.read().inner.read_all();
        f(&data)
    }

    /// Runs an edit with the write lock taken and held inside `Python::detach`.
    ///
    /// The lock is acquired with the GIL released, as every acquisition must
    /// be, and the edit and its undo record complete before the GIL is taken
    /// back. A large fill, copy, move, swap or delete therefore holds the
    /// document lock but never the GIL, so other Python threads, the UI among
    /// them, keep running while it copies.
    fn edit_detached<T, F>(&self, py: Python<'_>, edit: F) -> T
    where
        F: FnOnce(&mut DocumentState) -> T + Ungil + Send,
        T: Ungil + Send,
    {
        py.detach(move || edit(&mut self.state.write()))
    }

    /// Runs a whole-document analysis under the snapshot-then-detach discipline,
    /// with the GIL released throughout.
    ///
    /// This is the one place the read-only whole-document analyses funnel
    /// through: the read guard covers only the O(document) copy, never the
    /// compute, so none of them holds the lock across a long scan.
    fn analyze<T, F>(&self, py: Python<'_>, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T + Ungil + Send,
        T: Ungil + Send,
    {
        py.detach(move || self.analyze_locked(f))
    }
}

impl DocumentState {
    fn new() -> Self {
        Self {
            inner: MmapDocument::new_empty(),
            undo_mgr: UndoManager::new(),
            bookmarks: Vec::new(),
            template_registry: TemplateRegistry::new(),
            va_mappings: Vec::new(),
            generation: 0,
        }
    }

    fn open(path: &str) -> PyResult<Self> {
        let doc = MmapDocument::open(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        Ok(Self {
            inner: doc,
            undo_mgr: UndoManager::new(),
            bookmarks: Vec::new(),
            template_registry: TemplateRegistry::new(),
            va_mappings: Vec::new(),
            generation: 0,
        })
    }

    fn open_bytes(data: &[u8]) -> Self {
        Self {
            inner: MmapDocument::from_bytes(data),
            undo_mgr: UndoManager::new(),
            bookmarks: Vec::new(),
            template_registry: TemplateRegistry::new(),
            va_mappings: Vec::new(),
            generation: 0,
        }
    }

    /// Record that the bytes changed.
    ///
    /// Only content edits advance this. Saving, bookmarks, VA mappings,
    /// templates and the size hints leave it alone, so a client may treat it as
    /// a version for the bytes themselves and cache reads against it.
    fn touch(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    /// Records `op` and advances the generation, unless `op` changed no byte.
    ///
    /// Every content edit funnels through here, so a no-op (an empty write,
    /// rewriting a byte with its own value, repairing a valid checksum)
    /// leaves no undo entry, does not mark the document modified, and keeps
    /// cached reads valid.
    fn commit(&mut self, op: Operation) {
        if op.changes_bytes() {
            self.undo_mgr.record(op);
            self.touch();
        }
    }

    /// Rejects an `offset` past the end of the document, as `read` does.
    fn check_offset(&self, offset: usize) -> PyResult<()> {
        let size = self.inner.document_size();
        if offset > size {
            return Err(PyValueError::new_err(format!(
                "offset {offset} beyond document size {size}"
            )));
        }
        Ok(())
    }

    /// Replaces every byte of the document in place, keeping its file path,
    /// and records the change as one undoable [`Operation::Replace`].
    fn replace_document(&mut self, old_data: Vec<u8>, new_data: Vec<u8>) {
        let len = self.inner.document_size();
        self.inner.apply_delete(0, len);
        self.inner.apply_insert(0, &new_data);
        self.commit(Operation::Replace { old_data, new_data });
    }

    fn save(&mut self, py: Python<'_>, path: &str) -> PyResult<()> {
        py.detach(|| self.inner.save(path))
            .map_err(|e| PyIOError::new_err(e.to_string()))?;
        self.undo_mgr.mark_saved();
        Ok(())
    }

    fn save_as(&mut self, py: Python<'_>, path: &str) -> PyResult<()> {
        self.save(py, path)
    }

    /// Writes the current bytes to `path` without adopting it.
    ///
    /// Unlike `save`, the document keeps its own path, mapping and modified
    /// state, so a scratch copy (for example one handed to a sandbox and then
    /// deleted) never becomes the file a later Save writes to. The copy is
    /// written through a temp file and renamed into place, as `save` is.
    fn save_copy(&self, py: Python<'_>, path: &str) -> PyResult<()> {
        py.detach(|| self.inner.write_copy(path))
            .map_err(|e| PyIOError::new_err(format!("Failed to write {path}: {e}")))
    }

    fn close(&mut self, py: Python<'_>) {
        py.detach(|| self.inner.close());
    }

    fn length(&self) -> usize {
        self.inner.document_size()
    }

    fn read(&self, offset: usize, length: usize) -> PyResult<Vec<u8>> {
        self.check_offset(offset)?;
        Ok(self.inner.read(offset, length))
    }

    fn read_byte(&self, offset: usize) -> PyResult<u8> {
        self.inner
            .read_byte(offset)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))
    }

    fn write_bytes(&mut self, offset: usize, data: &[u8]) -> PyResult<()> {
        let size = self.inner.document_size();
        if offset >= size {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "offset {offset} beyond document size {size}"
            )));
        }
        // Reject an overrun instead of silently truncating it: a write whose
        // bytes run past the end would otherwise drop the overflow with no
        // signal to the caller. `overwrite` cannot grow the document, so a
        // caller that means to grow it must use `insert_bytes`.
        if offset.checked_add(data.len()).is_none_or(|end| end > size) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "write of {} bytes at offset {offset} runs past the end of the {size}-byte document; use insert_bytes to grow it",
                data.len()
            )));
        }

        let old_data = self.inner.read(offset, data.len());
        self.inner.overwrite(offset, data);
        self.commit(Operation::Overwrite {
            offset,
            old_data,
            new_data: data.to_vec(),
        });
        Ok(())
    }

    fn insert_bytes(&mut self, offset: usize, data: &[u8]) -> PyResult<()> {
        if offset > self.inner.document_size() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "offset {} beyond document size {}",
                offset,
                self.inner.document_size()
            )));
        }

        self.inner.insert(offset, data);
        self.commit(Operation::Insert {
            offset,
            data: data.to_vec(),
        });
        Ok(())
    }

    fn delete_bytes(&mut self, offset: usize, length: usize) -> PyResult<()> {
        if offset >= self.inner.document_size() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "offset {} beyond document size {}",
                offset,
                self.inner.document_size()
            )));
        }

        let actual_len = length.min(self.inner.document_size() - offset);
        let deleted_data = self.inner.read(offset, actual_len);
        self.inner.delete(offset, actual_len);
        self.commit(Operation::Delete {
            offset,
            deleted_data,
        });
        Ok(())
    }

    fn undo(&mut self) -> bool {
        let changed = self.undo_mgr.undo(&mut self.inner);
        if changed {
            self.touch();
        }
        changed
    }

    fn redo(&mut self) -> bool {
        let changed = self.undo_mgr.redo(&mut self.inner);
        if changed {
            self.touch();
        }
        changed
    }

    fn can_undo(&self) -> bool {
        self.undo_mgr.can_undo()
    }

    fn can_redo(&self) -> bool {
        self.undo_mgr.can_redo()
    }

    fn is_modified(&self) -> bool {
        self.undo_mgr.is_modified()
    }

    fn replace_bytes(
        &mut self,
        py: Python<'_>,
        pattern: &[u8],
        replacement: &[u8],
    ) -> PyResult<usize> {
        if pattern.is_empty() {
            return Err(PyValueError::new_err("pattern cannot be empty"));
        }
        let (old_data, new_data, count) = py.detach(|| {
            let data = self.inner.read_all();
            let (new_data, count) = search::replace_all(&data, pattern, replacement);
            (data, new_data, count)
        });
        if count > 0 {
            self.replace_document(old_data, new_data);
        }
        Ok(count)
    }

    /// Interprets the bytes at `offset` with [`data_inspector::inspect_at`].
    ///
    /// The window is [`INSPECT_WINDOW`] bytes (clamped at the end of the
    /// document) so every interpretation, including the 32-unit wide string,
    /// sees the bytes it needs; an `offset` at or past the end yields none.
    fn inspection(&self, offset: usize) -> data_inspector::DataInspection {
        let needed = INSPECT_WINDOW.min(self.inner.document_size().saturating_sub(offset));
        data_inspector::inspect_at(&self.inner.read(offset, needed), 0)
    }

    fn inspect_at(&self, py: Python<'_>, offset: usize) -> PyResult<Py<PyAny>> {
        let inspection = self.inspection(offset);
        let dict = PyDict::new(py);
        for (key, value) in inspection.to_map() {
            dict.set_item(key, value)?;
        }
        Ok(dict.into())
    }

    /// Clamps `start..end` to the document, rejecting a start past the end.
    fn checked_range(&self, start: usize, end: usize) -> PyResult<(usize, usize)> {
        let actual_end = end.min(self.inner.document_size());
        if start > actual_end {
            return Err(PyValueError::new_err(format!(
                "invalid range: start={start}, end={end} (document size {})",
                self.inner.document_size()
            )));
        }
        Ok((start, actual_end))
    }

    /// Streams `start..end` through `algorithm` in `chunk_size` reads,
    /// releasing the GIL for each chunk, so no range is ever materialized.
    fn stream_hash(
        &self,
        py: Python<'_>,
        (start, end): (usize, usize),
        algorithm: &str,
        chunk_size: usize,
    ) -> PyResult<String> {
        let mut hasher = hash::StreamingHasher::new(algorithm).map_err(value_error)?;
        let mut offset = start;
        while offset < end {
            let len = chunk_size.min(end - offset);
            py.detach(|| hasher.update(&self.inner.read(offset, len)));
            offset += len;
        }
        Ok(hasher.finalize().hex_digest)
    }

    fn compute_hash(&self, py: Python<'_>, algorithm: &str, chunk_size: usize) -> PyResult<String> {
        self.stream_hash(py, (0, self.inner.document_size()), algorithm, chunk_size)
    }

    fn compute_hash_range(
        &self,
        py: Python<'_>,
        (start, end): (usize, usize),
        algorithm: &str,
        chunk_size: usize,
    ) -> PyResult<String> {
        let range = self.checked_range(start, end)?;
        self.stream_hash(py, range, algorithm, chunk_size)
    }

    fn byte_statistics(&self, py: Python<'_>, chunk_size: usize) -> Vec<(u8, usize)> {
        let mut counts = [0usize; 256];
        let doc_size = self.inner.document_size();
        let mut offset: usize = 0;
        while offset < doc_size {
            let len = chunk_size.min(doc_size - offset);
            py.detach(|| {
                for &b in &self.inner.read(offset, len) {
                    counts[usize::from(b)] += 1;
                }
            });
            offset += len;
        }
        counts
            .iter()
            .copied()
            .enumerate()
            .map(|(byte_val, count)| {
                let byte = u8::try_from(byte_val).expect("index within 0..256");
                (byte, count)
            })
            .collect()
    }

    fn add_bookmark(&mut self, offset: usize, length: usize, label: &str, color: &str) -> usize {
        self.add_bookmark_object(Bookmark {
            offset,
            length,
            label: label.to_string(),
            color: color.to_string(),
        })
    }

    fn add_bookmark_object(&mut self, bookmark: Bookmark) -> usize {
        let idx = self.bookmarks.len();
        self.bookmarks.push(bookmark);
        idx
    }

    fn remove_bookmark(&mut self, index: usize) -> bool {
        if index < self.bookmarks.len() {
            self.bookmarks.remove(index);
            true
        } else {
            false
        }
    }

    fn list_bookmarks(&self) -> Vec<(usize, usize, String, String)> {
        self.bookmarks
            .iter()
            .map(|b| (b.offset, b.length, b.label.clone(), b.color.clone()))
            .collect()
    }

    fn get_bookmarks(&self) -> Vec<Bookmark> {
        self.bookmarks.clone()
    }

    fn get_bookmark(&self, index: usize) -> Option<Bookmark> {
        self.bookmarks.get(index).cloned()
    }

    fn update_bookmark(&mut self, index: usize, bookmark: Bookmark) -> bool {
        match self.bookmarks.get_mut(index) {
            Some(slot) => {
                *slot = bookmark;
                true
            }
            None => false,
        }
    }

    fn apply_template(&self, py: Python<'_>, name: &str, offset: usize) -> PyResult<Py<PyAny>> {
        fn field_to_dict(py: Python<'_>, field: &templates::ParsedField) -> PyResult<Py<PyAny>> {
            let dict = PyDict::new(py);
            dict.set_item("name", &field.name)?;
            dict.set_item("offset", field.offset)?;
            dict.set_item("size", field.size)?;
            dict.set_item("raw_bytes", &field.raw_bytes)?;
            dict.set_item("display_value", &field.display_value)?;
            dict.set_item("description", &field.description)?;

            match &field.color {
                Some(c) => dict.set_item("color", c)?,
                None => dict.set_item("color", py.None())?,
            }

            match field.validation_passed {
                Some(v) => dict.set_item("validation_passed", v)?,
                None => dict.set_item("validation_passed", py.None())?,
            }

            let children = PyList::empty(py);
            for child in &field.children {
                children.append(field_to_dict(py, child)?)?;
            }
            dict.set_item("children", children)?;
            Ok(dict.into())
        }

        let fields = py
            .detach(|| {
                self.template_registry
                    .apply(name, &self.inner.read_all(), offset)
            })
            .map_err(value_error)?;

        let result = PyList::empty(py);
        for field in &fields {
            result.append(field_to_dict(py, field)?)?;
        }
        Ok(result.into())
    }

    fn list_templates(&self) -> Vec<(String, String)> {
        self.template_registry.list()
    }

    fn register_json_template(&mut self, json_str: &str) -> PyResult<String> {
        self.template_registry
            .register_json(json_str)
            .map_err(value_error)
    }

    fn remove_template(&mut self, name: &str) -> bool {
        self.template_registry.remove(name)
    }

    fn export_template_json(&self, name: &str) -> PyResult<String> {
        self.template_registry
            .export_json(name)
            .map_err(value_error)
    }

    fn list_templates_detailed(&self) -> Vec<(String, String, String, usize)> {
        self.template_registry.list_detailed()
    }

    fn file_path(&self) -> Option<String> {
        self.inner
            .file_path()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn read_window(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
    ) -> PyResult<(Vec<u8>, Vec<u8>, u64, usize)> {
        self.check_offset(offset)?;
        let size = self.inner.document_size();
        let (data, classes) = py.detach(|| {
            let data = self.inner.read(offset, length);
            let classes = entropy::classify_bytes(&data);
            (data, classes)
        });
        Ok((data, classes, self.generation, size))
    }

    fn current_generation(&self) -> u64 {
        self.generation
    }

    fn transform_data(
        &self,
        py: Python<'_>,
        name: &str,
        offset: usize,
        length: usize,
        params: HashMap<String, Vec<u8>>,
    ) -> PyResult<Vec<u8>> {
        self.check_offset(offset)?;
        py.detach(move || {
            transforms::apply_transform(name, &self.inner.read(offset, length), &params)
        })
        .map_err(value_error)
    }

    fn list_transforms() -> Vec<(String, String, String)> {
        transforms::list_transforms()
            .into_iter()
            .map(|t| (t.name, t.category, t.description))
            .collect()
    }

    fn get_patches(&self) -> Vec<(usize, Vec<u8>)> {
        self.undo_mgr.get_overwrite_patches()
    }

    /// Collapses the history into disjoint patch records for export.
    ///
    /// # Errors
    ///
    /// Returns `PyValueError` when the history contains an insert, a delete,
    /// a truncation or a length-changing replacement: those shift offsets, so
    /// no overwrite-only patch applied to the original file reproduces them.
    fn exportable_records(&self) -> PyResult<Vec<patch_export::PatchRecord>> {
        if !self.undo_mgr.is_overwrite_only() {
            return Err(PyValueError::new_err(
                "the edit history inserts, deletes or resizes bytes; an overwrite-only patch \
                 (IPS, IPS32, COD, JSON) cannot reproduce it, use BPS or UPS instead",
            ));
        }
        Ok(patch_export::extract_patches_from_overwrites(
            &self.undo_mgr.get_overwrite_patches(),
        ))
    }

    fn export_patches_ips(&self) -> PyResult<Vec<u8>> {
        let records = self.exportable_records()?;
        patch_export::export_ips(&records, &|offset| self.inner.read_byte(offset).ok())
            .map_err(value_error)
    }

    fn export_patches_ips32(&self) -> PyResult<Vec<u8>> {
        let records = self.exportable_records()?;
        patch_export::export_ips32(&records, &|offset| self.inner.read_byte(offset).ok())
            .map_err(value_error)
    }

    fn export_patches_cod(&self) -> PyResult<Vec<u8>> {
        patch_export::export_cod(&self.exportable_records()?).map_err(value_error)
    }

    fn export_patches_json(&self) -> PyResult<String> {
        patch_export::export_patches_json(&self.exportable_records()?).map_err(value_error)
    }

    fn import_patches_ips(&mut self, data: &[u8]) -> PyResult<usize> {
        let size = self.inner.document_size();
        let parsed = patch_export::import_ips_patch(data, size).map_err(value_error)?;
        let mut writes = Vec::with_capacity(parsed.runs.len());
        for run in parsed.runs {
            let old_data = self.inner.read(run.offset, run.data.len());
            self.inner.overwrite(run.offset, &run.data);
            writes.push((run.offset, old_data, run.data));
        }
        let truncated = parsed.truncate_to.map(|new_len| {
            let tail = self.inner.read(new_len, size - new_len);
            self.inner.delete(new_len, size - new_len);
            (new_len, tail)
        });
        self.commit(Operation::PatchImport { writes, truncated });
        Ok(parsed.applied_records)
    }

    fn decode_text(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
        encoding: &str,
    ) -> PyResult<String> {
        self.check_offset(offset)?;
        let (text, _) = py
            .detach(|| encodings::decode_text(&self.inner.read(offset, length), encoding))
            .map_err(value_error)?;
        Ok(text)
    }

    fn encode_text_to_bytes(text: &str, encoding: &str) -> PyResult<Vec<u8>> {
        encodings::encode_text(text, encoding).map_err(value_error)
    }

    fn list_encodings() -> Vec<(String, String)> {
        encodings::list_encodings()
    }

    fn compute_hash_custom_crc(
        &self,
        py: Python<'_>,
        byte_range: (usize, usize),
        poly: u64,
        init: u64,
        width: u8,
        reflect: (bool, bool),
        xorout: u64,
    ) -> PyResult<String> {
        let (start, end) = self.checked_range(byte_range.0, byte_range.1)?;
        let (refin, refout) = reflect;
        py.detach(|| {
            hash::compute_crc_custom(
                &self.inner.read(start, end - start),
                width,
                poly,
                init,
                refin,
                refout,
                xorout,
            )
        })
        .map_err(value_error)
    }

    fn from_process_memory(
        py: Python<'_>,
        pid: u32,
        address: usize,
        size: usize,
    ) -> PyResult<Self> {
        #[cfg(windows)]
        {
            use data_source::{DataSource, ProcessDataSource};
            let data = py
                .detach(|| {
                    ProcessDataSource::attach(pid, address, size, true)
                        .and_then(|source| source.read(0, size))
                })
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(Self::open_bytes(&data))
        }
        #[cfg(not(windows))]
        {
            let _ = (py, pid, address, size);
            Err(PyRuntimeError::new_err(
                "process memory only supported on Windows",
            ))
        }
    }

    fn list_process_memory_regions(pid: u32) -> PyResult<Vec<(usize, usize, u32, u32)>> {
        #[cfg(windows)]
        {
            use data_source::ProcessDataSource;
            let source = ProcessDataSource::attach(pid, 0, 0, true)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let regions = source
                .list_regions()
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(regions
                .iter()
                .map(|r| (r.base_address, r.size, r.protection, r.state))
                .collect())
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            Err(PyRuntimeError::new_err(
                "process memory only supported on Windows",
            ))
        }
    }

    fn export_patches_bps(&self, py: Python<'_>, source_data: &[u8]) -> PyResult<Vec<u8>> {
        py.detach(|| bps_ups::export_bps(source_data, &self.inner.read_all()))
            .map_err(value_error)
    }

    /// Export a BPS patch by loading the source file inside Rust.
    ///
    /// Avoids the round-trip through Python `bytes` that
    /// `export_patches_bps` requires: the source is loaded with
    /// `mmap_io::load_stable` (on Windows mapped read-only and locked against
    /// writers unless the file is empty or another handle can write it, and
    /// copied into memory otherwise and on every other platform) and the
    /// resulting slice is handed directly to the encoder. The target is read out
    /// of this document's piece table without crossing the FFI boundary.
    fn export_patches_bps_from_path(&self, py: Python<'_>, source_path: &str) -> PyResult<Vec<u8>> {
        py.detach(|| self.export_patch_from_path_inner(source_path, bps_ups::export_bps))
    }

    /// Replaces the document with the target a BPS/UPS patch produces from
    /// `source_data`, as one undoable edit that keeps the file path.
    fn import_whole_patch(
        &mut self,
        py: Python<'_>,
        decode: impl FnOnce() -> std::io::Result<Vec<u8>> + Send,
    ) -> PyResult<usize> {
        let (old_data, target) = py
            .detach(|| decode().map(|target| (self.inner.read_all(), target)))
            .map_err(value_error)?;
        let target_len = target.len();
        self.replace_document(old_data, target);
        Ok(target_len)
    }

    fn import_patches_bps(
        &mut self,
        py: Python<'_>,
        patch_data: &[u8],
        source_data: &[u8],
    ) -> PyResult<usize> {
        self.import_whole_patch(py, || bps_ups::import_bps(patch_data, source_data))
    }

    fn export_patches_ups(&self, py: Python<'_>, source_data: &[u8]) -> PyResult<Vec<u8>> {
        py.detach(|| bps_ups::export_ups(source_data, &self.inner.read_all()))
            .map_err(value_error)
    }

    /// Export a UPS patch by loading the source file inside Rust.
    ///
    /// Mirrors `export_patches_bps_from_path`: the source path is loaded with
    /// `mmap_io::load_stable`, so on Windows the source is normally mapped
    /// rather than held as an owned `Vec<u8>`; it is copied when the file is
    /// empty or another handle can write it, and always on other platforms.
    fn export_patches_ups_from_path(&self, py: Python<'_>, source_path: &str) -> PyResult<Vec<u8>> {
        py.detach(|| self.export_patch_from_path_inner(source_path, bps_ups::export_ups))
    }

    fn import_patches_ups(
        &mut self,
        py: Python<'_>,
        patch_data: &[u8],
        source_data: &[u8],
    ) -> PyResult<usize> {
        self.import_whole_patch(py, || bps_ups::import_ups(patch_data, source_data))
    }

    /// Rejects a block that does not lie entirely inside the document.
    fn check_block(&self, offset: usize, length: usize) -> PyResult<()> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.inner.document_size())
        {
            return Err(PyValueError::new_err("block exceeds document size"));
        }
        Ok(())
    }

    fn fill_block(&mut self, offset: usize, length: usize, pattern: &[u8]) -> PyResult<()> {
        if pattern.is_empty() {
            return Err(PyValueError::new_err("pattern cannot be empty"));
        }
        self.check_block(offset, length)?;
        let fill: Vec<u8> = pattern.iter().cycle().take(length).copied().collect();
        let old_data = self.inner.read(offset, length);
        self.inner.overwrite(offset, &fill);
        self.commit(Operation::Overwrite {
            offset,
            old_data,
            new_data: fill,
        });
        Ok(())
    }

    fn copy_block(&mut self, src_offset: usize, length: usize, dst_offset: usize) -> PyResult<()> {
        self.check_block(src_offset, length)?;
        self.check_block(dst_offset, length)?;
        let data = self.inner.read(src_offset, length);
        let old_dst = self.inner.read(dst_offset, length);
        self.inner.overwrite(dst_offset, &data);
        self.commit(Operation::Overwrite {
            offset: dst_offset,
            old_data: old_dst,
            new_data: data,
        });
        Ok(())
    }

    fn move_block(&mut self, src_offset: usize, length: usize, dst_offset: usize) -> PyResult<()> {
        self.check_block(src_offset, length)?;
        self.check_block(dst_offset, length)?;
        if (src_offset < dst_offset + length) && (dst_offset < src_offset + length) {
            return Err(PyValueError::new_err(
                "source and destination blocks overlap",
            ));
        }
        let data = self.inner.read(src_offset, length);
        let old_dst = self.inner.read(dst_offset, length);
        let zeros = vec![0u8; length];
        self.inner.overwrite(src_offset, &zeros);
        self.inner.overwrite(dst_offset, &data);
        self.commit(Operation::MoveBlock {
            src_offset,
            dst_offset,
            moved_data: data,
            old_dst_data: old_dst,
        });
        Ok(())
    }

    fn swap_blocks(
        &mut self,
        offset_a: usize,
        len_a: usize,
        offset_b: usize,
        len_b: usize,
    ) -> PyResult<()> {
        if len_a != len_b {
            return Err(PyValueError::new_err(format!(
                "swap_blocks requires equal-length blocks; got len_a={len_a}, len_b={len_b}"
            )));
        }
        self.check_block(offset_a, len_a)?;
        self.check_block(offset_b, len_b)?;
        if (offset_a < offset_b + len_b) && (offset_b < offset_a + len_a) {
            return Err(PyValueError::new_err("blocks overlap"));
        }
        let data_a = self.inner.read(offset_a, len_a);
        let data_b = self.inner.read(offset_b, len_b);
        self.inner.overwrite(offset_a, &data_b);
        self.inner.overwrite(offset_b, &data_a);
        self.commit(Operation::SwapBlocks {
            offset_a,
            offset_b,
            data_a,
            data_b,
        });
        Ok(())
    }

    /// Reads the byte at `offset` for a bit operation on bit `bit_index`.
    fn bit_target(&self, offset: usize, bit_index: u8) -> PyResult<u8> {
        if bit_index > 7 {
            return Err(PyValueError::new_err("bit_index must be 0-7"));
        }
        self.inner
            .read_byte(offset)
            .map_err(|e| PyIndexError::new_err(e.to_string()))
    }

    /// Writes `new_byte` over `old_byte` at `offset` as one undoable edit.
    fn rewrite_byte(&mut self, offset: usize, old_byte: u8, new_byte: u8) {
        self.inner.overwrite(offset, &[new_byte]);
        self.commit(Operation::Overwrite {
            offset,
            old_data: vec![old_byte],
            new_data: vec![new_byte],
        });
    }

    fn get_bit(&self, offset: usize, bit_index: u8) -> PyResult<bool> {
        Ok(self.bit_target(offset, bit_index)? & (1 << bit_index) != 0)
    }

    fn set_bit(&mut self, offset: usize, bit_index: u8, value: bool) -> PyResult<()> {
        let old_byte = self.bit_target(offset, bit_index)?;
        let new_byte = if value {
            old_byte | (1 << bit_index)
        } else {
            old_byte & !(1 << bit_index)
        };
        self.rewrite_byte(offset, old_byte, new_byte);
        Ok(())
    }

    fn toggle_bit(&mut self, offset: usize, bit_index: u8) -> PyResult<bool> {
        let old_byte = self.bit_target(offset, bit_index)?;
        let new_byte = old_byte ^ (1 << bit_index);
        self.rewrite_byte(offset, old_byte, new_byte);
        Ok(new_byte & (1 << bit_index) != 0)
    }

    fn add_va_mapping(&mut self, file_offset: usize, virtual_address: u64, length: usize) {
        self.va_mappings
            .push((file_offset, virtual_address, length));
        self.va_mappings.sort_by_key(|m| m.0);
    }

    fn remove_va_mapping(&mut self, index: usize) -> bool {
        if index < self.va_mappings.len() {
            self.va_mappings.remove(index);
            true
        } else {
            false
        }
    }

    fn list_va_mappings(&self) -> Vec<(usize, u64, usize)> {
        self.va_mappings.clone()
    }

    /// Translates a file offset to a virtual address.
    ///
    /// Mappings may overlap; the first mapping in file-offset order that
    /// contains `offset` decides the answer, and `None` is returned if that
    /// mapping's translation would pass `u64::MAX`.
    ///
    /// Mappings are the image layout the caller registered (typically from
    /// section headers), in load-time coordinates: they are not checked
    /// against the document's length and are not shifted by later inserts or
    /// deletes. A mapping may therefore cover offsets at or past the end of
    /// the document, and this answers for them as the mapping describes.
    fn file_offset_to_va(&self, offset: usize) -> Option<u64> {
        for &(file_off, va, length) in &self.va_mappings {
            // Compare via subtraction (never `file_off + length`, which wraps
            // when a caller registered a mapping near `usize::MAX`), and add
            // the delta with a checked add so a VA past `u64::MAX` yields
            // `None` instead of wrapping.
            if offset >= file_off && offset - file_off < length {
                let delta = u64::try_from(offset - file_off).ok()?;
                return va.checked_add(delta);
            }
        }
        None
    }

    /// Translates a virtual address to a file offset.
    ///
    /// Mappings may overlap; the first mapping in file-offset order whose VA
    /// range contains `va` decides the answer, and `None` is returned if that
    /// mapping's translation would pass `usize::MAX`.
    ///
    /// The returned offset is where the registered layout places `va`, in the
    /// same load-time coordinates as [`DocumentState::file_offset_to_va`], so
    /// it can lie at or past the end of the document: a section whose virtual
    /// size exceeds its raw size (such as `.bss`) maps addresses no file bytes
    /// back. Callers reading the bytes check the offset against the document
    /// length first.
    fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        for &(file_off, base_va, length) in &self.va_mappings {
            // Compare via subtraction (never `base_va + length`, which wraps
            // when a caller registered a mapping near `u64::MAX`), and add the
            // delta with a checked add so a file offset past `usize::MAX`
            // yields `None` instead of wrapping.
            if va >= base_va && va - base_va < length as u64 {
                let delta = usize::try_from(va - base_va).ok()?;
                return file_off.checked_add(delta);
            }
        }
        None
    }

    fn pe_checksum(&self, py: Python<'_>) -> PyResult<hash::PeChecksumResult> {
        py.detach(|| hash::verify_pe_checksum(&self.inner.read_all()))
            .map_err(value_error)
    }

    fn verify_pe_checksum(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let result = self.pe_checksum(py)?;
        let dict = PyDict::new(py);
        dict.set_item("stored", result.stored)?;
        dict.set_item("calculated", result.calculated)?;
        dict.set_item("offset", result.offset)?;
        dict.set_item("valid", result.valid)?;
        Ok(dict.into())
    }

    fn repair_pe_checksum(&mut self, py: Python<'_>) -> PyResult<()> {
        let result = self.pe_checksum(py)?;
        let checksum_bytes = result.calculated.to_le_bytes();
        self.inner.overwrite(result.offset, &checksum_bytes);
        self.commit(Operation::Overwrite {
            offset: result.offset,
            old_data: result.stored.to_le_bytes().to_vec(),
            new_data: checksum_bytes.to_vec(),
        });
        Ok(())
    }

    fn get_document_memory_usage(&self) -> usize {
        self.inner.document_size()
    }
}

impl DocumentState {
    /// Load `source_path` and feed its bytes to `encoder`.
    ///
    /// Shared implementation for `export_patches_bps_from_path` and
    /// `export_patches_ups_from_path`. The source is loaded with
    /// `mmap_io::load_stable`: on Windows normally mapped read-only without a
    /// full-file `Vec<u8>`, and copied into memory when the file is empty or
    /// another handle can write it, as it always is on other platforms. The
    /// target is read out of this document's piece table.
    ///
    /// # Errors
    ///
    /// Returns `PyIOError` if the path is not a regular file (a device such
    /// as `NUL` reports length 0 and would silently encode against an empty
    /// source) or cannot be opened, mapped or copied, and `PyValueError` if
    /// the underlying encoder rejects the inputs.
    fn export_patch_from_path_inner<F>(&self, source_path: &str, encoder: F) -> PyResult<Vec<u8>>
    where
        F: FnOnce(&[u8], &[u8]) -> std::io::Result<Vec<u8>>,
    {
        let metadata =
            std::fs::metadata(source_path).map_err(|e| PyIOError::new_err(e.to_string()))?;
        if !metadata.is_file() {
            return Err(PyIOError::new_err(format!(
                "export source is not a regular file: {source_path}"
            )));
        }
        let target = self.inner.read_all();
        let source = mmap_io::load_stable(std::path::Path::new(source_path))
            .map_err(|e| PyIOError::new_err(e.to_string()))?;
        encoder(&source, &target).map_err(value_error)
    }
}

/// The Python-facing surface.
///
/// Every method here does the same three things: take the lock through
/// `lock_read` or `lock_write`, delegate to
/// [`DocumentState`], and return. No method calls another, because the lock is
/// not reentrant; where one entry point builds on another (`save_as` onto
/// `save`, `add_bookmark` onto `add_bookmark_object`) the chain happens one
/// level down, inside `DocumentState`.
#[pymethods]
impl HexDocument {
    #[new]
    fn py_new() -> Self {
        Self::wrap(DocumentState::new())
    }

    #[staticmethod]
    fn open(path: &str) -> PyResult<Self> {
        DocumentState::open(path).map(Self::wrap)
    }

    #[staticmethod]
    fn open_bytes(data: &[u8]) -> Self {
        Self::wrap(DocumentState::open_bytes(data))
    }

    #[staticmethod]
    fn from_process_memory(
        py: Python<'_>,
        pid: u32,
        address: usize,
        size: usize,
    ) -> PyResult<Self> {
        DocumentState::from_process_memory(py, pid, address, size).map(Self::wrap)
    }

    #[staticmethod]
    fn list_process_memory_regions(pid: u32) -> PyResult<Vec<(usize, usize, u32, u32)>> {
        DocumentState::list_process_memory_regions(pid)
    }

    #[staticmethod]
    fn list_transforms() -> Vec<(String, String, String)> {
        DocumentState::list_transforms()
    }

    #[staticmethod]
    fn encode_text_to_bytes(text: &str, encoding: &str) -> PyResult<Vec<u8>> {
        DocumentState::encode_text_to_bytes(text, encoding)
    }

    #[staticmethod]
    fn list_encodings() -> Vec<(String, String)> {
        DocumentState::list_encodings()
    }

    /// Saves the document to `path`.
    ///
    /// The write lock is held across the whole save — materialize, temp write,
    /// rename and remap — all of which already run with the GIL released, so
    /// the UI thread keeps going. Holding the lock is deliberate: it makes the
    /// save a serialization point, so a concurrent reader of this document sees
    /// it whole either before or after the save, never mid-remap, and the saved
    /// file always matches the generation that `mark_saved` then records.
    fn save(&self, py: Python<'_>, path: &str) -> PyResult<()> {
        self.lock_write(py).save(py, path)
    }

    fn save_as(&self, py: Python<'_>, path: &str) -> PyResult<()> {
        self.lock_write(py).save_as(py, path)
    }

    fn save_copy(&self, py: Python<'_>, path: &str) -> PyResult<()> {
        self.lock_read(py).save_copy(py, path)
    }

    fn close(&self, py: Python<'_>) {
        self.lock_write(py).close(py);
    }

    fn length(&self, py: Python<'_>) -> usize {
        self.lock_read(py).length()
    }

    fn read(&self, py: Python<'_>, offset: usize, length: usize) -> PyResult<Vec<u8>> {
        self.lock_read(py).read(offset, length)
    }

    fn read_byte(&self, py: Python<'_>, offset: usize) -> PyResult<u8> {
        self.lock_read(py).read_byte(offset)
    }

    /// Read a run of bytes together with a class tag for each one.
    ///
    /// The tags are [`entropy::byte_class`] values, the third member is the
    /// document generation the bytes were read at and the fourth is how long
    /// the document was. All four come from a single acquisition of the lock,
    /// so a caller caching the window cannot pair it with a generation the
    /// bytes never had, and one clamping a scroll position against the length
    /// cannot clamp against a length the bytes were never read under.
    fn read_window(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
    ) -> PyResult<(Vec<u8>, Vec<u8>, u64, usize)> {
        self.lock_read(py).read_window(py, offset, length)
    }

    /// How many times the bytes of this document have changed.
    ///
    /// Advanced by content edits only. Saving, bookmarks, VA mappings,
    /// templates and the size hints leave it alone.
    fn generation(&self, py: Python<'_>) -> u64 {
        self.lock_read(py).current_generation()
    }

    fn write_bytes(&self, py: Python<'_>, offset: usize, data: &[u8]) -> PyResult<()> {
        self.lock_write(py).write_bytes(offset, data)
    }

    fn insert_bytes(&self, py: Python<'_>, offset: usize, data: &[u8]) -> PyResult<()> {
        self.lock_write(py).insert_bytes(offset, data)
    }

    fn delete_bytes(&self, py: Python<'_>, offset: usize, length: usize) -> PyResult<()> {
        self.edit_detached(py, move |doc| doc.delete_bytes(offset, length))
    }

    fn undo(&self, py: Python<'_>) -> bool {
        self.lock_write(py).undo()
    }

    fn redo(&self, py: Python<'_>) -> bool {
        self.lock_write(py).redo()
    }

    fn can_undo(&self, py: Python<'_>) -> bool {
        self.lock_read(py).can_undo()
    }

    fn can_redo(&self, py: Python<'_>) -> bool {
        self.lock_read(py).can_redo()
    }

    fn is_modified(&self, py: Python<'_>) -> bool {
        self.lock_read(py).is_modified()
    }

    fn search_bytes(
        &self,
        py: Python<'_>,
        pattern: Vec<u8>,
        max_results: usize,
    ) -> Vec<(usize, usize)> {
        self.analyze(py, move |data| {
            search::search_bytes(data, &pattern, max_results)
                .into_iter()
                .map(|r| (r.offset, r.length))
                .collect()
        })
    }

    fn search_hex(
        &self,
        py: Python<'_>,
        pattern: &str,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        self.analyze(py, move |data| {
            search::search_hex_with_wildcards(data, pattern, max_results)
                .map(|results| results.into_iter().map(|r| (r.offset, r.length)).collect())
        })
        .map_err(value_error)
    }

    fn search_text(
        &self,
        py: Python<'_>,
        text: &str,
        encoding: &str,
        case_sensitive: bool,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        self.analyze(py, move |data| {
            search::search_text(data, text, encoding, case_sensitive, max_results)
                .map(|results| results.into_iter().map(|r| (r.offset, r.length)).collect())
        })
        .map_err(value_error)
    }

    fn search_regex(
        &self,
        py: Python<'_>,
        pattern: &str,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        self.analyze(py, move |data| {
            search::search_regex(data, pattern, max_results)
                .map(|results| results.into_iter().map(|r| (r.offset, r.length)).collect())
        })
        .map_err(value_error)
    }

    fn search_text_encoded(
        &self,
        py: Python<'_>,
        text: &str,
        encoding: &str,
        case_sensitive: bool,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        self.analyze(py, move |data| {
            encodings::search_text_encoded(data, text, encoding, case_sensitive, max_results)
        })
        .map_err(value_error)
    }

    fn search_numeric(
        &self,
        py: Python<'_>,
        value: i64,
        size: usize,
        signed: bool,
        big_endian: bool,
        alignment: usize,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        self.analyze(py, move |data| {
            search::search_numeric_int(
                data,
                value,
                size,
                signed,
                big_endian,
                alignment,
                max_results,
            )
            .map(|results| results.into_iter().map(|r| (r.offset, r.length)).collect())
        })
        .map_err(value_error)
    }

    fn search_numeric_float(
        &self,
        py: Python<'_>,
        value: f64,
        size: usize,
        big_endian: bool,
        tolerance: f64,
        alignment: usize,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        self.analyze(py, move |data| {
            search::search_numeric_float(
                data,
                value,
                size,
                big_endian,
                tolerance,
                alignment,
                max_results,
            )
            .map(|results| results.into_iter().map(|r| (r.offset, r.length)).collect())
        })
        .map_err(value_error)
    }

    fn search_numeric_range(
        &self,
        py: Python<'_>,
        value_range: (i64, i64),
        size: usize,
        signed: bool,
        big_endian: bool,
        alignment: usize,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        let (min_val, max_val) = value_range;
        self.analyze(py, move |data| {
            search::search_numeric_range(
                data,
                min_val,
                max_val,
                size,
                signed,
                big_endian,
                alignment,
                max_results,
            )
            .map(|results| results.into_iter().map(|r| (r.offset, r.length)).collect())
        })
        .map_err(value_error)
    }

    fn replace_bytes(&self, py: Python<'_>, pattern: &[u8], replacement: &[u8]) -> PyResult<usize> {
        self.lock_write(py).replace_bytes(py, pattern, replacement)
    }

    fn inspect_at(&self, py: Python<'_>, offset: usize) -> PyResult<Py<PyAny>> {
        self.lock_read(py).inspect_at(py, offset)
    }

    fn compute_hash(&self, py: Python<'_>, algorithm: &str) -> PyResult<String> {
        let chunk_size = self.chunk_size();
        self.lock_read(py).compute_hash(py, algorithm, chunk_size)
    }

    fn compute_hash_range(
        &self,
        py: Python<'_>,
        start: usize,
        end: usize,
        algorithm: &str,
    ) -> PyResult<String> {
        let chunk_size = self.chunk_size();
        self.lock_read(py)
            .compute_hash_range(py, (start, end), algorithm, chunk_size)
    }

    fn compute_hash_custom_crc(
        &self,
        py: Python<'_>,
        byte_range: (usize, usize),
        poly: u64,
        init: u64,
        width: u8,
        reflect: (bool, bool),
        xorout: u64,
    ) -> PyResult<String> {
        self.lock_read(py)
            .compute_hash_custom_crc(py, byte_range, poly, init, width, reflect, xorout)
    }

    fn byte_statistics(&self, py: Python<'_>) -> Vec<(u8, usize)> {
        let chunk_size = self.chunk_size();
        self.lock_read(py).byte_statistics(py, chunk_size)
    }

    fn add_bookmark(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
        label: &str,
        color: &str,
    ) -> usize {
        self.lock_write(py)
            .add_bookmark(offset, length, label, color)
    }

    fn add_bookmark_object(&self, py: Python<'_>, bookmark: Bookmark) -> usize {
        self.lock_write(py).add_bookmark_object(bookmark)
    }

    fn remove_bookmark(&self, py: Python<'_>, index: usize) -> bool {
        self.lock_write(py).remove_bookmark(index)
    }

    fn list_bookmarks(&self, py: Python<'_>) -> Vec<(usize, usize, String, String)> {
        self.lock_read(py).list_bookmarks()
    }

    fn get_bookmarks(&self, py: Python<'_>) -> Vec<Bookmark> {
        self.lock_read(py).get_bookmarks()
    }

    fn get_bookmark(&self, py: Python<'_>, index: usize) -> Option<Bookmark> {
        self.lock_read(py).get_bookmark(index)
    }

    fn update_bookmark(&self, py: Python<'_>, index: usize, bookmark: Bookmark) -> bool {
        self.lock_write(py).update_bookmark(index, bookmark)
    }

    fn apply_template(&self, py: Python<'_>, name: &str, offset: usize) -> PyResult<Py<PyAny>> {
        self.lock_read(py).apply_template(py, name, offset)
    }

    fn list_templates(&self, py: Python<'_>) -> Vec<(String, String)> {
        self.lock_read(py).list_templates()
    }

    fn register_json_template(&self, py: Python<'_>, json_str: &str) -> PyResult<String> {
        self.lock_write(py).register_json_template(json_str)
    }

    fn remove_template(&self, py: Python<'_>, name: &str) -> bool {
        self.lock_write(py).remove_template(name)
    }

    fn export_template_json(&self, py: Python<'_>, name: &str) -> PyResult<String> {
        self.lock_read(py).export_template_json(name)
    }

    fn list_templates_detailed(&self, py: Python<'_>) -> Vec<(String, String, String, usize)> {
        self.lock_read(py).list_templates_detailed()
    }

    fn file_path(&self, py: Python<'_>) -> Option<String> {
        self.lock_read(py).file_path()
    }

    fn entropy(&self, py: Python<'_>) -> f64 {
        self.analyze(py, entropy::compute_entropy)
    }

    fn entropy_map(&self, py: Python<'_>, block_size: usize) -> PyResult<Vec<f64>> {
        check_block_size(block_size)?;
        Ok(self.analyze(py, move |data| entropy::entropy_map(data, block_size)))
    }

    /// `entropy_map` as little-endian `f64`, eight bytes per block.
    ///
    /// The same numbers as [`HexDocument::entropy_map`], in a form that crosses
    /// into a typed array without being built as a list of Python floats first.
    fn entropy_map_bytes(&self, py: Python<'_>, block_size: usize) -> PyResult<Vec<u8>> {
        check_block_size(block_size)?;
        Ok(self.analyze(py, move |data| {
            entropy::entropy_map(data, block_size)
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect()
        }))
    }

    fn byte_distribution_full(&self, py: Python<'_>) -> Vec<u64> {
        self.analyze(py, |data| entropy::byte_distribution(data).to_vec())
    }

    /// `byte_distribution_full` as little-endian `u64`, 2048 bytes.
    fn byte_distribution_bytes(&self, py: Python<'_>) -> Vec<u8> {
        self.analyze(py, |data| {
            entropy::byte_distribution(data)
                .iter()
                .flat_map(|count| count.to_le_bytes())
                .collect()
        })
    }

    fn byte_type_distribution(&self, py: Python<'_>) -> (u64, u64, u64, u64) {
        self.analyze(py, entropy::byte_type_distribution)
    }

    fn digram_matrix(&self, py: Python<'_>) -> Vec<u64> {
        self.analyze(py, entropy::digram_matrix)
    }

    /// `digram_matrix` as little-endian `u64`, 512 KiB for the 256x256 grid.
    fn digram_matrix_bytes(&self, py: Python<'_>) -> Vec<u8> {
        self.analyze(py, |data| {
            entropy::digram_matrix(data)
                .iter()
                .flat_map(|count| count.to_le_bytes())
                .collect()
        })
    }

    fn content_classification(&self, py: Python<'_>, block_size: usize) -> PyResult<Vec<u8>> {
        check_block_size(block_size)?;
        Ok(self.analyze(py, move |data| {
            entropy::content_classification(data, block_size)
        }))
    }

    fn transform_data(
        &self,
        py: Python<'_>,
        name: &str,
        offset: usize,
        length: usize,
        params: HashMap<String, Vec<u8>>,
    ) -> PyResult<Vec<u8>> {
        self.lock_read(py)
            .transform_data(py, name, offset, length, params)
    }

    fn get_patches(&self, py: Python<'_>) -> Vec<(usize, Vec<u8>)> {
        self.lock_read(py).get_patches()
    }

    fn export_patches_ips(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_ips()
    }

    fn export_patches_ips32(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_ips32()
    }

    fn export_patches_cod(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_cod()
    }

    fn export_patches_json(&self, py: Python<'_>) -> PyResult<String> {
        self.lock_read(py).export_patches_json()
    }

    fn import_patches_ips(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        self.lock_write(py).import_patches_ips(data)
    }

    fn export_patches_bps(&self, py: Python<'_>, source_data: &[u8]) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_bps(py, source_data)
    }

    fn export_patches_bps_from_path(&self, py: Python<'_>, source_path: &str) -> PyResult<Vec<u8>> {
        self.lock_read(py)
            .export_patches_bps_from_path(py, source_path)
    }

    fn import_patches_bps(
        &self,
        py: Python<'_>,
        patch_data: &[u8],
        source_data: &[u8],
    ) -> PyResult<usize> {
        self.lock_write(py)
            .import_patches_bps(py, patch_data, source_data)
    }

    fn export_patches_ups(&self, py: Python<'_>, source_data: &[u8]) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_ups(py, source_data)
    }

    fn export_patches_ups_from_path(&self, py: Python<'_>, source_path: &str) -> PyResult<Vec<u8>> {
        self.lock_read(py)
            .export_patches_ups_from_path(py, source_path)
    }

    fn import_patches_ups(
        &self,
        py: Python<'_>,
        patch_data: &[u8],
        source_data: &[u8],
    ) -> PyResult<usize> {
        self.lock_write(py)
            .import_patches_ups(py, patch_data, source_data)
    }

    fn decode_text(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
        encoding: &str,
    ) -> PyResult<String> {
        self.lock_read(py).decode_text(py, offset, length, encoding)
    }

    fn fill_block(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
        pattern: &[u8],
    ) -> PyResult<()> {
        self.edit_detached(py, move |doc| doc.fill_block(offset, length, pattern))
    }

    fn copy_block(
        &self,
        py: Python<'_>,
        src_offset: usize,
        length: usize,
        dst_offset: usize,
    ) -> PyResult<()> {
        self.edit_detached(py, move |doc| {
            doc.copy_block(src_offset, length, dst_offset)
        })
    }

    fn move_block(
        &self,
        py: Python<'_>,
        src_offset: usize,
        length: usize,
        dst_offset: usize,
    ) -> PyResult<()> {
        self.edit_detached(py, move |doc| {
            doc.move_block(src_offset, length, dst_offset)
        })
    }

    fn swap_blocks(
        &self,
        py: Python<'_>,
        offset_a: usize,
        len_a: usize,
        offset_b: usize,
        len_b: usize,
    ) -> PyResult<()> {
        self.edit_detached(py, move |doc| {
            doc.swap_blocks(offset_a, len_a, offset_b, len_b)
        })
    }

    fn get_bit(&self, py: Python<'_>, offset: usize, bit_index: u8) -> PyResult<bool> {
        self.lock_read(py).get_bit(offset, bit_index)
    }

    fn set_bit(&self, py: Python<'_>, offset: usize, bit_index: u8, value: bool) -> PyResult<()> {
        self.lock_write(py).set_bit(offset, bit_index, value)
    }

    fn toggle_bit(&self, py: Python<'_>, offset: usize, bit_index: u8) -> PyResult<bool> {
        self.lock_write(py).toggle_bit(offset, bit_index)
    }

    fn add_va_mapping(
        &self,
        py: Python<'_>,
        file_offset: usize,
        virtual_address: u64,
        length: usize,
    ) {
        self.lock_write(py)
            .add_va_mapping(file_offset, virtual_address, length);
    }

    fn remove_va_mapping(&self, py: Python<'_>, index: usize) -> bool {
        self.lock_write(py).remove_va_mapping(index)
    }

    fn list_va_mappings(&self, py: Python<'_>) -> Vec<(usize, u64, usize)> {
        self.lock_read(py).list_va_mappings()
    }

    fn file_offset_to_va(&self, py: Python<'_>, offset: usize) -> Option<u64> {
        self.lock_read(py).file_offset_to_va(offset)
    }

    fn va_to_file_offset(&self, py: Python<'_>, va: u64) -> Option<usize> {
        self.lock_read(py).va_to_file_offset(va)
    }

    /// Extracts printable strings, as dicts of `offset`, `length`, `encoding`
    /// and `content` sorted by offset.
    ///
    /// `include_utf16` scans UTF-16LE and `include_utf16be` scans UTF-16BE;
    /// the two byte orders are scanned independently, so asking for both can
    /// report the same bytes once under each reading.
    #[pyo3(signature = (min_length, include_ascii, include_utf16, max_results, include_utf16be=false))]
    fn extract_strings(
        &self,
        py: Python<'_>,
        min_length: usize,
        include_ascii: bool,
        include_utf16: bool,
        max_results: usize,
        include_utf16be: bool,
    ) -> PyResult<Py<PyAny>> {
        let encodings = strings::StringEncodings {
            ascii: include_ascii,
            utf16le: include_utf16,
            utf16be: include_utf16be,
        };
        let matches = self.analyze(py, move |data| {
            strings::extract_strings(data, min_length, encodings, max_results)
        });
        let list = PyList::empty(py);
        for m in &matches {
            let dict = PyDict::new(py);
            dict.set_item("offset", m.offset)?;
            dict.set_item("length", m.length)?;
            dict.set_item("encoding", m.encoding)?;
            dict.set_item("content", &m.content)?;
            list.append(dict)?;
        }
        Ok(list.into())
    }

    fn verify_pe_checksum(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.lock_read(py).verify_pe_checksum(py)
    }

    fn repair_pe_checksum(&self, py: Python<'_>) -> PyResult<()> {
        self.lock_write(py).repair_pe_checksum(py)
    }

    fn get_document_memory_usage(&self, py: Python<'_>) -> usize {
        self.lock_read(py).get_document_memory_usage()
    }

    fn set_chunk_size_hint(&self, size: usize) {
        self.chunk_size_hint.store(size, Ordering::Relaxed);
    }

    fn get_chunk_size_hint(&self) -> usize {
        self.chunk_size_hint.load(Ordering::Relaxed)
    }

    fn set_memory_budget_hint(&self, budget: usize) {
        self.memory_budget_hint.store(budget, Ordering::Relaxed);
    }

    fn get_memory_budget_hint(&self) -> usize {
        self.memory_budget_hint.load(Ordering::Relaxed)
    }
}

#[pyfunction]
#[pyo3(signature = (path_a, path_b, min_match=1, max_regions=100_000))]
fn diff_files(
    py: Python<'_>,
    path_a: &str,
    path_b: &str,
    min_match: usize,
    max_regions: usize,
) -> PyResult<Py<PyAny>> {
    let options = diff::DiffOptions {
        min_match,
        max_regions,
    };
    let (size_a, size_b, result) = py
        .detach(|| {
            let read =
                |path: &str| std::fs::read(path).map_err(|e| format!("Failed to read {path}: {e}"));
            let data_a = read(path_a)?;
            let data_b = read(path_b)?;
            Ok((
                data_a.len(),
                data_b.len(),
                diff::diff_data(&data_a, &data_b, options),
            ))
        })
        .map_err(PyIOError::new_err::<String>)?;
    diff_result_to_py(py, size_a, size_b, &result)
}

#[pyfunction]
#[pyo3(signature = (data_a, data_b, min_match=1, max_regions=100_000))]
fn diff_bytes(
    py: Python<'_>,
    data_a: &[u8],
    data_b: &[u8],
    min_match: usize,
    max_regions: usize,
) -> PyResult<Py<PyAny>> {
    let options = diff::DiffOptions {
        min_match,
        max_regions,
    };
    let result = py.detach(|| diff::diff_data(data_a, data_b, options));
    diff_result_to_py(py, data_a.len(), data_b.len(), &result)
}

fn diff_result_to_py(
    py: Python<'_>,
    size_a: usize,
    size_b: usize,
    result: &diff::DiffResult,
) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);
    dict.set_item("total_differences", result.total_differences)?;
    dict.set_item("files_identical", result.files_identical)?;
    dict.set_item("region_count", result.region_count)?;
    dict.set_item("change_count", result.change_count)?;
    dict.set_item("truncated", result.truncated())?;
    dict.set_item("size_a", size_a)?;
    dict.set_item("size_b", size_b)?;

    let regions = PyList::empty(py);
    for region in &result.regions {
        let r = PyDict::new(py);
        r.set_item("offset_a", region.offset_a)?;
        r.set_item("offset_b", region.offset_b)?;
        r.set_item("length", region.length)?;
        r.set_item("length_a", region.length_a)?;
        r.set_item("length_b", region.length_b)?;
        r.set_item(
            "diff_type",
            match region.diff_type {
                diff::DiffType::Match => "match",
                diff::DiffType::Modified => "modified",
                diff::DiffType::InsertedA => "inserted_a",
                diff::DiffType::InsertedB => "inserted_b",
            },
        )?;
        regions.append(r)?;
    }
    dict.set_item("regions", regions)?;

    Ok(dict.into())
}

#[pymodule]
fn intellicrack_hexcore(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<HexDocument>()?;
    m.add_class::<Bookmark>()?;
    m.add_function(wrap_pyfunction!(diff_files, m)?)?;
    m.add_function(wrap_pyfunction!(diff_bytes, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bounds check must not use raw `usize` addition for `offset +
    /// length`: a huge `offset` chosen to wrap the sum below `doc_len` would
    /// bypass validation entirely. `usize::MAX - 3` and `length = 10` wrap to
    /// `6`, which passes `6 > doc_len` for an 8-byte document.
    #[test]
    fn test_fill_block_rejects_wrapped_offset_length_overflow() {
        let mut doc = DocumentState::open_bytes(b"ABCDEFGH");
        let result = doc.fill_block(usize::MAX - 3, 10, b"A");
        assert!(
            result.is_err(),
            "offset+length overflow must not bypass the bounds check"
        );
    }

    #[test]
    fn test_copy_block_rejects_wrapped_offset_length_overflow() {
        let mut doc = DocumentState::open_bytes(b"ABCDEFGH");
        let result = doc.copy_block(usize::MAX - 3, 8, 0);
        assert!(
            result.is_err(),
            "src_offset+length overflow must not bypass the bounds check"
        );
    }

    #[test]
    fn test_move_block_rejects_wrapped_offset_length_overflow() {
        let mut doc = DocumentState::open_bytes(b"ABCDEFGH");
        let result = doc.move_block(usize::MAX - 3, 8, 0);
        assert!(
            result.is_err(),
            "src_offset+length overflow must not bypass the bounds check"
        );
    }

    #[test]
    fn test_swap_blocks_rejects_wrapped_offset_length_overflow() {
        let mut doc = DocumentState::open_bytes(b"ABCDEFGH");
        let result = doc.swap_blocks(usize::MAX - 3, 8, 0, 8);
        assert!(
            result.is_err(),
            "offset_a+len_a overflow must not bypass the bounds check"
        );
    }

    #[test]
    fn test_fill_block_valid_range_still_succeeds() {
        let mut doc = DocumentState::open_bytes(b"AAAAAAAA");
        doc.fill_block(2, 3, b"X").unwrap();
        assert_eq!(doc.read(0, 8).unwrap(), b"AAXXXAAA".to_vec());
    }

    /// `swap_blocks` must not record two independent `Overwrite` entries, or a
    /// single `undo()` only reverts the second region and leaves the same
    /// bytes duplicated at both offsets.
    #[test]
    fn test_swap_blocks_single_undo_restores_both_regions() {
        let mut doc = DocumentState::open_bytes(b"AAAABBBB");
        doc.swap_blocks(0, 4, 4, 4).unwrap();
        assert_eq!(doc.read(0, 8).unwrap(), b"BBBBAAAA".to_vec());

        assert!(doc.undo());
        assert_eq!(
            doc.read(0, 8).unwrap(),
            b"AAAABBBB".to_vec(),
            "a single undo() after swap_blocks must restore both swapped regions"
        );
        assert!(
            !doc.can_undo(),
            "swap_blocks must record exactly one undo-stack entry"
        );
    }

    /// The returned count must be the number of records actually applied to
    /// the document, not `records.len()` (every record parsed from the IPS
    /// file), which would hide silently-skipped out-of-bounds records from the
    /// caller.
    #[test]
    fn test_import_patches_ips_returns_applied_not_total_record_count() {
        let mut doc = DocumentState::open_bytes(b"ABCD");
        let records = vec![
            patch_export::PatchRecord {
                offset: 0,
                data: vec![0x58],
            },
            patch_export::PatchRecord {
                offset: 100,
                data: vec![0x59],
            },
        ];
        let ips = patch_export::export_ips(&records, &|_| None).unwrap();

        let applied = doc.import_patches_ips(&ips).unwrap();
        assert_eq!(
            applied, 1,
            "import_patches_ips must report the number of records actually \
             applied, not the total record count parsed from the file"
        );
        assert_eq!(doc.read(0, 1).unwrap(), vec![0x58]);
    }

    /// `file_offset_to_va` must not compute `file_off + length` while
    /// evaluating the range test. `add_va_mapping` takes caller-supplied
    /// values with no bounds check, so a mapping at `usize::MAX` would make
    /// that sum wrap — panicking in a debug build (arithmetic overflow) and,
    /// worse, silently matching the wrong offsets in release. The lookup must
    /// instead resolve via subtraction and never panic.
    #[test]
    fn test_file_offset_to_va_rejects_wrapping_mapping_without_panic() {
        let mut doc = DocumentState::open_bytes(b"ABCD");
        doc.add_va_mapping(usize::MAX, 0x1000, 1);
        // The only offset that satisfies `offset >= usize::MAX` is `usize::MAX`
        // itself; a `file_off + length` sum overflows while testing it.
        // It is genuinely the first byte of this one-byte mapping, so it
        // resolves to the base VA rather than panicking.
        assert_eq!(doc.file_offset_to_va(usize::MAX), Some(0x1000));

        // A well-formed mapping still resolves exactly.
        let mut ok = DocumentState::open_bytes(b"ABCD");
        ok.add_va_mapping(0, 0x40_0000, 4);
        assert_eq!(ok.file_offset_to_va(2), Some(0x40_0002));
    }

    /// `va_to_file_offset` must not compute `base_va + length` unconditionally
    /// at the top of the loop: a mapping whose `virtual_address` sits near
    /// `u64::MAX` would overflow that sum for *every* lookup — a debug-build
    /// panic, a release-build wrong answer. The lookup must resolve via
    /// subtraction and a checked file-offset add.
    #[test]
    fn test_va_to_file_offset_rejects_wrapping_mapping_without_panic() {
        let mut doc = DocumentState::open_bytes(b"ABCD");
        doc.add_va_mapping(0, u64::MAX, 4);
        // A `base_va + length` sum would overflow on any lookup; a VA below
        // base_va must simply miss.
        assert_eq!(doc.va_to_file_offset(0), None);
        // The top-of-range VA is in-range and resolves to its file offset.
        assert_eq!(doc.va_to_file_offset(u64::MAX), Some(0));

        // A well-formed mapping still resolves exactly.
        let mut ok = DocumentState::open_bytes(b"ABCD");
        ok.add_va_mapping(0x10, 0x40_0000, 4);
        assert_eq!(ok.va_to_file_offset(0x40_0002), Some(0x12));
    }

    /// VA mappings are load-time coordinates, not bounded by the document: a
    /// section whose virtual size exceeds its raw data (a `.bss`-style tail)
    /// still translates in both directions past the end of the file, which is
    /// what lets a caller locate such addresses at all.
    #[test]
    fn test_va_mapping_translates_past_the_end_of_the_document() {
        let mut doc = DocumentState::open_bytes(b"ABCDEFGH");
        doc.add_va_mapping(4, 0x40_1000, 0x1000);
        assert_eq!(doc.va_to_file_offset(0x40_1FFF), Some(0x1003));
        assert_eq!(doc.file_offset_to_va(0x800), Some(0x40_17FC));
        assert_eq!(doc.va_to_file_offset(0x40_2000), None);
        assert_eq!(doc.length(), 8);
    }

    /// Edits that change no byte (an empty write, rewriting a byte with its
    /// own value, setting a bit that is already set, a zero-length fill) must
    /// not push an undo entry, mark the document modified or advance the
    /// generation; otherwise a Ctrl+Z appears to do nothing and every cache is
    /// invalidated for no reason.
    #[test]
    fn test_no_op_edits_leave_no_undo_entry_or_generation_bump() {
        let mut doc = DocumentState::open_bytes(b"\x01BCD");
        doc.write_bytes(1, &[]).unwrap();
        doc.write_bytes(1, b"B").unwrap();
        doc.set_bit(0, 0, true).unwrap();
        doc.fill_block(2, 0, b"Z").unwrap();
        doc.insert_bytes(4, &[]).unwrap();
        assert!(!doc.can_undo());
        assert!(!doc.is_modified());
        assert_eq!(doc.current_generation(), 0);
        assert!(!doc.undo());
        assert_eq!(doc.read(0, 4).unwrap(), b"\x01BCD".to_vec());
    }

    /// A `write_bytes` whose data runs past the end of the document is rejected
    /// outright rather than silently truncated, so no partial write lands and
    /// the document stays unchanged, unmodified and not undoable.
    #[test]
    fn test_write_bytes_rejects_overrun_without_partial_write() {
        let mut doc = DocumentState::open_bytes(b"ABCDEFGH");
        assert!(doc.write_bytes(6, b"\xaa\xbb\xcc\xdd").is_err());
        assert_eq!(doc.read(0, 8).unwrap(), b"ABCDEFGH".to_vec());
        assert!(!doc.is_modified());
        assert!(!doc.can_undo());
    }

    /// Whole-document analyses copy the bytes under a read guard and compute
    /// after it is dropped, so a long scan never holds the lock. The analysis
    /// closure below takes the write lock itself: that only succeeds when the
    /// read guard is already gone, and fails if the guard is held across the
    /// computation, which is what lets a queued writer stall other readers.
    #[test]
    fn test_analysis_releases_read_guard_before_computing() {
        let doc = HexDocument::wrap(DocumentState::open_bytes(b"ABCDEFGH"));
        let (seen, writer_free) = doc.analyze_locked(|data| {
            let writer_free = doc.state.try_write().is_some();
            (data.to_vec(), writer_free)
        });
        assert_eq!(seen, b"ABCDEFGH".to_vec());
        assert!(
            writer_free,
            "the read guard was still held while the analysis computed"
        );
    }

    /// Every content mutator advances the generation by exactly
    /// one and the non-content operations leave it alone, so a cache keyed on
    /// it is never stale and never needlessly invalidated.
    #[test]
    fn test_generation_advances_once_per_content_edit_only() {
        let mut doc = DocumentState::open_bytes(b"ABCDEFGHIJKLMNOP");
        let mut expected = 0u64;
        let mut step = |doc: &mut DocumentState, label: &str| {
            expected += 1;
            assert_eq!(doc.current_generation(), expected, "{label}");
        };
        doc.write_bytes(0, b"a").unwrap();
        step(&mut doc, "write_bytes");
        doc.insert_bytes(1, b"x").unwrap();
        step(&mut doc, "insert_bytes");
        doc.delete_bytes(1, 1).unwrap();
        step(&mut doc, "delete_bytes");
        doc.fill_block(2, 2, b"z").unwrap();
        step(&mut doc, "fill_block");
        doc.copy_block(0, 2, 8).unwrap();
        step(&mut doc, "copy_block");
        doc.move_block(4, 2, 12).unwrap();
        step(&mut doc, "move_block");
        doc.swap_blocks(0, 2, 6, 2).unwrap();
        step(&mut doc, "swap_blocks");
        doc.toggle_bit(15, 7).unwrap();
        step(&mut doc, "toggle_bit");
        assert!(doc.undo());
        step(&mut doc, "undo");
        assert!(doc.redo());
        step(&mut doc, "redo");

        let before = doc.current_generation();
        doc.add_bookmark(0, 1, "b", "red");
        doc.add_va_mapping(0, 0x1000, 4);
        doc.remove_va_mapping(0);
        assert_eq!(doc.current_generation(), before);
    }

    /// A whole-document replace is a single content edit, so it bumps the
    /// generation exactly once; the bookmark and template bookkeeping changes
    /// no bytes, so it must not bump it at all. (`replace_bytes`, `save` and
    /// the patch imports take a GIL token and are gated in the Python suite.)
    #[test]
    fn test_replace_bumps_once_and_bookmark_and_template_edits_do_not() {
        let mut doc = DocumentState::open_bytes(b"ABCDABCD");
        let before = doc.current_generation();
        doc.replace_document(b"ABCDABCD".to_vec(), b"wxyz".to_vec());
        assert_eq!(
            doc.current_generation(),
            before + 1,
            "replace must bump once"
        );
        assert_eq!(doc.length(), 4);

        let after_replace = doc.current_generation();
        let idx = doc.add_bookmark(0, 1, "b", "red");
        doc.update_bookmark(
            idx,
            Bookmark {
                offset: 1,
                length: 2,
                label: "c".to_string(),
                color: "blue".to_string(),
            },
        );
        doc.remove_bookmark(idx);
        assert!(!doc.remove_template("no-such-template"));
        assert_eq!(
            doc.current_generation(),
            after_replace,
            "bookmark and template bookkeeping must not bump the generation"
        );
    }

    /// The size hints live outside the document lock, so they can be changed
    /// and read while another caller holds it, here as a held read guard the
    /// way a long chunked hash holds one. They are not content, so changing
    /// them leaves the generation alone, and the read size they set never
    /// drops below 64 KiB.
    #[test]
    fn test_size_hints_bypass_the_document_lock() {
        let doc = HexDocument::wrap(DocumentState::open_bytes(b"ABCD"));
        let reader = doc.state.read();
        let generation = reader.current_generation();
        doc.set_chunk_size_hint(1 << 20);
        doc.set_memory_budget_hint(1 << 30);
        assert_eq!(doc.get_chunk_size_hint(), 1 << 20);
        assert_eq!(doc.get_memory_budget_hint(), 1 << 30);
        assert_eq!(doc.chunk_size(), 1 << 20);
        assert_eq!(reader.current_generation(), generation);
        drop(reader);

        doc.set_chunk_size_hint(1);
        assert_eq!(doc.get_chunk_size_hint(), 1);
        assert_eq!(doc.chunk_size(), 65536);
    }

    /// Overwrite-only exports must refuse a history with inserts or deletes;
    /// silently dropping them and keeping post-edit offsets means the patch
    /// applied to the original file does not reproduce the document.
    #[test]
    fn test_export_patches_refuses_offset_shifting_history() {
        let mut doc = DocumentState::open_bytes(b"ABCDEFGH");
        doc.write_bytes(2, b"Z").unwrap();
        assert_eq!(
            doc.export_patches_ips().unwrap(),
            [b"PATCH".as_slice(), &[0, 0, 2, 0, 1, b'Z'], b"EOF"].concat()
        );
        doc.insert_bytes(0, b"Q").unwrap();
        assert!(doc.exportable_records().is_err());
        assert!(doc.export_patches_ips().is_err());
        assert!(doc.export_patches_cod().is_err());
        assert!(doc.export_patches_json().is_err());
    }

    /// An IPS import must be one undo entry and honor the truncation
    /// extension; recording one entry per record means a single `undo()`
    /// reverts only the last record, and ignoring truncation means a shrinking
    /// patch never shrinks the document.
    #[test]
    fn test_import_patches_ips_is_one_undo_entry_including_truncation() {
        let mut doc = DocumentState::open_bytes(b"ABCDEF");
        let ips = b"PATCH\x00\x00\x00\x00\x01X\x00\x00\x02\x00\x01YEOF\x00\x00\x03";
        assert_eq!(doc.import_patches_ips(ips).unwrap(), 2);
        assert_eq!(doc.length(), 3);
        assert_eq!(doc.read(0, 3).unwrap(), b"XBY".to_vec());
        assert!(doc.undo());
        assert_eq!(doc.read(0, 6).unwrap(), b"ABCDEF".to_vec());
        assert!(!doc.can_undo());
        assert!(doc.redo());
        assert_eq!(doc.read(0, 6).unwrap(), b"XBY".to_vec());
    }

    /// `replace_bytes` and the BPS/UPS imports must keep the document's file
    /// path; rebuilding with `MmapDocument::from_bytes` drops it, so Save falls
    /// back to Save As and the sandbox refuses to run the file.
    #[test]
    fn test_replace_document_keeps_file_path_and_is_undoable() {
        let path = std::env::temp_dir().join("hexcore_f0131_replace_keeps_path.bin");
        std::fs::write(&path, b"foobar").unwrap();
        let mut doc = DocumentState::open(&path.to_string_lossy()).unwrap();
        doc.replace_document(b"foobar".to_vec(), b"X".to_vec());
        assert_eq!(doc.file_path(), Some(path.to_string_lossy().into_owned()));
        assert_eq!(doc.read(0, 6).unwrap(), b"X".to_vec());
        assert!(doc.undo());
        assert_eq!(doc.read(0, 6).unwrap(), b"foobar".to_vec());
        drop(doc);
        let _ = std::fs::remove_file(&path);
    }

    /// The inspector must be handed enough bytes for its 32-unit wide-string
    /// view; a 16-byte window can never show more than 8 characters.
    #[test]
    fn test_inspection_window_covers_the_wide_string_view() {
        let text = "ABCDEFGHIJKLMNOP";
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let doc = DocumentState::open_bytes(&bytes);
        assert_eq!(
            doc.inspection(0)
                .values
                .get("wide_string")
                .map(String::as_str),
            Some(text)
        );
        assert_eq!(doc.inspection(32).values.len(), 0);
    }

    #[test]
    fn test_check_offset_boundary_matches_read() {
        let doc = DocumentState::open_bytes(b"ABCDEFGH");
        assert!(doc.check_offset(8).is_ok());
        assert!(doc.check_offset(9).is_err());
        assert!(doc.read(9, 1).is_err());
        assert_eq!(doc.read(8, 1).unwrap(), Vec::<u8>::new());
    }
}
