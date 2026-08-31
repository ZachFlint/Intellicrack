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

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use mmap_io::MmapDocument;
use templates::TemplateRegistry;
use undo::{Operation, UndoManager};

#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct Bookmark {
    #[pyo3(get, set)]
    pub offset: usize,
    #[pyo3(get, set)]
    pub length: usize,
    #[pyo3(get, set)]
    pub label: String,
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

/// Everything one open document owns, with no synchronisation of its own.
///
/// Only [`HexDocument`] may hold one of these, and only behind its lock, so the
/// methods here are free to take `&mut self` exactly as they did when this was
/// itself the `#[pyclass]`.
pub struct DocumentState {
    inner: MmapDocument,
    undo_mgr: UndoManager,
    bookmarks: Vec<Bookmark>,
    template_registry: TemplateRegistry,
    va_mappings: Vec<(usize, u64, usize)>,
    chunk_size_hint: usize,
    memory_budget_hint: usize,
    generation: u64,
}

/// One open document, safe to share across threads.
///
/// This is `frozen` so `PyO3` hands out `&self` and never an exclusive borrow.
/// Before that change, the 28 mutating methods forced `PyO3` to take a `RefCell`
/// borrow for the duration of the call, and because the long analyses hold that
/// borrow across `Python::detach`, any second thread touching the same document
/// got `RuntimeError: Already borrowed`. Callers worked around it by serialising
/// every call behind a lock of their own, which also serialised the read-only
/// analyses that could safely have run together.
///
/// # Locking
///
/// Every acquisition of `state` **must** happen inside `Python::detach`, which
/// is what [`HexDocument::read`] and [`HexDocument::write`] do. Taking the lock
/// while still holding the GIL deadlocks: a writer that is inside `detach` has
/// released the GIL but still holds this lock, so a second thread that blocks on
/// the lock *while holding the GIL* stops the writer from ever re-acquiring the
/// GIL to finish and release. This is why `parking_lot` is used with
/// `send_guard`, and why several methods below take a `Python` token they would
/// not otherwise need.
///
/// For the same reason no `#[pymethods]` function may call another: it would
/// take the lock twice and `RwLock` is not reentrant. The facade delegates to
/// [`DocumentState`] instead, which is where the logic lives.
#[pyclass(frozen)]
pub struct HexDocument {
    state: RwLock<DocumentState>,
}

impl HexDocument {
    /// Wrap freshly built state.
    fn wrap(state: DocumentState) -> Self {
        Self {
            state: RwLock::new(state),
        }
    }

    /// Borrow the document for reading, releasing the GIL while blocking.
    fn lock_read(&self, py: Python<'_>) -> RwLockReadGuard<'_, DocumentState> {
        py.detach(|| self.state.read())
    }

    /// Borrow the document for writing, releasing the GIL while blocking.
    fn lock_write(&self, py: Python<'_>) -> RwLockWriteGuard<'_, DocumentState> {
        py.detach(|| self.state.write())
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
            chunk_size_hint: 4 * 1024 * 1024,
            memory_budget_hint: 512 * 1024 * 1024,
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
            chunk_size_hint: 4 * 1024 * 1024,
            memory_budget_hint: 512 * 1024 * 1024,
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
            chunk_size_hint: 4 * 1024 * 1024,
            memory_budget_hint: 512 * 1024 * 1024,
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

    fn save(&mut self, path: &str) -> PyResult<()> {
        self.inner
            .save(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        self.undo_mgr.mark_saved();
        Ok(())
    }

    fn save_as(&mut self, path: &str) -> PyResult<()> {
        self.save(path)
    }

    fn close(&mut self) {
        self.inner.close();
    }

    fn length(&self) -> usize {
        self.inner.document_size()
    }

    fn read(&self, offset: usize, length: usize) -> PyResult<Vec<u8>> {
        if offset > self.inner.document_size() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "offset {} beyond document size {}",
                offset,
                self.inner.document_size()
            )));
        }
        Ok(self.inner.read(offset, length))
    }

    fn read_byte(&self, offset: usize) -> PyResult<u8> {
        self.inner
            .read_byte(offset)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))
    }

    fn write_bytes(&mut self, offset: usize, data: &[u8]) -> PyResult<()> {
        if offset >= self.inner.document_size() {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "offset {} beyond document size {}",
                offset,
                self.inner.document_size()
            )));
        }

        let actual_len = data.len().min(self.inner.document_size() - offset);
        let old_data = self.inner.read(offset, actual_len);
        self.inner.overwrite(offset, &data[..actual_len]);
        self.undo_mgr.record(Operation::Overwrite {
            offset,
            old_data,
            new_data: data[..actual_len].to_vec(),
        });
        self.touch();
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
        self.undo_mgr.record(Operation::Insert {
            offset,
            data: data.to_vec(),
        });
        self.touch();
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
        self.undo_mgr.record(Operation::Delete {
            offset,
            deleted_data,
        });
        self.touch();
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

    fn search_bytes(
        &self,
        py: Python<'_>,
        pattern: Vec<u8>,
        max_results: usize,
    ) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let results = py.detach(move || search::search_bytes(&data, &pattern, max_results));
        results.into_iter().map(|r| (r.offset, r.length)).collect()
    }

    fn search_hex(&self, py: Python<'_>, pattern: &str, max_results: usize) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let results = py.detach(|| search::search_hex_with_wildcards(&data, pattern, max_results));
        results.into_iter().map(|r| (r.offset, r.length)).collect()
    }

    fn search_text(
        &self,
        py: Python<'_>,
        text: &str,
        encoding: &str,
        case_sensitive: bool,
        max_results: usize,
    ) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let text_owned = text.to_string();
        let encoding_owned = encoding.to_string();
        let results = py.detach(|| {
            search::search_text(
                &data,
                &text_owned,
                &encoding_owned,
                case_sensitive,
                max_results,
            )
        });
        results.into_iter().map(|r| (r.offset, r.length)).collect()
    }

    fn search_regex(
        &self,
        py: Python<'_>,
        pattern: &str,
        max_results: usize,
    ) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let pattern_owned = pattern.to_string();
        let results = py.detach(|| search::search_regex(&data, &pattern_owned, max_results));
        results.into_iter().map(|r| (r.offset, r.length)).collect()
    }

    fn replace_bytes(&mut self, py: Python<'_>, pattern: &[u8], replacement: &[u8]) -> usize {
        let data = self.inner.read_all();
        let pattern_owned = pattern.to_vec();
        let replacement_owned = replacement.to_vec();
        let (new_data, count) =
            py.detach(|| search::replace_all(&data, &pattern_owned, &replacement_owned));
        if count > 0 {
            let old_data = data;
            self.inner = MmapDocument::from_bytes(&new_data);
            self.undo_mgr.record(Operation::Overwrite {
                offset: 0,
                old_data,
                new_data,
            });
            self.touch();
        }
        count
    }

    fn inspect_at(&self, py: Python<'_>, offset: usize) -> PyResult<Py<PyAny>> {
        let needed = 16.min(self.inner.document_size().saturating_sub(offset));
        let slice = self.inner.read(offset, needed);
        let inspection = data_inspector::inspect_at(&slice, 0);
        let dict = PyDict::new(py);
        for (key, value) in inspection.to_map() {
            dict.set_item(key, value)?;
        }
        Ok(dict.into())
    }

    fn compute_hash(&self, py: Python<'_>, algorithm: &str) -> PyResult<String> {
        let doc_size = self.inner.document_size();
        let chunk_size = self.chunk_size_hint.max(65536);
        let mut hasher = hash::StreamingHasher::new(algorithm)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let mut offset: usize = 0;
        while offset < doc_size {
            let len = chunk_size.min(doc_size - offset);
            let chunk = self.inner.read(offset, len);
            py.detach(|| hasher.update(&chunk));
            offset += len;
        }
        Ok(hasher.finalize().hex_digest)
    }

    fn compute_hash_range(
        &self,
        py: Python<'_>,
        start: usize,
        end: usize,
        algorithm: &str,
    ) -> PyResult<String> {
        let actual_end = end.min(self.inner.document_size());
        if start > actual_end {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid range: start={start}, end={actual_end}"
            )));
        }
        let range_data = self.inner.read(start, actual_end - start);
        let algo = algorithm.to_string();
        let result = py.detach(|| hash::compute_hash(&range_data, &algo));
        match result {
            Ok(r) => Ok(r.hex_digest),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
        }
    }

    fn byte_statistics(&self, py: Python<'_>) -> Vec<(u8, usize)> {
        let mut counts = [0usize; 256];
        let doc_size = self.inner.document_size();
        let chunk_size = self.chunk_size_hint.max(65536);
        let mut offset: usize = 0;
        while offset < doc_size {
            let len = chunk_size.min(doc_size - offset);
            let chunk = self.inner.read(offset, len);
            py.detach(|| {
                for &b in &chunk {
                    counts[b as usize] += 1;
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

        let data = self.inner.read_all();
        let fields = self
            .template_registry
            .apply(name, &data, offset)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

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
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn remove_template(&mut self, name: &str) -> bool {
        self.template_registry.remove(name)
    }

    fn export_template_json(&self, name: &str) -> PyResult<String> {
        self.template_registry
            .export_json(name)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn list_templates_detailed(&self) -> Vec<(String, String, String, usize)> {
        self.template_registry.list_detailed()
    }

    fn file_path(&self) -> Option<String> {
        self.inner
            .file_path()
            .map(|p| p.to_string_lossy().into_owned())
    }

    fn entropy(&self, py: Python<'_>) -> f64 {
        let data = self.inner.read_all();
        py.detach(|| entropy::compute_entropy(&data))
    }

    fn entropy_map(&self, py: Python<'_>, block_size: usize) -> Vec<f64> {
        let data = self.inner.read_all();
        py.detach(|| entropy::entropy_map(&data, block_size))
    }

    fn byte_distribution_full(&self, py: Python<'_>) -> Vec<u64> {
        let data = self.inner.read_all();
        let dist = py.detach(|| entropy::byte_distribution(&data));
        dist.to_vec()
    }

    fn byte_type_distribution(&self, py: Python<'_>) -> (u64, u64, u64, u64) {
        let data = self.inner.read_all();
        py.detach(|| entropy::byte_type_distribution(&data))
    }

    fn digram_matrix(&self, py: Python<'_>) -> Vec<u64> {
        let data = self.inner.read_all();
        py.detach(|| entropy::digram_matrix(&data))
    }

    fn content_classification(&self, py: Python<'_>, block_size: usize) -> Vec<u8> {
        let data = self.inner.read_all();
        py.detach(|| entropy::content_classification(&data, block_size))
    }

    fn entropy_map_buffer(&self, py: Python<'_>, block_size: usize) -> Vec<u8> {
        let data = self.inner.read_all();
        py.detach(|| {
            entropy::entropy_map(&data, block_size)
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect()
        })
    }

    fn byte_distribution_buffer(&self, py: Python<'_>) -> Vec<u8> {
        let data = self.inner.read_all();
        py.detach(|| {
            entropy::byte_distribution(&data)
                .iter()
                .flat_map(|count| count.to_le_bytes())
                .collect()
        })
    }

    fn digram_matrix_buffer(&self, py: Python<'_>) -> Vec<u8> {
        let data = self.inner.read_all();
        py.detach(|| {
            entropy::digram_matrix(&data)
                .iter()
                .flat_map(|count| count.to_le_bytes())
                .collect()
        })
    }

    fn read_window(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
    ) -> PyResult<(Vec<u8>, Vec<u8>, u64, usize)> {
        let size = self.inner.document_size();
        if offset > size {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "offset {offset} beyond document size {size}"
            )));
        }
        let data = self.inner.read(offset, length);
        let classes = py.detach(|| entropy::classify_bytes(&data));
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
        let data = self.inner.read(offset, length);
        let name_owned = name.to_string();
        let result = py.detach(move || transforms::apply_transform(&name_owned, &data, &params));
        result.map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
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

    fn export_patches_ips(&self) -> PyResult<Vec<u8>> {
        let ops = self.undo_mgr.get_overwrite_patches();
        let records = patch_export::extract_patches_from_overwrites(&ops);
        patch_export::export_ips(&records, &|offset| self.inner.read_byte(offset).ok())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn export_patches_ips32(&self) -> PyResult<Vec<u8>> {
        let ops = self.undo_mgr.get_overwrite_patches();
        let records = patch_export::extract_patches_from_overwrites(&ops);
        patch_export::export_ips32(&records, &|offset| self.inner.read_byte(offset).ok())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn export_patches_cod(&self) -> Vec<u8> {
        let ops = self.undo_mgr.get_overwrite_patches();
        let records = patch_export::extract_patches_from_overwrites(&ops);
        patch_export::export_cod(&records)
    }

    fn export_patches_json(&self) -> PyResult<String> {
        let ops = self.undo_mgr.get_overwrite_patches();
        let records = patch_export::extract_patches_from_overwrites(&ops);
        patch_export::export_patches_json(&records)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn import_patches_ips(&mut self, data: &[u8]) -> PyResult<usize> {
        let records = patch_export::import_ips(data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let mut applied_count: usize = 0;
        for record in records {
            if record.offset < self.inner.document_size() {
                applied_count += 1;
                let actual_len = record
                    .data
                    .len()
                    .min(self.inner.document_size() - record.offset);
                let old_data = self.inner.read(record.offset, actual_len);
                self.inner
                    .overwrite(record.offset, &record.data[..actual_len]);
                self.undo_mgr.record(undo::Operation::Overwrite {
                    offset: record.offset,
                    old_data,
                    new_data: record.data[..actual_len].to_vec(),
                });
            }
        }
        if applied_count > 0 {
            self.touch();
        }
        Ok(applied_count)
    }

    fn decode_text(&self, offset: usize, length: usize, encoding: &str) -> PyResult<String> {
        let data = self.inner.read(offset, length);
        let (text, _) = encodings::decode_text(&data, encoding)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(text)
    }

    fn encode_text_to_bytes(text: &str, encoding: &str) -> PyResult<Vec<u8>> {
        encodings::encode_text(text, encoding)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn list_encodings() -> Vec<(String, String)> {
        encodings::list_encodings()
    }

    fn search_text_encoded(
        &self,
        py: Python<'_>,
        text: &str,
        encoding: &str,
        case_sensitive: bool,
        max_results: usize,
    ) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let text_owned = text.to_string();
        let enc_owned = encoding.to_string();
        py.detach(|| {
            encodings::search_text_encoded(
                &data,
                &text_owned,
                &enc_owned,
                case_sensitive,
                max_results,
            )
        })
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
    ) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let results = py.detach(|| {
            search::search_numeric_int(
                &data,
                value,
                size,
                signed,
                big_endian,
                alignment,
                max_results,
            )
        });
        results.into_iter().map(|r| (r.offset, r.length)).collect()
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
    ) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let results = py.detach(|| {
            search::search_numeric_float(
                &data,
                value,
                size,
                big_endian,
                tolerance,
                alignment,
                max_results,
            )
        });
        results.into_iter().map(|r| (r.offset, r.length)).collect()
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
    ) -> Vec<(usize, usize)> {
        let (min_val, max_val) = value_range;
        let data = self.inner.read_all();
        let results = py.detach(|| {
            search::search_numeric_range(
                &data,
                min_val,
                max_val,
                size,
                signed,
                big_endian,
                alignment,
                max_results,
            )
        });
        results.into_iter().map(|r| (r.offset, r.length)).collect()
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
        let (start, end) = byte_range;
        let (refin, refout) = reflect;
        let actual_end = end.min(self.inner.document_size());
        if start > actual_end {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid range: start={start}, end={actual_end}"
            )));
        }
        let range_data = self.inner.read(start, actual_end - start);
        let result = py.detach(|| {
            hash::compute_crc_custom(&range_data, width, poly, init, refin, refout, xorout)
        });
        result.map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn from_process_memory(pid: u32, address: usize, size: usize) -> PyResult<Self> {
        #[cfg(windows)]
        {
            use data_source::{DataSource, ProcessDataSource};
            let source = ProcessDataSource::attach(pid, address, size, false)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            let data = source
                .read(0, size)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            Ok(Self {
                inner: MmapDocument::from_bytes(&data),
                undo_mgr: UndoManager::new(),
                bookmarks: Vec::new(),
                template_registry: TemplateRegistry::new(),
                va_mappings: Vec::new(),
                chunk_size_hint: 4 * 1024 * 1024,
                memory_budget_hint: 512 * 1024 * 1024,
                generation: 0,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (pid, address, size);
            Err(pyo3::exceptions::PyRuntimeError::new_err(
                "process memory only supported on Windows",
            ))
        }
    }

    fn list_process_memory_regions(pid: u32) -> PyResult<Vec<(usize, usize, u32, u32)>> {
        #[cfg(windows)]
        {
            use data_source::ProcessDataSource;
            let source = ProcessDataSource::attach(pid, 0, 0, true)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            let regions = source
                .list_regions()
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            Ok(regions
                .iter()
                .map(|r| (r.base_address, r.size, r.protection, r.state))
                .collect())
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            Err(pyo3::exceptions::PyRuntimeError::new_err(
                "process memory only supported on Windows",
            ))
        }
    }

    // --- BPS/UPS Patch Formats ---

    fn export_patches_bps(&self, source_data: &[u8]) -> PyResult<Vec<u8>> {
        let target = self.inner.read_all();
        bps_ups::export_bps(source_data, &target)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Export a BPS patch by memory-mapping the source file inside Rust.
    ///
    /// Avoids the round-trip through Python `bytes` that
    /// `export_patches_bps` requires: the source path is mapped via
    /// `memmap2::Mmap` and the resulting slice is handed directly to
    /// the encoder. The target is read out of this document's piece
    /// table without crossing the FFI boundary.
    fn export_patches_bps_from_path(&self, source_path: &str) -> PyResult<Vec<u8>> {
        self.export_patch_from_path_inner(source_path, bps_ups::export_bps)
    }

    fn import_patches_bps(&mut self, patch_data: &[u8], source_data: &[u8]) -> PyResult<usize> {
        let target = bps_ups::import_bps(patch_data, source_data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let target_len = target.len();
        self.inner = MmapDocument::from_bytes(&target);
        self.undo_mgr = UndoManager::new();
        self.undo_mgr.mark_unsaved();
        self.touch();
        Ok(target_len)
    }

    fn export_patches_ups(&self, source_data: &[u8]) -> PyResult<Vec<u8>> {
        let target = self.inner.read_all();
        bps_ups::export_ups(source_data, &target)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Export a UPS patch by memory-mapping the source file inside Rust.
    ///
    /// Mirrors `export_patches_bps_from_path`: opens the source path
    /// with `memmap2::Mmap` so neither Python nor Rust hold the source
    /// as an owned `Vec<u8>` while encoding proceeds.
    fn export_patches_ups_from_path(&self, source_path: &str) -> PyResult<Vec<u8>> {
        self.export_patch_from_path_inner(source_path, bps_ups::export_ups)
    }

    fn import_patches_ups(&mut self, patch_data: &[u8], source_data: &[u8]) -> PyResult<usize> {
        let target = bps_ups::import_ups(patch_data, source_data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let target_len = target.len();
        self.inner = MmapDocument::from_bytes(&target);
        self.undo_mgr = UndoManager::new();
        self.undo_mgr.mark_unsaved();
        self.touch();
        Ok(target_len)
    }

    // --- Block Operations ---

    fn fill_block(&mut self, offset: usize, length: usize, pattern: &[u8]) -> PyResult<()> {
        if pattern.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "pattern cannot be empty",
            ));
        }
        let doc_len = self.inner.document_size();
        if offset.checked_add(length).is_none_or(|end| end > doc_len) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "block exceeds document size",
            ));
        }
        let fill: Vec<u8> = pattern.iter().cycle().take(length).copied().collect();
        let old_data = self.inner.read(offset, length);
        self.inner.overwrite(offset, &fill);
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset,
            old_data,
            new_data: fill,
        });
        self.touch();
        Ok(())
    }

    fn copy_block(&mut self, src_offset: usize, length: usize, dst_offset: usize) -> PyResult<()> {
        let doc_len = self.inner.document_size();
        if src_offset
            .checked_add(length)
            .is_none_or(|end| end > doc_len)
            || dst_offset
                .checked_add(length)
                .is_none_or(|end| end > doc_len)
        {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "block exceeds document size",
            ));
        }
        let data = self.inner.read(src_offset, length);
        let old_dst = self.inner.read(dst_offset, length);
        self.inner.overwrite(dst_offset, &data);
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset: dst_offset,
            old_data: old_dst,
            new_data: data,
        });
        self.touch();
        Ok(())
    }

    fn move_block(&mut self, src_offset: usize, length: usize, dst_offset: usize) -> PyResult<()> {
        let doc_len = self.inner.document_size();
        if src_offset
            .checked_add(length)
            .is_none_or(|end| end > doc_len)
            || dst_offset
                .checked_add(length)
                .is_none_or(|end| end > doc_len)
        {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "block exceeds document size",
            ));
        }
        if (src_offset < dst_offset + length) && (dst_offset < src_offset + length) {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "source and destination blocks overlap",
            ));
        }
        let data = self.inner.read(src_offset, length);
        let old_dst = self.inner.read(dst_offset, length);
        let zeros = vec![0u8; length];
        self.inner.overwrite(src_offset, &zeros);
        self.inner.overwrite(dst_offset, &data);
        self.undo_mgr.record(undo::Operation::MoveBlock {
            src_offset,
            dst_offset,
            moved_data: data,
            old_dst_data: old_dst,
        });
        self.touch();
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
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "swap_blocks requires equal-length blocks; got len_a={len_a}, len_b={len_b}"
            )));
        }
        let doc_len = self.inner.document_size();
        if offset_a.checked_add(len_a).is_none_or(|end| end > doc_len)
            || offset_b.checked_add(len_b).is_none_or(|end| end > doc_len)
        {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "block exceeds document size",
            ));
        }
        if (offset_a < offset_b + len_b) && (offset_b < offset_a + len_a) {
            return Err(pyo3::exceptions::PyValueError::new_err("blocks overlap"));
        }
        let data_a = self.inner.read(offset_a, len_a);
        let data_b = self.inner.read(offset_b, len_b);
        self.inner.overwrite(offset_a, &data_b);
        self.inner.overwrite(offset_b, &data_a);
        self.undo_mgr.record(undo::Operation::SwapBlocks {
            offset_a,
            offset_b,
            data_a,
            data_b,
        });
        self.touch();
        Ok(())
    }

    // --- Bit Operations ---

    fn get_bit(&self, offset: usize, bit_index: u8) -> PyResult<bool> {
        if bit_index > 7 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "bit_index must be 0-7",
            ));
        }
        let byte = self
            .inner
            .read_byte(offset)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))?;
        Ok(byte & (1 << bit_index) != 0)
    }

    fn set_bit(&mut self, offset: usize, bit_index: u8, value: bool) -> PyResult<()> {
        if bit_index > 7 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "bit_index must be 0-7",
            ));
        }
        let old_byte = self
            .inner
            .read_byte(offset)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))?;
        let new_byte = if value {
            old_byte | (1 << bit_index)
        } else {
            old_byte & !(1 << bit_index)
        };
        self.inner.overwrite(offset, &[new_byte]);
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset,
            old_data: vec![old_byte],
            new_data: vec![new_byte],
        });
        self.touch();
        Ok(())
    }

    fn toggle_bit(&mut self, offset: usize, bit_index: u8) -> PyResult<bool> {
        if bit_index > 7 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "bit_index must be 0-7",
            ));
        }
        let old_byte = self
            .inner
            .read_byte(offset)
            .map_err(|e| pyo3::exceptions::PyIndexError::new_err(e.to_string()))?;
        let new_byte = old_byte ^ (1 << bit_index);
        self.inner.overwrite(offset, &[new_byte]);
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset,
            old_data: vec![old_byte],
            new_data: vec![new_byte],
        });
        self.touch();
        Ok(new_byte & (1 << bit_index) != 0)
    }

    // --- VA Mapping ---

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

    fn file_offset_to_va(&self, offset: usize) -> Option<u64> {
        for &(file_off, va, length) in &self.va_mappings {
            if offset >= file_off && offset < file_off + length {
                return Some(va + (offset - file_off) as u64);
            }
        }
        None
    }

    fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        for &(file_off, base_va, length) in &self.va_mappings {
            let end_va = base_va + length as u64;
            if va >= base_va && va < end_va {
                let delta = usize::try_from(va - base_va).ok()?;
                return Some(file_off + delta);
            }
        }
        None
    }

    // --- String Extraction ---

    fn extract_strings(
        &self,
        py: Python<'_>,
        min_length: usize,
        include_ascii: bool,
        include_utf16: bool,
        max_results: usize,
    ) -> PyResult<Py<PyAny>> {
        let data = self.inner.read_all();
        let matches =
            strings::extract_strings(&data, min_length, include_ascii, include_utf16, max_results);

        let list = PyList::empty(py);
        for m in &matches {
            let dict = PyDict::new(py);
            dict.set_item("offset", m.offset)?;
            dict.set_item("length", m.length)?;
            dict.set_item("encoding", &m.encoding)?;
            dict.set_item("content", &m.content)?;
            list.append(dict)?;
        }
        Ok(list.into())
    }

    // --- PE Checksum ---

    fn verify_pe_checksum(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let data = self.inner.read_all();
        let result = hash::verify_pe_checksum(&data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e:?}")))?;
        let dict = PyDict::new(py);
        dict.set_item("stored", result.stored)?;
        dict.set_item("calculated", result.calculated)?;
        dict.set_item("offset", result.offset)?;
        dict.set_item("valid", result.valid)?;
        Ok(dict.into())
    }

    fn repair_pe_checksum(&mut self) -> PyResult<()> {
        let data = self.inner.read_all();
        let result = hash::verify_pe_checksum(&data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e:?}")))?;
        let new_checksum = result.calculated;
        let old_bytes = result.stored.to_le_bytes().to_vec();
        let checksum_bytes = new_checksum.to_le_bytes();
        self.inner.overwrite(result.offset, &checksum_bytes);
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset: result.offset,
            old_data: old_bytes,
            new_data: checksum_bytes.to_vec(),
        });
        self.touch();
        Ok(())
    }

    // --- Large File Controls ---

    fn get_document_memory_usage(&self) -> usize {
        self.inner.document_size()
    }

    fn set_chunk_size_hint(&mut self, size: usize) {
        self.chunk_size_hint = size;
    }

    fn get_chunk_size_hint(&self) -> usize {
        self.chunk_size_hint
    }

    fn set_memory_budget_hint(&mut self, budget: usize) {
        self.memory_budget_hint = budget;
    }

    fn get_memory_budget_hint(&self) -> usize {
        self.memory_budget_hint
    }
}

impl DocumentState {
    /// Memory-map ``source_path`` and feed it to ``encoder``.
    ///
    /// Shared implementation for `export_patches_bps_from_path` and
    /// `export_patches_ups_from_path`. The source file is opened and
    /// mapped via `memmap2::Mmap` so neither Python nor Rust allocate
    /// a full-file `Vec<u8>` for the source; the target is read out
    /// of this document's piece table.
    ///
    /// # Errors
    ///
    /// Returns `PyIOError` if the file cannot be opened or mapped,
    /// and `PyValueError` if the underlying encoder rejects the
    /// inputs.
    fn export_patch_from_path_inner<F>(&self, source_path: &str, encoder: F) -> PyResult<Vec<u8>>
    where
        F: FnOnce(&[u8], &[u8]) -> std::io::Result<Vec<u8>>,
    {
        let file = std::fs::File::open(source_path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        let metadata = file
            .metadata()
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        let target = self.inner.read_all();
        if metadata.len() == 0 {
            return encoder(&[], &target)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()));
        }
        let mmap = unsafe { memmap2::Mmap::map(&file) }
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        encoder(&mmap[..], &target)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }
}

/// The Python-facing surface.
///
/// Every method here does the same three things: take the lock through
/// [`HexDocument::lock_read`] or [`HexDocument::lock_write`], delegate to
/// [`DocumentState`], and return. No method calls another, because the lock is
/// not reentrant; where the old code chained two entry points together
/// (`save_as` onto `save`, `add_bookmark` onto `add_bookmark_object`) the chain
/// now happens one level down, inside `DocumentState`.
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
    fn from_process_memory(pid: u32, address: usize, size: usize) -> PyResult<Self> {
        DocumentState::from_process_memory(pid, address, size).map(Self::wrap)
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

    fn save(&self, py: Python<'_>, path: &str) -> PyResult<()> {
        self.lock_write(py).save(path)
    }

    fn save_as(&self, py: Python<'_>, path: &str) -> PyResult<()> {
        self.lock_write(py).save_as(path)
    }

    fn close(&self, py: Python<'_>) {
        self.lock_write(py).close();
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
        self.lock_write(py).delete_bytes(offset, length)
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
        self.lock_read(py).search_bytes(py, pattern, max_results)
    }

    fn search_hex(&self, py: Python<'_>, pattern: &str, max_results: usize) -> Vec<(usize, usize)> {
        self.lock_read(py).search_hex(py, pattern, max_results)
    }

    fn search_text(
        &self,
        py: Python<'_>,
        text: &str,
        encoding: &str,
        case_sensitive: bool,
        max_results: usize,
    ) -> Vec<(usize, usize)> {
        self.lock_read(py)
            .search_text(py, text, encoding, case_sensitive, max_results)
    }

    fn search_regex(
        &self,
        py: Python<'_>,
        pattern: &str,
        max_results: usize,
    ) -> Vec<(usize, usize)> {
        self.lock_read(py).search_regex(py, pattern, max_results)
    }

    fn search_text_encoded(
        &self,
        py: Python<'_>,
        text: &str,
        encoding: &str,
        case_sensitive: bool,
        max_results: usize,
    ) -> Vec<(usize, usize)> {
        self.lock_read(py)
            .search_text_encoded(py, text, encoding, case_sensitive, max_results)
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
    ) -> Vec<(usize, usize)> {
        self.lock_read(py).search_numeric(
            py,
            value,
            size,
            signed,
            big_endian,
            alignment,
            max_results,
        )
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
    ) -> Vec<(usize, usize)> {
        self.lock_read(py).search_numeric_float(
            py,
            value,
            size,
            big_endian,
            tolerance,
            alignment,
            max_results,
        )
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
    ) -> Vec<(usize, usize)> {
        self.lock_read(py).search_numeric_range(
            py,
            value_range,
            size,
            signed,
            big_endian,
            alignment,
            max_results,
        )
    }

    fn replace_bytes(&self, py: Python<'_>, pattern: &[u8], replacement: &[u8]) -> usize {
        self.lock_write(py).replace_bytes(py, pattern, replacement)
    }

    fn inspect_at(&self, py: Python<'_>, offset: usize) -> PyResult<Py<PyAny>> {
        self.lock_read(py).inspect_at(py, offset)
    }

    fn compute_hash(&self, py: Python<'_>, algorithm: &str) -> PyResult<String> {
        self.lock_read(py).compute_hash(py, algorithm)
    }

    fn compute_hash_range(
        &self,
        py: Python<'_>,
        start: usize,
        end: usize,
        algorithm: &str,
    ) -> PyResult<String> {
        self.lock_read(py)
            .compute_hash_range(py, start, end, algorithm)
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
        self.lock_read(py).byte_statistics(py)
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
        self.lock_read(py).entropy(py)
    }

    fn entropy_map(&self, py: Python<'_>, block_size: usize) -> Vec<f64> {
        self.lock_read(py).entropy_map(py, block_size)
    }

    /// `entropy_map` as little-endian `f64`, eight bytes per block.
    ///
    /// The same numbers as [`HexDocument::entropy_map`], in a form that crosses
    /// into a typed array without being built as a list of Python floats first.
    fn entropy_map_bytes(&self, py: Python<'_>, block_size: usize) -> Vec<u8> {
        self.lock_read(py).entropy_map_buffer(py, block_size)
    }

    fn byte_distribution_full(&self, py: Python<'_>) -> Vec<u64> {
        self.lock_read(py).byte_distribution_full(py)
    }

    /// `byte_distribution_full` as little-endian `u64`, 2048 bytes.
    fn byte_distribution_bytes(&self, py: Python<'_>) -> Vec<u8> {
        self.lock_read(py).byte_distribution_buffer(py)
    }

    fn byte_type_distribution(&self, py: Python<'_>) -> (u64, u64, u64, u64) {
        self.lock_read(py).byte_type_distribution(py)
    }

    fn digram_matrix(&self, py: Python<'_>) -> Vec<u64> {
        self.lock_read(py).digram_matrix(py)
    }

    /// `digram_matrix` as little-endian `u64`, 512 KiB for the 256x256 grid.
    fn digram_matrix_bytes(&self, py: Python<'_>) -> Vec<u8> {
        self.lock_read(py).digram_matrix_buffer(py)
    }

    fn content_classification(&self, py: Python<'_>, block_size: usize) -> Vec<u8> {
        self.lock_read(py).content_classification(py, block_size)
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

    fn export_patches_cod(&self, py: Python<'_>) -> Vec<u8> {
        self.lock_read(py).export_patches_cod()
    }

    fn export_patches_json(&self, py: Python<'_>) -> PyResult<String> {
        self.lock_read(py).export_patches_json()
    }

    fn import_patches_ips(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        self.lock_write(py).import_patches_ips(data)
    }

    fn export_patches_bps(&self, py: Python<'_>, source_data: &[u8]) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_bps(source_data)
    }

    fn export_patches_bps_from_path(&self, py: Python<'_>, source_path: &str) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_bps_from_path(source_path)
    }

    fn import_patches_bps(
        &self,
        py: Python<'_>,
        patch_data: &[u8],
        source_data: &[u8],
    ) -> PyResult<usize> {
        self.lock_write(py)
            .import_patches_bps(patch_data, source_data)
    }

    fn export_patches_ups(&self, py: Python<'_>, source_data: &[u8]) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_ups(source_data)
    }

    fn export_patches_ups_from_path(&self, py: Python<'_>, source_path: &str) -> PyResult<Vec<u8>> {
        self.lock_read(py).export_patches_ups_from_path(source_path)
    }

    fn import_patches_ups(
        &self,
        py: Python<'_>,
        patch_data: &[u8],
        source_data: &[u8],
    ) -> PyResult<usize> {
        self.lock_write(py)
            .import_patches_ups(patch_data, source_data)
    }

    fn decode_text(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
        encoding: &str,
    ) -> PyResult<String> {
        self.lock_read(py).decode_text(offset, length, encoding)
    }

    fn fill_block(
        &self,
        py: Python<'_>,
        offset: usize,
        length: usize,
        pattern: &[u8],
    ) -> PyResult<()> {
        self.lock_write(py).fill_block(offset, length, pattern)
    }

    fn copy_block(
        &self,
        py: Python<'_>,
        src_offset: usize,
        length: usize,
        dst_offset: usize,
    ) -> PyResult<()> {
        self.lock_write(py)
            .copy_block(src_offset, length, dst_offset)
    }

    fn move_block(
        &self,
        py: Python<'_>,
        src_offset: usize,
        length: usize,
        dst_offset: usize,
    ) -> PyResult<()> {
        self.lock_write(py)
            .move_block(src_offset, length, dst_offset)
    }

    fn swap_blocks(
        &self,
        py: Python<'_>,
        offset_a: usize,
        len_a: usize,
        offset_b: usize,
        len_b: usize,
    ) -> PyResult<()> {
        self.lock_write(py)
            .swap_blocks(offset_a, len_a, offset_b, len_b)
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

    fn extract_strings(
        &self,
        py: Python<'_>,
        min_length: usize,
        include_ascii: bool,
        include_utf16: bool,
        max_results: usize,
    ) -> PyResult<Py<PyAny>> {
        self.lock_read(py).extract_strings(
            py,
            min_length,
            include_ascii,
            include_utf16,
            max_results,
        )
    }

    fn verify_pe_checksum(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.lock_read(py).verify_pe_checksum(py)
    }

    fn repair_pe_checksum(&self, py: Python<'_>) -> PyResult<()> {
        self.lock_write(py).repair_pe_checksum()
    }

    fn get_document_memory_usage(&self, py: Python<'_>) -> usize {
        self.lock_read(py).get_document_memory_usage()
    }

    fn set_chunk_size_hint(&self, py: Python<'_>, size: usize) {
        self.lock_write(py).set_chunk_size_hint(size);
    }

    fn get_chunk_size_hint(&self, py: Python<'_>) -> usize {
        self.lock_read(py).get_chunk_size_hint()
    }

    fn set_memory_budget_hint(&self, py: Python<'_>, budget: usize) {
        self.lock_write(py).set_memory_budget_hint(budget);
    }

    fn get_memory_budget_hint(&self, py: Python<'_>) -> usize {
        self.lock_read(py).get_memory_budget_hint()
    }
}

#[pyfunction]
fn diff_files(py: Python<'_>, path_a: &str, path_b: &str) -> PyResult<Py<PyAny>> {
    let data_a = std::fs::read(path_a).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Failed to read {path_a}: {e}"))
    })?;
    let data_b = std::fs::read(path_b).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Failed to read {path_b}: {e}"))
    })?;

    diff_result_to_py(py, &data_a, &data_b)
}

#[pyfunction]
fn diff_bytes(py: Python<'_>, data_a: &[u8], data_b: &[u8]) -> PyResult<Py<PyAny>> {
    diff_result_to_py(py, data_a, data_b)
}

fn diff_result_to_py(py: Python<'_>, data_a: &[u8], data_b: &[u8]) -> PyResult<Py<PyAny>> {
    let result = diff::diff_data(data_a, data_b);

    let dict = PyDict::new(py);
    dict.set_item("total_differences", result.total_differences)?;
    dict.set_item("files_identical", result.files_identical)?;
    dict.set_item("size_a", data_a.len())?;
    dict.set_item("size_b", data_b.len())?;

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

    /// F-0004/F-0048 regression: `offset + length` used raw `usize` addition
    /// for the bounds check, so a huge `offset` chosen to wrap the sum below
    /// `doc_len` bypassed validation entirely. `usize::MAX - 3` and `length =
    /// 10` wrap to `6`, which passes `6 > doc_len` for an 8-byte document.
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

    /// F-0017 regression: `swap_blocks` used to record two independent
    /// `Overwrite` entries, so a single `undo()` only reverted the second
    /// region and left the same bytes duplicated at both offsets.
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

    /// F-0018 regression: the returned count used to be `records.len()`
    /// (every record parsed from the IPS file), not the number of records
    /// actually applied to the document, hiding silently-skipped
    /// out-of-bounds records from the caller.
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
}
