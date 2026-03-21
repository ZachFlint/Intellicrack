pub mod data_inspector;
pub mod diff;
pub mod hash;
pub mod mmap_io;
pub mod piece_table;
pub mod search;
pub mod templates;
pub mod undo;


use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use mmap_io::MmapDocument;
use templates::TemplateRegistry;
use undo::{Operation, UndoManager};

#[pyclass]
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

#[pyclass]
pub struct HexDocument {
    inner: MmapDocument,
    undo_mgr: UndoManager,
    bookmarks: Vec<Bookmark>,
    template_registry: TemplateRegistry,
}

#[pymethods]
impl HexDocument {
    #[new]
    fn new() -> Self {
        Self {
            inner: MmapDocument::new_empty(),
            undo_mgr: UndoManager::new(),
            bookmarks: Vec::new(),
            template_registry: TemplateRegistry::new(),
        }
    }

    #[staticmethod]
    fn open(path: &str) -> PyResult<Self> {
        let doc = MmapDocument::open(path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        Ok(Self {
            inner: doc,
            undo_mgr: UndoManager::new(),
            bookmarks: Vec::new(),
            template_registry: TemplateRegistry::new(),
        })
    }

    #[staticmethod]
    fn open_bytes(data: &[u8]) -> Self {
        Self {
            inner: MmapDocument::from_bytes(data),
            undo_mgr: UndoManager::new(),
            bookmarks: Vec::new(),
            template_registry: TemplateRegistry::new(),
        }
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
        Ok(())
    }

    fn undo(&mut self) -> bool {
        self.undo_mgr.undo(&mut self.inner)
    }

    fn redo(&mut self) -> bool {
        self.undo_mgr.redo(&mut self.inner)
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
    ) -> PyResult<Vec<(usize, usize)>> {
        let data = self.inner.read_all();
        let results = py.allow_threads(|| search::search_bytes(&data, &pattern, max_results));
        Ok(results.into_iter().map(|r| (r.offset, r.length)).collect())
    }

    fn search_hex(
        &self,
        py: Python<'_>,
        pattern: &str,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        let data = self.inner.read_all();
        let results =
            py.allow_threads(|| search::search_hex_with_wildcards(&data, pattern, max_results));
        Ok(results.into_iter().map(|r| (r.offset, r.length)).collect())
    }

    fn search_text(
        &self,
        py: Python<'_>,
        text: &str,
        encoding: &str,
        case_sensitive: bool,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        let data = self.inner.read_all();
        let text_owned = text.to_string();
        let encoding_owned = encoding.to_string();
        let results = py.allow_threads(|| {
            search::search_text(&data, &text_owned, &encoding_owned, case_sensitive, max_results)
        });
        Ok(results.into_iter().map(|r| (r.offset, r.length)).collect())
    }

    fn search_regex(
        &self,
        py: Python<'_>,
        pattern: &str,
        max_results: usize,
    ) -> PyResult<Vec<(usize, usize)>> {
        let data = self.inner.read_all();
        let pattern_owned = pattern.to_string();
        let results =
            py.allow_threads(|| search::search_regex(&data, &pattern_owned, max_results));
        Ok(results.into_iter().map(|r| (r.offset, r.length)).collect())
    }

    fn replace_bytes(&mut self, pattern: Vec<u8>, replacement: Vec<u8>) -> PyResult<usize> {
        let data = self.inner.read_all();
        let (new_data, count) = search::replace_all(&data, &pattern, &replacement);
        if count > 0 {
            let old_data = data;
            self.inner = MmapDocument::from_bytes(&new_data);
            self.undo_mgr.record(Operation::Overwrite {
                offset: 0,
                old_data,
                new_data,
            });
        }
        Ok(count)
    }

    fn inspect_at(&self, py: Python<'_>, offset: usize) -> PyResult<PyObject> {
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
        let chunk_size: usize = 65536;
        let mut all_data = Vec::with_capacity(doc_size);
        let mut offset: usize = 0;
        while offset < doc_size {
            let len = chunk_size.min(doc_size - offset);
            all_data.extend_from_slice(&self.inner.read(offset, len));
            offset += len;
        }
        let algo = algorithm.to_string();
        let result = py.allow_threads(|| hash::compute_hash(&all_data, &algo));
        match result {
            Ok(r) => Ok(r.hex_digest),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
        }
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
                "invalid range: start={}, end={}", start, actual_end
            )));
        }
        let range_data = self.inner.read(start, actual_end - start);
        let algo = algorithm.to_string();
        let result = py.allow_threads(|| hash::compute_hash(&range_data, &algo));
        match result {
            Ok(r) => Ok(r.hex_digest),
            Err(e) => Err(pyo3::exceptions::PyValueError::new_err(e.to_string())),
        }
    }

    fn byte_statistics(&self) -> Vec<(u8, usize)> {
        let mut counts = [0usize; 256];
        let doc_size = self.inner.document_size();
        let chunk_size: usize = 65536;
        let mut offset: usize = 0;
        while offset < doc_size {
            let len = chunk_size.min(doc_size - offset);
            let chunk = self.inner.read(offset, len);
            for &b in &chunk {
                counts[b as usize] += 1;
            }
            offset += len;
        }
        counts
            .iter()
            .enumerate()
            .map(|(byte_val, &count)| (byte_val as u8, count))
            .collect()
    }

    fn add_bookmark(
        &mut self,
        offset: usize,
        length: usize,
        label: &str,
        color: &str,
    ) -> usize {
        let idx = self.bookmarks.len();
        self.bookmarks.push(Bookmark {
            offset,
            length,
            label: label.to_string(),
            color: color.to_string(),
        });
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

    fn apply_template(
        &self,
        py: Python<'_>,
        name: &str,
        offset: usize,
    ) -> PyResult<PyObject> {
        let data = self.inner.read_all();
        let fields = self
            .template_registry
            .apply(name, &data, offset)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        fn field_to_dict(py: Python<'_>, field: &templates::ParsedField) -> PyResult<PyObject> {
            let dict = PyDict::new(py);
            dict.set_item("name", &field.name)?;
            dict.set_item("offset", field.offset)?;
            dict.set_item("size", field.size)?;
            dict.set_item("raw_bytes", &field.raw_bytes)?;
            dict.set_item("display_value", &field.display_value)?;

            let children = PyList::empty(py);
            for child in &field.children {
                children.append(field_to_dict(py, child)?)?;
            }
            dict.set_item("children", children)?;
            Ok(dict.into())
        }

        let result = PyList::empty(py);
        for field in &fields {
            result.append(field_to_dict(py, field)?)?;
        }
        Ok(result.into())
    }

    fn list_templates(&self) -> Vec<(String, String)> {
        self.template_registry.list()
    }

    fn file_path(&self) -> Option<String> {
        self.inner.file_path().map(|p| p.to_string_lossy().into_owned())
    }
}

#[pyfunction]
fn diff_files(py: Python<'_>, path_a: &str, path_b: &str) -> PyResult<PyObject> {
    let data_a = std::fs::read(path_a)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to read {}: {}", path_a, e)))?;
    let data_b = std::fs::read(path_b)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("Failed to read {}: {}", path_b, e)))?;

    diff_result_to_py(py, &data_a, &data_b)
}

#[pyfunction]
fn diff_bytes(py: Python<'_>, data_a: &[u8], data_b: &[u8]) -> PyResult<PyObject> {
    diff_result_to_py(py, data_a, data_b)
}

fn diff_result_to_py(py: Python<'_>, data_a: &[u8], data_b: &[u8]) -> PyResult<PyObject> {
    let result = diff::diff_data(data_a, data_b);

    let dict = PyDict::new(py);
    dict.set_item("total_differences", result.total_differences)?;
    dict.set_item("files_identical", result.files_identical)?;

    let regions = PyList::empty(py);
    for region in &result.regions {
        let r = PyDict::new(py);
        r.set_item("offset_a", region.offset_a)?;
        r.set_item("offset_b", region.offset_b)?;
        r.set_item("length", region.length)?;
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
