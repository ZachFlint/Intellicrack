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
    va_mappings: Vec<(usize, u64, usize)>,
    chunk_size_hint: usize,
    memory_budget_hint: usize,
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
            va_mappings: Vec::new(),
            chunk_size_hint: 4 * 1024 * 1024,
            memory_budget_hint: 512 * 1024 * 1024,
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
            va_mappings: Vec::new(),
            chunk_size_hint: 4 * 1024 * 1024,
            memory_budget_hint: 512 * 1024 * 1024,
        })
    }

    #[staticmethod]
    fn open_bytes(data: &[u8]) -> Self {
        Self {
            inner: MmapDocument::from_bytes(data),
            undo_mgr: UndoManager::new(),
            bookmarks: Vec::new(),
            template_registry: TemplateRegistry::new(),
            va_mappings: Vec::new(),
            chunk_size_hint: 4 * 1024 * 1024,
            memory_budget_hint: 512 * 1024 * 1024,
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
    ) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let results = py.allow_threads(move || search::search_bytes(&data, &pattern, max_results));
        results.into_iter().map(|r| (r.offset, r.length)).collect()
    }

    fn search_hex(&self, py: Python<'_>, pattern: &str, max_results: usize) -> Vec<(usize, usize)> {
        let data = self.inner.read_all();
        let results =
            py.allow_threads(|| search::search_hex_with_wildcards(&data, pattern, max_results));
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
        let results = py.allow_threads(|| {
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
        let results = py.allow_threads(|| search::search_regex(&data, &pattern_owned, max_results));
        results.into_iter().map(|r| (r.offset, r.length)).collect()
    }

    fn replace_bytes(&mut self, pattern: &[u8], replacement: &[u8]) -> usize {
        let data = self.inner.read_all();
        let (new_data, count) = search::replace_all(&data, pattern, replacement);
        if count > 0 {
            let old_data = data;
            self.inner = MmapDocument::from_bytes(&new_data);
            self.undo_mgr.record(Operation::Overwrite {
                offset: 0,
                old_data,
                new_data,
            });
        }
        count
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
                "invalid range: start={start}, end={actual_end}"
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
            .copied()
            .enumerate()
            .map(|(byte_val, count)| {
                let byte = u8::try_from(byte_val).expect("index within 0..256");
                (byte, count)
            })
            .collect()
    }

    fn add_bookmark(&mut self, offset: usize, length: usize, label: &str, color: &str) -> usize {
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

    fn apply_template(&self, py: Python<'_>, name: &str, offset: usize) -> PyResult<PyObject> {
        fn field_to_dict(py: Python<'_>, field: &templates::ParsedField) -> PyResult<PyObject> {
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
        py.allow_threads(|| entropy::compute_entropy(&data))
    }

    fn entropy_map(&self, py: Python<'_>, block_size: usize) -> Vec<f64> {
        let data = self.inner.read_all();
        py.allow_threads(|| entropy::entropy_map(&data, block_size))
    }

    fn byte_distribution_full(&self, py: Python<'_>) -> Vec<u64> {
        let data = self.inner.read_all();
        let dist = py.allow_threads(|| entropy::byte_distribution(&data));
        dist.to_vec()
    }

    fn byte_type_distribution(&self, py: Python<'_>) -> (u64, u64, u64, u64) {
        let data = self.inner.read_all();
        py.allow_threads(|| entropy::byte_type_distribution(&data))
    }

    fn digram_matrix(&self, py: Python<'_>) -> Vec<u64> {
        let data = self.inner.read_all();
        py.allow_threads(|| entropy::digram_matrix(&data))
    }

    fn content_classification(&self, py: Python<'_>, block_size: usize) -> Vec<u8> {
        let data = self.inner.read_all();
        py.allow_threads(|| entropy::content_classification(&data, block_size))
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
        let result =
            py.allow_threads(move || transforms::apply_transform(&name_owned, &data, &params));
        result.map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
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
        patch_export::export_ips(&records)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn export_patches_ips32(&self) -> PyResult<Vec<u8>> {
        let ops = self.undo_mgr.get_overwrite_patches();
        let records = patch_export::extract_patches_from_overwrites(&ops);
        patch_export::export_ips32(&records)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn export_patches_cod(&self) -> PyResult<Vec<u8>> {
        let ops = self.undo_mgr.get_overwrite_patches();
        let records = patch_export::extract_patches_from_overwrites(&ops);
        Ok(patch_export::export_cod(&records))
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
        let count = records.len();
        for record in records {
            if record.offset < self.inner.document_size() {
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
        Ok(count)
    }

    fn decode_text(&self, offset: usize, length: usize, encoding: &str) -> PyResult<String> {
        let data = self.inner.read(offset, length);
        let (text, _) = encodings::decode_text(&data, encoding)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        Ok(text)
    }

    #[staticmethod]
    fn encode_text_to_bytes(text: &str, encoding: &str) -> PyResult<Vec<u8>> {
        encodings::encode_text(text, encoding)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
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
        py.allow_threads(|| {
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
        let results = py.allow_threads(|| {
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
        let results = py.allow_threads(|| {
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
        let results = py.allow_threads(|| {
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
        let result = py.allow_threads(|| {
            hash::compute_crc_custom(&range_data, width, poly, init, refin, refout, xorout)
        });
        result.map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
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

    #[staticmethod]
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

    fn import_patches_bps(&mut self, patch_data: &[u8], source_data: &[u8]) -> PyResult<usize> {
        let target = bps_ups::import_bps(patch_data, source_data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let target_len = target.len();
        self.inner = MmapDocument::from_bytes(&target);
        self.undo_mgr = UndoManager::new();
        self.undo_mgr.mark_unsaved();
        Ok(target_len)
    }

    fn export_patches_ups(&self, source_data: &[u8]) -> PyResult<Vec<u8>> {
        let target = self.inner.read_all();
        bps_ups::export_ups(source_data, &target)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    fn import_patches_ups(&mut self, patch_data: &[u8], source_data: &[u8]) -> PyResult<usize> {
        let target = bps_ups::import_ups(patch_data, source_data)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let target_len = target.len();
        self.inner = MmapDocument::from_bytes(&target);
        self.undo_mgr = UndoManager::new();
        self.undo_mgr.mark_unsaved();
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
        if offset + length > doc_len {
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
        Ok(())
    }

    fn copy_block(&mut self, src_offset: usize, length: usize, dst_offset: usize) -> PyResult<()> {
        let doc_len = self.inner.document_size();
        if src_offset + length > doc_len || dst_offset + length > doc_len {
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
        Ok(())
    }

    fn move_block(&mut self, src_offset: usize, length: usize, dst_offset: usize) -> PyResult<()> {
        let doc_len = self.inner.document_size();
        if src_offset + length > doc_len || dst_offset + length > doc_len {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "block exceeds document size",
            ));
        }
        let data = self.inner.read(src_offset, length);
        let old_dst = self.inner.read(dst_offset, length);
        let zeros = vec![0u8; length];
        self.inner.overwrite(src_offset, &zeros);
        self.inner.overwrite(dst_offset, &data);
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset: dst_offset,
            old_data: old_dst,
            new_data: data,
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
        let doc_len = self.inner.document_size();
        if offset_a + len_a > doc_len || offset_b + len_b > doc_len {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "block exceeds document size",
            ));
        }
        if (offset_a < offset_b + len_b) && (offset_b < offset_a + len_a) {
            return Err(pyo3::exceptions::PyValueError::new_err("blocks overlap"));
        }
        let data_a = self.inner.read(offset_a, len_a);
        let data_b = self.inner.read(offset_b, len_b);
        let mut write_a: Vec<u8> = data_b.clone();
        write_a.resize(len_a, 0);
        let mut write_b: Vec<u8> = data_a.clone();
        write_b.resize(len_b, 0);
        self.inner.overwrite(offset_a, &write_a);
        self.inner.overwrite(offset_b, &write_b);
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset: offset_a,
            old_data: data_a,
            new_data: write_a,
        });
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset: offset_b,
            old_data: data_b,
            new_data: write_b,
        });
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
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
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
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
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
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let new_byte = old_byte ^ (1 << bit_index);
        self.inner.overwrite(offset, &[new_byte]);
        self.undo_mgr.record(undo::Operation::Overwrite {
            offset,
            old_data: vec![old_byte],
            new_data: vec![new_byte],
        });
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
    ) -> PyResult<PyObject> {
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

    fn verify_pe_checksum(&self, py: Python<'_>) -> PyResult<PyObject> {
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

#[pyfunction]
fn diff_files(py: Python<'_>, path_a: &str, path_b: &str) -> PyResult<PyObject> {
    let data_a = std::fs::read(path_a).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Failed to read {path_a}: {e}"))
    })?;
    let data_b = std::fs::read(path_b).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Failed to read {path_b}: {e}"))
    })?;

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
