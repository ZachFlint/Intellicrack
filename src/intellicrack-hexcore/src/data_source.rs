use thiserror::Error;

#[derive(Error, Debug)]
pub enum DataSourceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("offset out of bounds: {offset} >= {length}")]
    OutOfBounds { offset: usize, length: usize },
    #[error("process error: {0}")]
    ProcessError(String),
    #[error("read-only data source")]
    ReadOnly,
}

pub trait DataSource: Send {
    /// Reads data from the source at the given offset.
    ///
    /// # Errors
    ///
    /// Returns `DataSourceError` if the offset is out of bounds or the read fails.
    fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, DataSourceError>;

    /// Writes data to the source at the given offset.
    ///
    /// # Errors
    ///
    /// Returns `DataSourceError` if the source is read-only, offset is out of bounds, or the write fails.
    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), DataSourceError>;

    fn length(&self) -> usize;
    fn is_writable(&self) -> bool;
    fn source_type(&self) -> &'static str;
}

pub struct BufferDataSource {
    data: Vec<u8>,
    writable: bool,
}

impl BufferDataSource {
    #[must_use]
    pub fn new(data: Vec<u8>, writable: bool) -> Self {
        Self { data, writable }
    }

    #[must_use]
    pub fn new_readonly(data: Vec<u8>) -> Self {
        Self {
            data,
            writable: false,
        }
    }
}

impl DataSource for BufferDataSource {
    fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, DataSourceError> {
        if offset > self.data.len() {
            return Err(DataSourceError::OutOfBounds {
                offset,
                length: self.data.len(),
            });
        }
        let end = (offset + length).min(self.data.len());
        Ok(self.data[offset..end].to_vec())
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), DataSourceError> {
        if !self.writable {
            return Err(DataSourceError::ReadOnly);
        }
        if offset > self.data.len() {
            return Err(DataSourceError::OutOfBounds {
                offset,
                length: self.data.len(),
            });
        }
        let end = (offset + data.len()).min(self.data.len());
        let actual_len = end - offset;
        self.data[offset..end].copy_from_slice(&data[..actual_len]);
        Ok(())
    }

    fn length(&self) -> usize {
        self.data.len()
    }

    fn is_writable(&self) -> bool {
        self.writable
    }

    fn source_type(&self) -> &'static str {
        "buffer"
    }
}

#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: u32,
    pub state: u32,
    pub region_type: u32,
}

#[cfg(windows)]
pub struct ProcessDataSource {
    handle: windows_sys::Win32::Foundation::HANDLE,
    pub pid: u32,
    pub base_address: usize,
    pub region_size: usize,
    writable: bool,
}

#[cfg(windows)]
unsafe impl Send for ProcessDataSource {}

#[cfg(windows)]
impl ProcessDataSource {
    /// Attaches to a running process for memory inspection.
    ///
    /// # Errors
    ///
    /// Returns `DataSourceError::ProcessError` if `OpenProcess` fails.
    pub fn attach(
        pid: u32,
        base_address: usize,
        region_size: usize,
        read_only: bool,
    ) -> Result<Self, DataSourceError> {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
            PROCESS_VM_WRITE,
        };
        let access = if read_only {
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
        } else {
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
        };
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            return Err(DataSourceError::ProcessError(format!(
                "OpenProcess failed for pid {pid}"
            )));
        }
        Ok(Self {
            handle,
            pid,
            base_address,
            region_size,
            writable: !read_only,
        })
    }

    /// Lists all memory regions in the attached process.
    ///
    /// # Errors
    ///
    /// Returns `DataSourceError` if querying virtual memory fails.
    pub fn list_regions(&self) -> Result<Vec<MemoryRegion>, DataSourceError> {
        use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
        let mut regions = Vec::new();
        let mut address: usize = 0;
        loop {
            let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
            let result = unsafe {
                VirtualQueryEx(
                    self.handle,
                    address as *const std::ffi::c_void,
                    &raw mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if result == 0 {
                break;
            }
            regions.push(MemoryRegion {
                base_address: mbi.BaseAddress as usize,
                size: mbi.RegionSize,
                protection: mbi.Protect,
                state: mbi.State,
                region_type: mbi.Type,
            });
            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 {
                break;
            }
        }
        Ok(regions)
    }
}

#[cfg(windows)]
impl DataSource for ProcessDataSource {
    fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, DataSourceError> {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        if offset > self.region_size {
            return Err(DataSourceError::OutOfBounds {
                offset,
                length: self.region_size,
            });
        }
        let length = length.min(self.region_size - offset);
        if length == 0 {
            return Ok(Vec::new());
        }
        let addr = self.base_address + offset;
        let mut buffer = vec![0u8; length];
        let mut bytes_read: usize = 0;
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const std::ffi::c_void,
                buffer.as_mut_ptr().cast::<std::ffi::c_void>(),
                length,
                &raw mut bytes_read,
            )
        };
        if result == 0 {
            return Err(DataSourceError::ProcessError(
                "ReadProcessMemory failed".to_string(),
            ));
        }
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), DataSourceError> {
        use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        if !self.writable {
            return Err(DataSourceError::ReadOnly);
        }
        if offset > self.region_size {
            return Err(DataSourceError::OutOfBounds {
                offset,
                length: self.region_size,
            });
        }
        let max_len = self.region_size - offset;
        let data = &data[..data.len().min(max_len)];
        if data.is_empty() {
            return Ok(());
        }
        let addr = self.base_address + offset;
        let mut bytes_written: usize = 0;
        let result = unsafe {
            WriteProcessMemory(
                self.handle,
                addr as *const std::ffi::c_void,
                data.as_ptr().cast::<std::ffi::c_void>(),
                data.len(),
                &raw mut bytes_written,
            )
        };
        if result == 0 {
            return Err(DataSourceError::ProcessError(
                "WriteProcessMemory failed".to_string(),
            ));
        }
        Ok(())
    }

    fn length(&self) -> usize {
        self.region_size
    }

    fn is_writable(&self) -> bool {
        self.writable
    }

    fn source_type(&self) -> &'static str {
        "process"
    }
}

#[cfg(windows)]
impl Drop for ProcessDataSource {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BufferDataSource, DataSource, DataSourceError};

    #[test]
    fn test_read_mid_offset_returns_exact_slice() {
        // Oracle: bytes at indices 1..4 of [0x41,0x42,0x43,0x44,0x45] are [0x42,0x43,0x44]
        let src = BufferDataSource::new(vec![0x41u8, 0x42, 0x43, 0x44, 0x45], false);
        let result = src.read(1, 3).unwrap();
        assert_eq!(result, vec![0x42u8, 0x43, 0x44]);
        // Mutation caught: `self.data[0..actual_len]` instead of `self.data[offset..end]`
        // places bytes from index 0, returning [0x41,0x42,0x43] and failing this assertion
    }

    #[test]
    fn test_read_from_offset_zero_returns_leading_bytes() {
        // Oracle: full buffer [0x10,0x20,0x30] read from offset 0, length 3
        let src = BufferDataSource::new(vec![0x10u8, 0x20, 0x30], false);
        let result = src.read(0, 3).unwrap();
        assert_eq!(result, vec![0x10u8, 0x20, 0x30]);
        // Mutation caught: returning data starting from offset 1 drops 0x10 and fails equality
    }

    #[test]
    fn test_read_length_beyond_end_clamps_to_buffer_boundary() {
        // Oracle: [0xAA,0xBB,0xCC].read(1,10); end = min(11,3) = 3; slice [1..3] = [0xBB,0xCC]
        let src = BufferDataSource::new(vec![0xAAu8, 0xBB, 0xCC], false);
        let result = src.read(1, 10).unwrap();
        assert_eq!(result, vec![0xBBu8, 0xCC]);
        // Mutation caught: `.min(self.data.len() - 1)` returns [0xBB] only, failing the eq
    }

    #[test]
    fn test_read_offset_equal_to_len_returns_empty_vec() {
        // Boundary: offset == data.len(); guard `offset > len` is false, so Ok([]) is the contract.
        // Mutation caught: changing `>` to `>=` in the bounds guard returns Err instead of Ok([])
        let src = BufferDataSource::new(vec![0x01u8, 0x02, 0x03], false);
        let result = src.read(3, 5).unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_read_offset_beyond_len_returns_exact_out_of_bounds_variant() {
        // Oracle: buffer.len() == 3; offset 4 > 3 triggers OutOfBounds{offset:4, length:3}
        // Mutation caught: removing the guard causes a panic; wrong field values fail the match
        let src = BufferDataSource::new(vec![0x01u8, 0x02, 0x03], false);
        let err = src.read(4, 1).unwrap_err();
        assert!(
            matches!(
                err,
                DataSourceError::OutOfBounds {
                    offset: 4,
                    length: 3
                }
            ),
            "expected OutOfBounds{{offset:4, length:3}}, got {err:?}"
        );
    }

    #[test]
    fn test_write_within_bounds_mutates_exact_byte_positions() {
        // Oracle: [0,0,0,0,0].write([0xDE,0xAD], offset=2) -> [0x00,0x00,0xDE,0xAD,0x00]
        // Mutation caught: `self.data[0..actual_len]` instead of `self.data[offset..end]`
        // places 0xDE at index 0, producing [0xDE,0xAD,0x00,0x00,0x00] and failing equality
        let mut src = BufferDataSource::new(vec![0x00u8; 5], true);
        src.write(2, &[0xDEu8, 0xAD]).unwrap();
        let readback = src.read(0, 5).unwrap();
        assert_eq!(readback, vec![0x00u8, 0x00, 0xDE, 0xAD, 0x00]);
    }

    #[test]
    fn test_write_partial_overlap_at_buffer_end_clamps_written_data() {
        // Oracle: [0,0,0,0].write([0x11,0x22,0x33,0x44], offset=2)
        // end = min(6,4) = 4; actual_len = 4-2 = 2; only [0x11,0x22] written at indices 2..4
        // Mutation caught: removing `.min(self.data.len())` causes copy_from_slice to panic
        let mut src = BufferDataSource::new(vec![0x00u8; 4], true);
        src.write(2, &[0x11u8, 0x22, 0x33, 0x44]).unwrap();
        let readback = src.read(0, 4).unwrap();
        assert_eq!(readback, vec![0x00u8, 0x00, 0x11, 0x22]);
    }

    #[test]
    fn test_write_offset_beyond_len_returns_exact_out_of_bounds_variant() {
        // Oracle: buffer.len() == 3; write at offset 10 -> OutOfBounds{offset:10, length:3}
        // Mutation caught: removing the write bounds check causes a slice panic instead of Err
        let mut src = BufferDataSource::new(vec![0xAAu8, 0xBB, 0xCC], true);
        let err = src.write(10, &[0xFFu8]).unwrap_err();
        assert!(
            matches!(
                err,
                DataSourceError::OutOfBounds {
                    offset: 10,
                    length: 3
                }
            ),
            "expected OutOfBounds{{offset:10, length:3}}, got {err:?}"
        );
    }

    #[test]
    fn test_write_on_new_readonly_returns_read_only_variant() {
        // new_readonly sets writable:false; write must return ReadOnly before any bounds check
        // Mutation caught: removing `if !self.writable` allows the write to proceed silently
        let mut src = BufferDataSource::new_readonly(vec![0x01u8, 0x02]);
        let err = src.write(0, &[0xFFu8]).unwrap_err();
        assert!(
            matches!(err, DataSourceError::ReadOnly),
            "expected ReadOnly, got {err:?}"
        );
    }

    #[test]
    fn test_write_on_new_with_writable_false_returns_read_only_variant() {
        // new(..., false) must treat writable:false identically to new_readonly
        // Mutation caught: inverting `!self.writable` to `self.writable` flips read/write semantics
        let mut src = BufferDataSource::new(vec![0xAAu8], false);
        let err = src.write(0, &[0xBBu8]).unwrap_err();
        assert!(
            matches!(err, DataSourceError::ReadOnly),
            "expected ReadOnly, got {err:?}"
        );
    }

    #[test]
    fn test_write_on_writable_source_succeeds_and_changes_bytes() {
        // Confirms writable:true allows writes; read-back distinguishes from ReadOnly rejection
        // Mutation caught: always returning Err(ReadOnly) regardless of writable flag fails here
        let mut src = BufferDataSource::new(vec![0x00u8; 3], true);
        src.write(0, &[0xCAu8, 0xFE, 0xBA]).unwrap();
        assert_eq!(src.read(0, 3).unwrap(), vec![0xCAu8, 0xFE, 0xBA]);
    }

    #[test]
    fn test_length_returns_exact_allocated_byte_count() {
        // Oracle: exactly 7 bytes allocated; length() must equal data.len() == 7
        // Mutation caught: `self.data.capacity()` or a constant differs from the logical length
        let src = BufferDataSource::new(vec![0u8; 7], false);
        assert_eq!(src.length(), 7usize);
    }

    #[test]
    fn test_is_writable_returns_true_when_constructed_writable() {
        // Mutation caught: always returning `false` from is_writable fails this assertion
        let src = BufferDataSource::new(vec![0u8; 4], true);
        assert!(src.is_writable());
    }

    #[test]
    fn test_is_writable_returns_false_for_new_readonly_source() {
        // Mutation caught: new_readonly setting `writable: true` fails this assertion
        let src = BufferDataSource::new_readonly(vec![0u8; 4]);
        assert!(!src.is_writable());
    }

    #[test]
    fn test_is_writable_returns_false_for_new_with_writable_false() {
        // Mutation caught: ignoring the writable constructor argument returns true here
        let src = BufferDataSource::new(vec![0u8; 2], false);
        assert!(!src.is_writable());
    }

    #[test]
    fn test_source_type_returns_buffer_discriminator_string() {
        // Oracle: "buffer" distinguishes this source from "process" in dispatch code
        // Mutation caught: returning "process" or "" fails the exact string equality
        let src = BufferDataSource::new(vec![], false);
        assert_eq!(src.source_type(), "buffer");
    }

    #[test]
    fn test_datasource_error_io_from_std_io_error_preserves_message() {
        // Covers the `#[from] std::io::Error` conversion on DataSourceError::Io.
        // Mutation caught: dropping the `#[from]` attribute breaks the `?`/`.into()` path;
        // altering the Display format string fails the prefix/content assertions.
        let io_err =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "mapped view failed");
        let ds_err: DataSourceError = io_err.into();
        assert!(
            matches!(ds_err, DataSourceError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "expected Io(PermissionDenied), got {ds_err:?}"
        );
        assert_eq!(ds_err.to_string(), "I/O error: mapped view failed");
    }
}

#[cfg(all(test, windows))]
mod process_tests {
    use super::{DataSource, DataSourceError, MemoryRegion, ProcessDataSource};

    #[test]
    fn test_memory_region_debug_and_clone_roundtrip() {
        // Exercises the derived Debug + Clone on MemoryRegion.
        // Mutation caught: dropping a field from Clone changes the cloned value; a broken
        // Debug impl fails the substring check.
        let region = MemoryRegion {
            base_address: 0x0001_0000,
            size: 0x2000,
            protection: 0x20,
            state: 0x1000,
            region_type: 0x2_0000,
        };
        let cloned = region.clone();
        assert_eq!(cloned.base_address, 0x0001_0000);
        assert_eq!(cloned.size, 0x2000);
        assert_eq!(cloned.protection, 0x20);
        assert_eq!(cloned.state, 0x1000);
        assert_eq!(cloned.region_type, 0x2_0000);
        let dbg = format!("{region:?}");
        assert!(dbg.contains("MemoryRegion"), "unexpected Debug: {dbg}");
        assert!(
            dbg.contains("65536"),
            "base_address missing from Debug: {dbg}"
        );
    }

    #[test]
    fn test_attach_readonly_sets_access_flags_and_metadata() {
        // read_only=true takes the PROCESS_VM_READ|PROCESS_QUERY_INFORMATION access branch.
        // Mutation caught: setting writable:!read_only wrong flips is_writable().
        let src = ProcessDataSource::attach(std::process::id(), 0, 4096, true)
            .expect("self-attach failed");
        assert!(!src.is_writable());
        assert_eq!(src.length(), 4096);
        assert_eq!(src.source_type(), "process");
    }

    #[test]
    fn test_attach_writable_sets_writable_true() {
        // read_only=false takes the VM_WRITE|VM_OPERATION access branch and sets writable:true.
        // Mutation caught: swapping the two access-flag branches would still open, but
        // is_writable() would be false here.
        let src = ProcessDataSource::attach(std::process::id(), 0, 8, false)
            .expect("self-attach (writable) failed");
        assert!(src.is_writable());
        assert_eq!(src.source_type(), "process");
    }

    #[test]
    fn test_attach_invalid_pid_returns_process_error() {
        // u32::MAX is odd; Windows kernel PIDs are multiples of 4, so it never names a live
        // process and OpenProcess returns NULL.
        // Mutation caught: removing the `handle.is_null()` guard returns Ok with a null handle.
        let Err(err) = ProcessDataSource::attach(u32::MAX, 0, 16, true) else {
            panic!("expected attach to an invalid pid to fail");
        };
        assert!(
            matches!(err, DataSourceError::ProcessError(_)),
            "expected ProcessError, got {err:?}"
        );
    }

    #[test]
    fn test_read_own_memory_returns_exact_bytes() {
        // Real ReadProcessMemory against our own committed heap: read back a known payload.
        // Mutation caught: an off-by-one on `base_address + offset` returns shifted bytes.
        let payload: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let base = payload.as_ptr() as usize;
        let src = ProcessDataSource::attach(std::process::id(), base, payload.len(), true)
            .expect("self-attach failed");
        assert_eq!(src.read(0, 4).unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(src.read(1, 2).unwrap(), vec![0xAD, 0xBE]);
        // Keep payload alive until after the reads complete.
        assert_eq!(payload.len(), 4);
    }

    #[test]
    fn test_read_zero_length_returns_empty_without_syscall() {
        // length==0 early-return path.
        // Mutation caught: removing the guard issues ReadProcessMemory(len=0) which fails -> Err.
        let src =
            ProcessDataSource::attach(std::process::id(), 0, 16, true).expect("attach failed");
        assert_eq!(src.read(0, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_write_readonly_source_returns_read_only() {
        // Writable guard fires before any WriteProcessMemory call.
        // Mutation caught: removing the `!self.writable` guard attempts the syscall.
        let mut src =
            ProcessDataSource::attach(std::process::id(), 0, 16, true).expect("attach failed");
        let err = src.write(0, &[0xFF]).unwrap_err();
        assert!(
            matches!(err, DataSourceError::ReadOnly),
            "expected ReadOnly, got {err:?}"
        );
    }

    #[test]
    fn test_write_empty_data_is_noop_ok() {
        // data.is_empty() early-return on a writable source.
        // Mutation caught: removing the guard issues WriteProcessMemory(len=0) -> Err.
        let mut src =
            ProcessDataSource::attach(std::process::id(), 0, 16, false).expect("attach failed");
        assert!(src.write(0, &[]).is_ok());
    }

    #[test]
    fn test_write_own_memory_mutates_target_bytes() {
        // Real WriteProcessMemory against our own writable heap buffer.
        // Mutation caught: writing to base_address without `+ offset` corrupts the wrong index.
        let payload: Vec<u8> = vec![0u8; 4];
        let base = payload.as_ptr() as usize;
        let mut src = ProcessDataSource::attach(std::process::id(), base, payload.len(), false)
            .expect("self-attach (writable) failed");
        src.write(1, &[0xAB, 0xCD])
            .expect("WriteProcessMemory failed");
        assert_eq!(payload, vec![0x00, 0xAB, 0xCD, 0x00]);
    }

    /// F-0047 regression: `read`/`write` forwarded straight into
    /// ReadProcessMemory/WriteProcessMemory without ever comparing the
    /// requested range against the declared `region_size`. The underlying
    /// heap allocation has 4 real bytes, but the source only declares a
    /// 2-byte window; without the bounds check the read spills into the
    /// extra 2 bytes just because the underlying memory happens to be valid.
    #[test]
    fn test_read_beyond_declared_region_size_is_clamped() {
        let payload: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let base = payload.as_ptr() as usize;
        let src =
            ProcessDataSource::attach(std::process::id(), base, 2, true).expect("attach failed");
        let result = src.read(0, 4).unwrap();
        assert_eq!(
            result,
            vec![0xDE, 0xAD],
            "read must clamp to the declared region_size, not spill into adjacent valid memory"
        );
        assert_eq!(payload.len(), 4, "keep payload alive until after the read");
    }

    #[test]
    fn test_read_offset_beyond_region_size_returns_out_of_bounds() {
        let src =
            ProcessDataSource::attach(std::process::id(), 0, 16, true).expect("attach failed");
        let err = src.read(32, 4).unwrap_err();
        assert!(
            matches!(
                err,
                DataSourceError::OutOfBounds {
                    offset: 32,
                    length: 16
                }
            ),
            "expected OutOfBounds{{offset:32, length:16}}, got {err:?}"
        );
    }

    #[test]
    fn test_write_beyond_declared_region_size_is_clamped() {
        let payload: Vec<u8> = vec![0u8; 4];
        let base = payload.as_ptr() as usize;
        let mut src = ProcessDataSource::attach(std::process::id(), base, 2, false)
            .expect("self-attach (writable) failed");
        src.write(0, &[0xAA, 0xBB, 0xCC, 0xDD])
            .expect("WriteProcessMemory failed");
        assert_eq!(
            payload,
            vec![0xAA, 0xBB, 0x00, 0x00],
            "write must clamp to the declared region_size, not spill into adjacent valid memory"
        );
    }

    #[test]
    fn test_write_offset_beyond_region_size_returns_out_of_bounds() {
        let mut src =
            ProcessDataSource::attach(std::process::id(), 0, 16, false).expect("attach failed");
        let err = src.write(32, &[0xFF]).unwrap_err();
        assert!(
            matches!(
                err,
                DataSourceError::OutOfBounds {
                    offset: 32,
                    length: 16
                }
            ),
            "expected OutOfBounds{{offset:32, length:16}}, got {err:?}"
        );
    }

    #[test]
    fn test_list_regions_returns_contiguous_walk() {
        // VirtualQueryEx enumeration: every pushed region begins exactly where the previous
        // one ends (address = base + size). A real process has many regions.
        // Mutation caught: a wrong address advance breaks contiguity or truncates the walk.
        let src = ProcessDataSource::attach(std::process::id(), 0, 0, true).expect("attach failed");
        let regions = src.list_regions().expect("list_regions failed");
        assert!(
            regions.len() > 5,
            "expected many regions in own process, got {}",
            regions.len()
        );
        for pair in regions.windows(2) {
            assert_eq!(
                pair[1].base_address,
                pair[0].base_address + pair[0].size,
                "regions must be contiguous"
            );
        }
    }
}
