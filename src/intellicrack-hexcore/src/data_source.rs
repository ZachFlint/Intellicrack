// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Zachary Flint
//
// This file is part of Intellicrack. See LICENSE for details.

use thiserror::Error;

/// Errors raised by a [`DataSource`].
#[derive(Error, Debug)]
pub enum DataSourceError {
    /// An underlying I/O or OS error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The offset lies past the end of the source.
    #[error("offset out of bounds: {offset} >= {length}")]
    OutOfBounds { offset: usize, length: usize },
    /// A process-memory call failed or transferred too few bytes.
    #[error("process error: {0}")]
    ProcessError(String),
    /// A write was attempted on a read-only source.
    #[error("read-only data source")]
    ReadOnly,
}

/// A byte-addressable backing store an editor can read from and write to.
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

    /// Returns the number of addressable bytes.
    fn length(&self) -> usize;
    /// Returns `true` when [`DataSource::write`] is permitted.
    fn is_writable(&self) -> bool;
    /// Returns a short name for the kind of source, e.g. `"buffer"`.
    fn source_type(&self) -> &'static str;
}

/// An in-memory [`DataSource`] over an owned byte vector.
pub struct BufferDataSource {
    data: Vec<u8>,
    writable: bool,
}

impl BufferDataSource {
    /// Wraps `data`, writable when `writable` is `true`.
    #[must_use]
    pub fn new(data: Vec<u8>, writable: bool) -> Self {
        Self { data, writable }
    }

    /// Wraps `data` as a read-only source.
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
        let end = offset.saturating_add(length).min(self.data.len());
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
        let end = offset.saturating_add(data.len()).min(self.data.len());
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

/// One region reported by `VirtualQueryEx`.
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// First address of the region.
    pub base_address: usize,
    /// Region size in bytes.
    pub size: usize,
    /// `PAGE_*` protection flags.
    pub protection: u32,
    /// `MEM_COMMIT` / `MEM_RESERVE` / `MEM_FREE` state.
    pub state: u32,
    /// `MEM_IMAGE` / `MEM_MAPPED` / `MEM_PRIVATE` type.
    pub region_type: u32,
}

/// A [`DataSource`] over a window of another process's memory.
#[cfg(windows)]
pub struct ProcessDataSource {
    handle: windows_sys::Win32::Foundation::HANDLE,
    /// Target process id.
    pub pid: u32,
    /// Address of offset 0 in the target.
    pub base_address: usize,
    /// Number of addressable bytes from `base_address`.
    pub region_size: usize,
    writable: bool,
}

// SAFETY: the only non-`Send` field is `handle`, a Win32 process `HANDLE`
// (an opaque kernel-object handle, not a thread-affine resource). Windows
// process handles may be used and closed from any thread, and this struct
// never hands out or aliases the raw handle — every use is behind `&self`/
// `&mut self` inside the guarded Win32 calls below, and `Drop` closes it
// exactly once. Sending the owner between threads is therefore sound.
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
        // SAFETY: `OpenProcess` is a pure Win32 call taking a copied access
        // mask, `BOOL` inherit flag, and `pid` by value; it borrows no Rust
        // memory. It returns a null handle on failure, which is checked
        // immediately below before the handle is stored or used.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            // Carry the OS error so access-denied (a live process the caller
            // may not open) is distinguishable from an invalid pid, as
            // `check_transfer` already does for the transfer calls.
            return Err(DataSourceError::ProcessError(format!(
                "OpenProcess failed for pid {pid}: {}",
                std::io::Error::last_os_error()
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
            // SAFETY: `MEMORY_BASIC_INFORMATION` is a plain C struct of
            // integer/pointer fields, so an all-zero bit pattern is a valid
            // initialized value; `VirtualQueryEx` overwrites it before it is
            // read.
            let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
            // SAFETY: `self.handle` is a live process handle opened with
            // `PROCESS_QUERY_INFORMATION`; `&raw mut mbi` points at the stack
            // slot just zero-initialized and the passed size is exactly that
            // struct's size, so the kernel writes only within it. The return
            // value (0 on failure/end-of-walk) is checked before `mbi` is read.
            let result = unsafe {
                VirtualQueryEx(
                    self.handle,
                    address as *const std::ffi::c_void,
                    &raw mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if result == 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error()
                    == i32::try_from(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER).ok()
                {
                    break;
                }
                return Err(DataSourceError::Io(err));
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

    /// Converts a region-relative `offset` to an address in the target.
    ///
    /// # Errors
    ///
    /// Returns `DataSourceError::ProcessError` if the address would wrap past
    /// the top of the address space.
    fn address_of(&self, offset: usize) -> Result<usize, DataSourceError> {
        self.base_address.checked_add(offset).ok_or_else(|| {
            DataSourceError::ProcessError(format!(
                "address 0x{:X} + 0x{offset:X} overflows the address space",
                self.base_address
            ))
        })
    }
}

/// Turns a Win32 memory-transfer result into a typed outcome.
///
/// `ReadProcessMemory`/`WriteProcessMemory` return `FALSE` on failure, but a
/// `TRUE` return with fewer bytes transferred than requested is still a
/// partial copy, so both conditions are reported instead of silently
/// truncating.
///
/// # Errors
///
/// Returns `DataSourceError::ProcessError` naming the call and the OS error
/// when `ok` is zero, or the short count when `transferred != requested`.
#[cfg(windows)]
fn check_transfer(
    call: &str,
    ok: windows_sys::core::BOOL,
    transferred: usize,
    requested: usize,
) -> Result<(), DataSourceError> {
    if ok == 0 {
        return Err(DataSourceError::ProcessError(format!(
            "{call} failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if transferred != requested {
        return Err(DataSourceError::ProcessError(format!(
            "{call} transferred {transferred} of {requested} bytes"
        )));
    }
    Ok(())
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
        let addr = self.address_of(offset)?;
        let mut buffer: Vec<u8> = Vec::new();
        buffer.try_reserve_exact(length).map_err(|e| {
            DataSourceError::ProcessError(format!("cannot allocate {length} bytes for read: {e}"))
        })?;
        buffer.resize(length, 0);
        let mut bytes_read: usize = 0;
        // SAFETY: `self.handle` is a live process handle opened with
        // `PROCESS_VM_READ`; `buffer` is a freshly allocated `Vec<u8>` of
        // exactly `length` bytes, so the kernel writes at most `length` bytes
        // into memory this call owns; `&raw mut bytes_read` points at a local.
        // A zero (`FALSE`) return is checked before `bytes_read` is trusted.
        let result = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const std::ffi::c_void,
                buffer.as_mut_ptr().cast::<std::ffi::c_void>(),
                length,
                &raw mut bytes_read,
            )
        };
        check_transfer("ReadProcessMemory", result, bytes_read, length)?;
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
        let addr = self.address_of(offset)?;
        let mut bytes_written: usize = 0;
        // SAFETY: `self.handle` is a live process handle opened with
        // `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`; `data` is a Rust slice and
        // `data.len()` bytes are read from it (read-only source); the kernel
        // reads at most that many bytes. `&raw mut bytes_written` points at a
        // local. A zero (`FALSE`) return is surfaced as an error below.
        let result = unsafe {
            WriteProcessMemory(
                self.handle,
                addr as *const std::ffi::c_void,
                data.as_ptr().cast::<std::ffi::c_void>(),
                data.len(),
                &raw mut bytes_written,
            )
        };
        check_transfer("WriteProcessMemory", result, bytes_written, data.len())
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
            // SAFETY: `self.handle` was returned by `OpenProcess`, is non-null
            // (checked), and is owned solely by this struct — it is never
            // aliased or closed elsewhere, so closing it exactly once here on
            // the single drop is sound.
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
        let src = BufferDataSource::new(vec![0x41u8, 0x42, 0x43, 0x44, 0x45], false);
        let result = src.read(1, 3).unwrap();
        assert_eq!(result, vec![0x42u8, 0x43, 0x44]);
    }

    #[test]
    fn test_read_from_offset_zero_returns_leading_bytes() {
        let src = BufferDataSource::new(vec![0x10u8, 0x20, 0x30], false);
        let result = src.read(0, 3).unwrap();
        assert_eq!(result, vec![0x10u8, 0x20, 0x30]);
    }

    #[test]
    fn test_read_length_beyond_end_clamps_to_buffer_boundary() {
        let src = BufferDataSource::new(vec![0xAAu8, 0xBB, 0xCC], false);
        let result = src.read(1, 10).unwrap();
        assert_eq!(result, vec![0xBBu8, 0xCC]);
    }

    #[test]
    fn test_read_offset_equal_to_len_returns_empty_vec() {
        // Boundary: offset == data.len(); guard `offset > len` is false, so Ok([]) is the contract.
        let src = BufferDataSource::new(vec![0x01u8, 0x02, 0x03], false);
        let result = src.read(3, 5).unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_read_offset_beyond_len_returns_exact_out_of_bounds_variant() {
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
        let mut src = BufferDataSource::new(vec![0x00u8; 5], true);
        src.write(2, &[0xDEu8, 0xAD]).unwrap();
        let readback = src.read(0, 5).unwrap();
        assert_eq!(readback, vec![0x00u8, 0x00, 0xDE, 0xAD, 0x00]);
    }

    #[test]
    fn test_write_partial_overlap_at_buffer_end_clamps_written_data() {
        let mut src = BufferDataSource::new(vec![0x00u8; 4], true);
        src.write(2, &[0x11u8, 0x22, 0x33, 0x44]).unwrap();
        let readback = src.read(0, 4).unwrap();
        assert_eq!(readback, vec![0x00u8, 0x00, 0x11, 0x22]);
    }

    #[test]
    fn test_write_offset_beyond_len_returns_exact_out_of_bounds_variant() {
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
        let mut src = BufferDataSource::new(vec![0x00u8; 3], true);
        src.write(0, &[0xCAu8, 0xFE, 0xBA]).unwrap();
        assert_eq!(src.read(0, 3).unwrap(), vec![0xCAu8, 0xFE, 0xBA]);
    }

    #[test]
    fn test_length_returns_exact_allocated_byte_count() {
        let src = BufferDataSource::new(vec![0u8; 7], false);
        assert_eq!(src.length(), 7usize);
    }

    #[test]
    fn test_is_writable_returns_true_when_constructed_writable() {
        let src = BufferDataSource::new(vec![0u8; 4], true);
        assert!(src.is_writable());
    }

    #[test]
    fn test_is_writable_returns_false_for_new_readonly_source() {
        let src = BufferDataSource::new_readonly(vec![0u8; 4]);
        assert!(!src.is_writable());
    }

    #[test]
    fn test_is_writable_returns_false_for_new_with_writable_false() {
        let src = BufferDataSource::new(vec![0u8; 2], false);
        assert!(!src.is_writable());
    }

    #[test]
    fn test_source_type_returns_buffer_discriminator_string() {
        let src = BufferDataSource::new(vec![], false);
        assert_eq!(src.source_type(), "buffer");
    }

    /// `BufferDataSource::read` must not compute `offset + length` unchecked:
    /// `read(1, usize::MAX)` would overflow (a debug panic, and a release
    /// `data[1..0]` slice panic) instead of clamping to the buffer.
    #[test]
    fn test_read_length_overflowing_usize_clamps_to_buffer_end() {
        let src = BufferDataSource::new(vec![0x41u8, 0x42, 0x43], false);
        assert_eq!(src.read(1, usize::MAX).unwrap(), vec![0x42u8, 0x43]);
    }

    #[test]
    fn test_write_length_overflow_guard_clamps_to_buffer_end() {
        let mut src = BufferDataSource::new(vec![0u8; 3], true);
        src.write(3, &[0xFF]).unwrap();
        src.write(2, &[0x11, 0x22]).unwrap();
        assert_eq!(src.read(0, 3).unwrap(), vec![0x00, 0x00, 0x11]);
    }

    #[test]
    fn test_datasource_error_io_from_std_io_error_preserves_message() {
        // Covers the `#[from] std::io::Error` conversion on DataSourceError::Io.
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
    use super::{check_transfer, DataSource, DataSourceError, MemoryRegion, ProcessDataSource};

    /// `read` must not allocate `vec![0u8; length]` for a caller-chosen
    /// length: `from_process_memory(pid, 0, huge)` would panic with "capacity
    /// overflow" or abort the whole Python process when the allocation could
    /// not be committed, instead of returning an error.
    #[test]
    fn test_read_unallocatable_length_returns_error_not_panic() {
        let src = ProcessDataSource::attach(std::process::id(), 0, usize::MAX, true)
            .expect("self-attach failed");
        let err = src.read(0, usize::MAX).unwrap_err();
        let prefix = format!("cannot allocate {} bytes for read: ", usize::MAX);
        assert!(
            matches!(&err, DataSourceError::ProcessError(m) if m.starts_with(&prefix)),
            "expected allocation ProcessError, got {err:?}"
        );
    }

    /// A `TRUE` return with a short byte count must not be accepted (reads
    /// would be silently truncated, writes would report success after copying
    /// only a prefix), so a partial transfer cannot look complete.
    #[test]
    fn test_check_transfer_rejects_short_and_failed_transfers() {
        let short = check_transfer("ReadProcessMemory", 1, 3, 4).unwrap_err();
        assert_eq!(
            short.to_string(),
            "process error: ReadProcessMemory transferred 3 of 4 bytes"
        );
        assert!(matches!(
            check_transfer("WriteProcessMemory", 0, 0, 4),
            Err(DataSourceError::ProcessError(m)) if m.starts_with("WriteProcessMemory failed: ")
        ));
        assert!(check_transfer("ReadProcessMemory", 1, 4, 4).is_ok());
    }

    /// `base_address + offset` must be checked: a region declared near the top
    /// of the address space would otherwise overflow (a debug panic) instead of
    /// reporting a typed error.
    #[test]
    fn test_read_address_overflow_is_typed_error() {
        let src = ProcessDataSource::attach(std::process::id(), usize::MAX, 16, true)
            .expect("self-attach failed");
        let err = src.read(1, 1).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "process error: address 0x{:X} + 0x1 overflows the address space",
                usize::MAX
            )
        );
    }

    #[test]
    fn test_memory_region_debug_and_clone_roundtrip() {
        // Exercises the derived Debug + Clone on MemoryRegion.
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
        let src = ProcessDataSource::attach(std::process::id(), 0, 4096, true)
            .expect("self-attach failed");
        assert!(!src.is_writable());
        assert_eq!(src.length(), 4096);
        assert_eq!(src.source_type(), "process");
    }

    #[test]
    fn test_attach_writable_sets_writable_true() {
        // read_only=false takes the VM_WRITE|VM_OPERATION access branch and sets writable:true.
        let src = ProcessDataSource::attach(std::process::id(), 0, 8, false)
            .expect("self-attach (writable) failed");
        assert!(src.is_writable());
        assert_eq!(src.source_type(), "process");
    }

    #[test]
    fn test_attach_invalid_pid_returns_process_error() {
        // u32::MAX is odd; Windows kernel PIDs are multiples of 4, so it never names a live
        // process and OpenProcess returns NULL.
        let Err(err) = ProcessDataSource::attach(u32::MAX, 0, 16, true) else {
            panic!("expected attach to an invalid pid to fail");
        };
        let DataSourceError::ProcessError(message) = err else {
            panic!("expected ProcessError, got {err:?}");
        };
        assert!(
            message.starts_with("OpenProcess failed for pid 4294967295: "),
            "the failure must name the pid and carry the OS error, got {message:?}"
        );
    }

    #[test]
    fn test_read_own_memory_returns_exact_bytes() {
        // Real ReadProcessMemory against our own committed heap: read back a known payload.
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
        let src =
            ProcessDataSource::attach(std::process::id(), 0, 16, true).expect("attach failed");
        assert_eq!(src.read(0, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_write_readonly_source_returns_read_only() {
        // Writable guard fires before any WriteProcessMemory call.
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
        let mut src =
            ProcessDataSource::attach(std::process::id(), 0, 16, false).expect("attach failed");
        assert!(src.write(0, &[]).is_ok());
    }

    #[test]
    fn test_write_own_memory_mutates_target_bytes() {
        // Real WriteProcessMemory against our own writable heap buffer.
        let payload: Vec<u8> = vec![0u8; 4];
        let base = payload.as_ptr() as usize;
        let mut src = ProcessDataSource::attach(std::process::id(), base, payload.len(), false)
            .expect("self-attach (writable) failed");
        src.write(1, &[0xAB, 0xCD])
            .expect("WriteProcessMemory failed");
        assert_eq!(payload, vec![0x00, 0xAB, 0xCD, 0x00]);
    }

    /// `read`/`write` must compare the requested range against the declared
    /// `region_size` before calling ReadProcessMemory/WriteProcessMemory. The
    /// underlying heap allocation has 4 real bytes, but the source only
    /// declares a 2-byte window; without the bounds check the read spills into
    /// the extra 2 bytes just because the underlying memory happens to be
    /// valid.
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
