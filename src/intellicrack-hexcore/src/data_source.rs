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
    fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, DataSourceError>;
    fn write(&mut self, offset: usize, data: &[u8]) -> Result<(), DataSourceError>;
    fn length(&self) -> usize;
    fn is_writable(&self) -> bool;
    fn source_type(&self) -> &str;
}

pub struct BufferDataSource {
    data: Vec<u8>,
    writable: bool,
}

impl BufferDataSource {
    pub fn new(data: Vec<u8>, writable: bool) -> Self {
        Self { data, writable }
    }

    pub fn new_readonly(data: Vec<u8>) -> Self {
        Self { data, writable: false }
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

    fn source_type(&self) -> &str {
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
                "OpenProcess failed for pid {}",
                pid
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
                    &mut mbi,
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
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                length,
                &mut bytes_read,
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
        if !self.writable {
            return Err(DataSourceError::ReadOnly);
        }
        use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        if data.is_empty() {
            return Ok(());
        }
        let addr = self.base_address + offset;
        let mut bytes_written: usize = 0;
        let result = unsafe {
            WriteProcessMemory(
                self.handle,
                addr as *const std::ffi::c_void,
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                &mut bytes_written,
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

    fn source_type(&self) -> &str {
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
