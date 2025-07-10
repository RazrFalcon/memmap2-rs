#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::raw::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::{io, mem, ptr};

use crate::Win32Handle;

type BOOL = i32;
type WORD = u16;
type DWORD = u32;
type WCHAR = u16;
type HANDLE = *mut c_void;
type LPHANDLE = *mut HANDLE;
type LPVOID = *mut c_void;
type LPCVOID = *const c_void;
type ULONG_PTR = usize;
type SIZE_T = ULONG_PTR;
type LPCWSTR = *const WCHAR;
type PDWORD = *mut DWORD;
type DWORD_PTR = ULONG_PTR;
type LPSECURITY_ATTRIBUTES = *mut SECURITY_ATTRIBUTES;
type LPSYSTEM_INFO = *mut SYSTEM_INFO;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

const DUPLICATE_SAME_ACCESS: DWORD = 0x00000002;

const STANDARD_RIGHTS_REQUIRED: DWORD = 0x000F0000;

const SECTION_QUERY: DWORD = 0x0001;
const SECTION_MAP_WRITE: DWORD = 0x0002;
const SECTION_MAP_READ: DWORD = 0x0004;
const SECTION_MAP_EXECUTE: DWORD = 0x0008;
const SECTION_EXTEND_SIZE: DWORD = 0x0010;
const SECTION_MAP_EXECUTE_EXPLICIT: DWORD = 0x0020;
const SECTION_ALL_ACCESS: DWORD = STANDARD_RIGHTS_REQUIRED
    | SECTION_QUERY
    | SECTION_MAP_WRITE
    | SECTION_MAP_READ
    | SECTION_MAP_EXECUTE
    | SECTION_EXTEND_SIZE;

const PAGE_READONLY: DWORD = 0x02;
const PAGE_READWRITE: DWORD = 0x04;
const PAGE_WRITECOPY: DWORD = 0x08;
const PAGE_EXECUTE_READ: DWORD = 0x20;
const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;

const FILE_MAP_WRITE: DWORD = SECTION_MAP_WRITE;
const FILE_MAP_READ: DWORD = SECTION_MAP_READ;
const FILE_MAP_ALL_ACCESS: DWORD = SECTION_ALL_ACCESS;
const FILE_MAP_EXECUTE: DWORD = SECTION_MAP_EXECUTE_EXPLICIT;
const FILE_MAP_COPY: DWORD = 0x00000001;

#[repr(C)]
struct SECURITY_ATTRIBUTES {
    nLength: DWORD,
    lpSecurityDescriptor: LPVOID,
    bInheritHandle: BOOL,
}

#[repr(C)]
struct SYSTEM_INFO {
    wProcessorArchitecture: WORD,
    wReserved: WORD,
    dwPageSize: DWORD,
    lpMinimumApplicationAddress: LPVOID,
    lpMaximumApplicationAddress: LPVOID,
    dwActiveProcessorMask: DWORD_PTR,
    dwNumberOfProcessors: DWORD,
    dwProcessorType: DWORD,
    dwAllocationGranularity: DWORD,
    wProcessorLevel: WORD,
    wProcessorRevision: WORD,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}

extern "system" {
    fn GetCurrentProcess() -> HANDLE;

    fn CloseHandle(hObject: HANDLE) -> BOOL;

    fn DuplicateHandle(
        hSourceProcessHandle: HANDLE,
        hSourceHandle: HANDLE,
        hTargetProcessHandle: HANDLE,
        lpTargetHandle: LPHANDLE,
        dwDesiredAccess: DWORD,
        bInheritHandle: BOOL,
        dwOptions: DWORD,
    ) -> BOOL;

    fn CreateFileMappingW(
        hFile: HANDLE,
        lpFileMappingAttributes: LPSECURITY_ATTRIBUTES,
        flProtect: DWORD,
        dwMaximumSizeHigh: DWORD,
        dwMaximumSizeLow: DWORD,
        lpName: LPCWSTR,
    ) -> HANDLE;

    fn FlushFileBuffers(hFile: HANDLE) -> BOOL;

    fn FlushViewOfFile(lpBaseAddress: LPCVOID, dwNumberOfBytesToFlush: SIZE_T) -> BOOL;

    fn UnmapViewOfFile(lpBaseAddress: LPCVOID) -> BOOL;

    fn MapViewOfFile(
        hFileMappingObject: HANDLE,
        dwDesiredAccess: DWORD,
        dwFileOffsetHigh: DWORD,
        dwFileOffsetLow: DWORD,
        dwNumberOfBytesToMap: SIZE_T,
    ) -> LPVOID;

    fn VirtualProtect(
        lpAddress: LPVOID,
        dwSize: SIZE_T,
        flNewProtect: DWORD,
        lpflOldProtect: PDWORD,
    ) -> BOOL;

    fn GetSystemInfo(lpSystemInfo: LPSYSTEM_INFO);
}

/// Returns a fixed aligned pointer that is valid for `slice::from_raw_parts::<u8>` with `len == 0`.
///
/// This aligns the pointer to `allocation_granularity()` or 1 if unknown.
fn empty_slice_ptr() -> *mut c_void {
    allocation_granularity().max(1) as *mut c_void
}

pub struct MmapInner {
    file_handle: Option<OwnedHandle>,
    ptr: *mut c_void,
    len: usize,
    copy: bool,
}

impl MmapInner {
    /// Creates a new `MmapInner`.
    ///
    /// This is a thin wrapper around the `CreateFileMappingW` and `MapViewOfFile` system calls.
    pub fn new(
        handle: Win32Handle,
        protect: DWORD,
        access: DWORD,
        offset: u64,
        len: usize,
        copy: bool,
    ) -> io::Result<MmapInner> {
        let alignment = offset % allocation_granularity() as u64;
        let aligned_offset = offset - alignment as u64;
        let aligned_len = len + alignment as usize;
        if aligned_len == 0 {
            // `CreateFileMappingW` documents:
            //
            // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw
            // > An attempt to map a file with a length of 0 (zero) fails with an error code
            // > of ERROR_FILE_INVALID. Applications should test for files with a length of 0
            // > (zero) and reject those files.
            //
            // For such files, don’t create a mapping at all and use a marker pointer instead.
            return Ok(MmapInner {
                file_handle: None,
                ptr: empty_slice_ptr(),
                len: 0,
                copy,
            });
        }

        unsafe {
            let mapping = match handle {
                Win32Handle::File(handle) => {
                    CreateFileMappingW(handle, ptr::null_mut(), protect, 0, 0, ptr::null())
                }
                Win32Handle::FileMapping(handle) => handle,
            };

            if mapping.is_null() {
                return Err(io::Error::last_os_error());
            }

            let ptr = MapViewOfFile(
                mapping,
                access,
                (aligned_offset >> 16 >> 16) as DWORD,
                (aligned_offset & 0xffffffff) as DWORD,
                aligned_len as SIZE_T,
            );
            CloseHandle(mapping);
            if ptr.is_null() {
                return Err(io::Error::last_os_error());
            }

            let file_handle = if let Win32Handle::File(handle) = handle {
                let mut new_handle = 0 as RawHandle;
                let cur_proc = GetCurrentProcess();
                let ok = DuplicateHandle(
                    cur_proc,
                    handle,
                    cur_proc,
                    &mut new_handle,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                );
                if ok == 0 {
                    UnmapViewOfFile(ptr);
                    return Err(io::Error::last_os_error());
                }
                Some(OwnedHandle::from_raw_handle(new_handle))
            } else {
                None
            };

            Ok(MmapInner {
                file_handle,
                ptr: ptr.offset(alignment as isize),
                len,
                copy,
            })
        }
    }

    pub fn map(
        len: usize,
        handle: Win32Handle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let mut access = FILE_MAP_READ;
        let mut write = true;
        let mut exec = true;

        let protection = match handle {
            Win32Handle::File(handle) => {
                write = protection_supported(handle, PAGE_READWRITE);
                exec = protection_supported(handle, PAGE_EXECUTE_READ);

                match (write, exec) {
                    (true, true) => {
                        access |= FILE_MAP_WRITE | FILE_MAP_EXECUTE;
                        PAGE_EXECUTE_READWRITE
                    }
                    (true, false) => {
                        access |= FILE_MAP_WRITE;
                        PAGE_READWRITE
                    }
                    (false, true) => {
                        access |= FILE_MAP_EXECUTE;
                        PAGE_EXECUTE_READ
                    }
                    (false, false) => PAGE_READONLY,
                }
            }
            Win32Handle::FileMapping(_) => 0,
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, false)?;
        if write || exec {
            inner.make_read_only()?;
        }
        Ok(inner)
    }

    pub fn map_exec(
        len: usize,
        handle: Win32Handle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let mut access = FILE_MAP_READ | FILE_MAP_EXECUTE;
        let mut write = true;

        let protection = match handle {
            Win32Handle::File(handle) => {
                write = protection_supported(handle, PAGE_READWRITE);
                if write {
                    access |= FILE_MAP_WRITE;
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_EXECUTE_READ
                }
            }
            Win32Handle::FileMapping(_) => 0,
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, false)?;
        if write {
            inner.make_exec()?;
        }
        Ok(inner)
    }

    pub fn map_mut(
        len: usize,
        handle: Win32Handle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let mut access = FILE_MAP_READ | FILE_MAP_WRITE;
        let mut exec = true;

        let protection = match handle {
            Win32Handle::File(handle) => {
                exec = protection_supported(handle, PAGE_EXECUTE_READ);
                if exec {
                    access |= FILE_MAP_EXECUTE;
                    PAGE_EXECUTE_READWRITE
                } else {
                    PAGE_READWRITE
                }
            }
            Win32Handle::FileMapping(_) => 0,
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, false)?;
        if exec {
            inner.make_mut()?;
        }
        Ok(inner)
    }

    pub fn map_copy(
        len: usize,
        handle: Win32Handle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let mut access = FILE_MAP_COPY;
        let mut exec = true;

        let protection = match handle {
            Win32Handle::File(handle) => {
                exec = protection_supported(handle, PAGE_EXECUTE_READWRITE);
                if exec {
                    access |= FILE_MAP_EXECUTE;
                    PAGE_EXECUTE_WRITECOPY
                } else {
                    PAGE_WRITECOPY
                }
            }
            Win32Handle::FileMapping(_) => 0,
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, true)?;
        if exec {
            inner.make_mut()?;
        }
        Ok(inner)
    }

    pub fn map_copy_read_only(
        len: usize,
        handle: Win32Handle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let mut access = FILE_MAP_COPY;
        let mut write = true;
        let mut exec = true;

        let protection = match handle {
            Win32Handle::File(handle) => {
                exec = protection_supported(handle, PAGE_EXECUTE_READ);
                write = protection_supported(handle, PAGE_READWRITE);
                if exec {
                    access |= FILE_MAP_EXECUTE;
                    PAGE_EXECUTE_WRITECOPY
                } else {
                    PAGE_WRITECOPY
                }
            }
            Win32Handle::FileMapping(_) => 0,
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, true)?;
        if write || exec {
            inner.make_read_only()?;
        }
        Ok(inner)
    }

    pub fn map_anon(
        len: usize,
        _stack: bool,
        _populate: bool,
        _huge: Option<u8>,
    ) -> io::Result<MmapInner> {
        // Ensure a non-zero length for the underlying mapping
        let mapped_len = len.max(1);
        unsafe {
            // Create a mapping and view with maximum access permissions, then use `VirtualProtect`
            // to set the actual `Protection`. This way, we can set more permissive protection later
            // on.
            // Also see https://msdn.microsoft.com/en-us/library/windows/desktop/aa366537.aspx

            let mapping = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                ptr::null_mut(),
                PAGE_EXECUTE_READWRITE,
                (mapped_len >> 16 >> 16) as DWORD,
                (mapped_len & 0xffffffff) as DWORD,
                ptr::null(),
            );
            if mapping.is_null() {
                return Err(io::Error::last_os_error());
            }
            let access = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
            let ptr = MapViewOfFile(mapping, access, 0, 0, mapped_len as SIZE_T);
            CloseHandle(mapping);

            if ptr.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut old = 0;
            let result = VirtualProtect(ptr, mapped_len as SIZE_T, PAGE_READWRITE, &mut old);
            if result != 0 {
                Ok(MmapInner {
                    file_handle: None,
                    ptr,
                    len,
                    copy: false,
                })
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn flush(&self, offset: usize, len: usize) -> io::Result<()> {
        self.flush_async(offset, len)?;

        if let Some(ref handle) = self.file_handle {
            let ok = unsafe { FlushFileBuffers(handle.as_raw_handle()) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    pub fn flush_async(&self, offset: usize, len: usize) -> io::Result<()> {
        if self.ptr == empty_slice_ptr() {
            return Ok(());
        }
        let result = unsafe { FlushViewOfFile(self.ptr.add(offset), len as SIZE_T) };
        if result != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn virtual_protect(&mut self, protect: DWORD) -> io::Result<()> {
        if self.ptr == empty_slice_ptr() {
            return Ok(());
        }
        unsafe {
            let alignment = self.ptr as usize % allocation_granularity();
            let ptr = self.ptr.offset(-(alignment as isize));
            let aligned_len = self.len as SIZE_T + alignment as SIZE_T;

            let mut old = 0;
            let result = VirtualProtect(ptr, aligned_len, protect, &mut old);

            if result != 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn make_read_only(&mut self) -> io::Result<()> {
        self.virtual_protect(PAGE_READONLY)
    }

    pub fn make_exec(&mut self) -> io::Result<()> {
        if self.copy {
            self.virtual_protect(PAGE_EXECUTE_WRITECOPY)
        } else {
            self.virtual_protect(PAGE_EXECUTE_READ)
        }
    }

    pub fn make_mut(&mut self) -> io::Result<()> {
        if self.copy {
            self.virtual_protect(PAGE_WRITECOPY)
        } else {
            self.virtual_protect(PAGE_READWRITE)
        }
    }

    #[inline]
    pub fn ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    #[inline]
    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.ptr.cast()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
}

impl Drop for MmapInner {
    fn drop(&mut self) {
        if self.ptr == empty_slice_ptr() {
            return;
        }
        let alignment = self.ptr as usize % allocation_granularity();
        // Any errors during unmapping/closing are ignored as the only way
        // to report them would be through panicking which is highly discouraged
        // in Drop impls, c.f. https://github.com/rust-lang/lang-team/issues/97
        unsafe {
            let ptr = self.ptr.offset(-(alignment as isize));
            UnmapViewOfFile(ptr);
        }
    }
}

unsafe impl Sync for MmapInner {}
unsafe impl Send for MmapInner {}

fn protection_supported(handle: RawHandle, protection: DWORD) -> bool {
    unsafe {
        let mapping = CreateFileMappingW(handle, ptr::null_mut(), protection, 0, 0, ptr::null());
        if mapping.is_null() {
            return false;
        }
        CloseHandle(mapping);
        true
    }
}

fn allocation_granularity() -> usize {
    unsafe {
        let mut info = mem::zeroed();
        GetSystemInfo(&mut info);
        info.dwAllocationGranularity as usize
    }
}

pub fn file_len(handle: RawHandle) -> io::Result<u64> {
    // SAFETY: We must not close the passed-in fd by dropping the File we create,
    // we ensure this by immediately wrapping it in a ManuallyDrop.
    unsafe {
        let file = ManuallyDrop::new(File::from_raw_handle(handle));
        Ok(file.metadata()?.len())
    }
}

#[cfg(test)]
mod test {
    use super::{CloseHandle, CreateFileMappingW, PAGE_READWRITE};
    use crate::{MmapOptions, MmapRawDescriptor};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;

    #[test]
    #[cfg(target_os = "windows")]
    fn map_file_mapping() {
        let len = 128;
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();

        file.set_len(len as u64).unwrap();
        let mapping = unsafe {
            CreateFileMappingW(
                file.as_raw_handle(),
                ptr::null_mut(),
                PAGE_READWRITE,
                0,
                0,
                ptr::null(),
            )
        };
        assert!(!mapping.is_null());

        let handle = MmapRawDescriptor::from_file_mapping(mapping);
        let mut mmap = unsafe { MmapOptions::new().len(len).map_mut(handle).unwrap() };
        let mmap_len = mmap.len();
        assert_eq!(len, mmap_len);

        let zeros = vec![0; len];
        let incr: Vec<u8> = (0..len as u8).collect();

        // check that the mmap is empty
        assert_eq!(&zeros[..], &mmap[..]);

        // write values into the mmap
        (&mut mmap[..]).write_all(&incr[..]).unwrap();

        // read values back
        assert_eq!(&incr[..], &mmap[..]);
        unsafe { CloseHandle(mapping) };
    }
}
