#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::fs::File;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::os::raw::c_void;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::{io, ptr};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::FlushFileBuffers,
    System::{
        Memory::{
            CreateFileMappingW, FlushViewOfFile, MapViewOfFile, UnmapViewOfFile, VirtualProtect,
            FILE_MAP, FILE_MAP_ALL_ACCESS, FILE_MAP_COPY, FILE_MAP_EXECUTE, FILE_MAP_READ,
            FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
            PAGE_WRITECOPY,
        },
        SystemInformation::GetSystemInfo,
        Threading::GetCurrentProcess,
    },
};

/// Returns a fixed aligned pointer that is valid for `slice::from_raw_parts::<u8>` with `len == 0`.
///
/// This aligns the pointer to `allocation_granularity()` or 1 if unknown.
fn empty_slice_ptr() -> *mut c_void {
    let align = allocation_granularity().max(1);
    align as *mut _
}

pub struct MmapInner {
    handle: Option<HANDLE>,
    ptr: *mut c_void,
    len: usize,
    copy: bool,
}

impl MmapInner {
    /// Creates a new `MmapInner`.
    ///
    /// This is a thin wrapper around the `CreateFileMappingW` and `MapViewOfFile` system calls.
    pub fn new(
        handle: RawHandle,
        protect: PAGE_PROTECTION_FLAGS,
        access: FILE_MAP,
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
                handle: None,
                ptr: empty_slice_ptr(),
                len: 0,
                copy,
            });
        }

        unsafe {
            let mapping = CreateFileMappingW(
                handle as HANDLE,
                ptr::null_mut(),
                protect,
                0,
                0,
                ptr::null(),
            );
            if mapping == 0 {
                return Err(io::Error::last_os_error());
            }

            let ptr = MapViewOfFile(
                mapping,
                access,
                (aligned_offset >> 16 >> 16) as u32,
                (aligned_offset & 0xffffffff) as u32,
                aligned_len,
            );
            CloseHandle(mapping);
            if ptr.Value.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut new_handle = MaybeUninit::zeroed();
            let cur_proc = GetCurrentProcess();
            let ok = DuplicateHandle(
                cur_proc,
                handle as HANDLE,
                cur_proc,
                new_handle.as_mut_ptr(),
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            );
            if ok == 0 {
                UnmapViewOfFile(ptr);
                return Err(io::Error::last_os_error());
            }

            Ok(MmapInner {
                handle: Some(new_handle.assume_init()),
                ptr: ptr.Value.offset(alignment as isize),
                len,
                copy,
            })
        }
    }

    pub fn map(
        len: usize,
        handle: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let write = protection_supported(handle, PAGE_READWRITE);
        let exec = protection_supported(handle, PAGE_EXECUTE_READ);
        let mut access = FILE_MAP_READ;
        let protection = match (write, exec) {
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
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, false)?;
        if write || exec {
            inner.make_read_only()?;
        }
        Ok(inner)
    }

    pub fn map_exec(
        len: usize,
        handle: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let write = protection_supported(handle, PAGE_READWRITE);
        let mut access = FILE_MAP_READ | FILE_MAP_EXECUTE;
        let protection = if write {
            access |= FILE_MAP_WRITE;
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_EXECUTE_READ
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, false)?;
        if write {
            inner.make_exec()?;
        }
        Ok(inner)
    }

    pub fn map_mut(
        len: usize,
        handle: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let exec = protection_supported(handle, PAGE_EXECUTE_READ);
        let mut access = FILE_MAP_READ | FILE_MAP_WRITE;
        let protection = if exec {
            access |= FILE_MAP_EXECUTE;
            PAGE_EXECUTE_READWRITE
        } else {
            PAGE_READWRITE
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, false)?;
        if exec {
            inner.make_mut()?;
        }
        Ok(inner)
    }

    pub fn map_copy(
        len: usize,
        handle: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let exec = protection_supported(handle, PAGE_EXECUTE_READWRITE);
        let mut access = FILE_MAP_COPY;
        let protection = if exec {
            access |= FILE_MAP_EXECUTE;
            PAGE_EXECUTE_WRITECOPY
        } else {
            PAGE_WRITECOPY
        };

        let mut inner = MmapInner::new(handle, protection, access, offset, len, true)?;
        if exec {
            inner.make_mut()?;
        }
        Ok(inner)
    }

    pub fn map_copy_read_only(
        len: usize,
        handle: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        let write = protection_supported(handle, PAGE_READWRITE);
        let exec = protection_supported(handle, PAGE_EXECUTE_READ);
        let mut access = FILE_MAP_COPY;
        let protection = if exec {
            access |= FILE_MAP_EXECUTE;
            PAGE_EXECUTE_WRITECOPY
        } else {
            PAGE_WRITECOPY
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
                (mapped_len >> 16 >> 16) as u32,
                (mapped_len & 0xffffffff) as u32,
                ptr::null(),
            );
            if mapping == 0 {
                return Err(io::Error::last_os_error());
            }
            let access = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
            let ptr = MapViewOfFile(mapping, access, 0, 0, mapped_len);
            CloseHandle(mapping);

            if ptr.Value.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut old = MaybeUninit::uninit();
            let result = VirtualProtect(ptr.Value, mapped_len, PAGE_READWRITE, old.as_mut_ptr());
            if result != 0 {
                Ok(MmapInner {
                    handle: None,
                    ptr: ptr.Value,
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

        if let Some(handle) = self.handle {
            let ok = unsafe { FlushFileBuffers(handle) };
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
        let result = unsafe { FlushViewOfFile(self.ptr.add(offset), len) };
        if result != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn virtual_protect(&mut self, protect: PAGE_PROTECTION_FLAGS) -> io::Result<()> {
        if self.ptr == empty_slice_ptr() {
            return Ok(());
        }
        unsafe {
            let alignment = self.ptr as usize % allocation_granularity();
            let ptr = self.ptr.offset(-(alignment as isize));
            let aligned_len = self.len + alignment;

            let mut old = MaybeUninit::uninit();
            let result = VirtualProtect(ptr, aligned_len, protect, old.as_mut_ptr());

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
        self.ptr as *mut u8
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
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: ptr });

            if let Some(handle) = self.handle {
                CloseHandle(handle);
            }
        }
    }
}

unsafe impl Sync for MmapInner {}
unsafe impl Send for MmapInner {}

fn protection_supported(handle: RawHandle, protection: PAGE_PROTECTION_FLAGS) -> bool {
    unsafe {
        let mapping = CreateFileMappingW(
            handle as HANDLE,
            ptr::null_mut(),
            protection,
            0,
            0,
            ptr::null(),
        ) as RawHandle;
        if mapping.is_null() {
            return false;
        }
        CloseHandle(mapping as HANDLE);
        true
    }
}

fn allocation_granularity() -> usize {
    unsafe {
        let mut info = MaybeUninit::zeroed();
        GetSystemInfo(info.as_mut_ptr());
        info.assume_init().dwAllocationGranularity as usize
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
