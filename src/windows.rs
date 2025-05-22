#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::fs::File;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_void;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::{io, mem, ptr};

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
type LPLUID = *mut LUID;
type LPCTOKEN_PRIVILEGES = *const TOKEN_PRIVILEGES;
type LPTOKEN_PRIVILEGES = *mut TOKEN_PRIVILEGES;

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

const SEC_COMMIT: DWORD = 0x800_0000;
const SEC_LARGE_PAGES: DWORD = 0x8000_0000;

const FILE_MAP_WRITE: DWORD = SECTION_MAP_WRITE;
const FILE_MAP_READ: DWORD = SECTION_MAP_READ;
const FILE_MAP_ALL_ACCESS: DWORD = SECTION_ALL_ACCESS;
const FILE_MAP_EXECUTE: DWORD = SECTION_MAP_EXECUTE_EXPLICIT;
const FILE_MAP_COPY: DWORD = 0x00000001;
const FILE_MAP_LARGE_PAGES: DWORD = 0x2000_0000;

const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
const TOKEN_QUERY: DWORD = 0x0008;

// TOKEN_PRIVILEGE attributes flags https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges

const SE_PRIVILEGE_ATTR_ENABLED: DWORD = 0x0000_0002;
// const SE_PRIVILEGE_ATTR_ENABLED_BY_DEFAULT: DWORD = 0x0000_0001;
// const SE_PRIVILEGE_ATTR_REMOVED: DWORD = 0x0000_0004;
// const SE_PRIVILEGE_ATTR_USED_FOR_ACCESS: DWORD = 0x8000_0000;

// alternatively could be defined via utf16string crate
const SE_PRIVILEGE_LOCK_MEMORY: *const u16 =
    b"S\0e\0L\0o\0c\0k\0M\0e\0m\0o\0r\0y\0P\0r\0i\0v\0i\0l\0e\0g\0e\0\0\0" as *const _
        as *const u16;

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

#[repr(C)]
#[derive(Copy, Clone)]
struct LUID {
    pub LowPart: DWORD,
    pub HighPart: DWORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct LUID_AND_ATTRIBUTES {
    pub Luid: LUID,
    pub Attributes: DWORD,
}

#[repr(C)]
struct TOKEN_PRIVILEGES {
    PrivilegeCount: DWORD,
    Privileges: [LUID_AND_ATTRIBUTES; 1],
    // note: this should be variable length, but given this is used only
    // localy and only with single LUID_AND_ATTRIBUTES pair,
    // leaving it as it is
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

    fn OpenProcessToken(processHandle: HANDLE, desiredAccess: DWORD, tokenHandle: LPHANDLE)
        -> BOOL;

    fn LookupPrivilegeValueW(lpSystemName: LPCWSTR, lpName: LPCWSTR, lpLuid: LPLUID) -> BOOL;

    fn AdjustTokenPrivileges(
        tokenHandle: HANDLE,
        disableAllPrivileges: BOOL,
        newState: LPCTOKEN_PRIVILEGES,
        bufferLength: DWORD,
        previousState: LPTOKEN_PRIVILEGES,
        returnLength: PDWORD,
    ) -> BOOL;

    fn GetLargePageMinimum() -> SIZE_T;
}

/// Returns a fixed aligned pointer that is valid for `slice::from_raw_parts::<u8>` with `len == 0`.
///
/// This aligns the pointer to `allocation_granularity()` or 1 if unknown.
fn empty_slice_ptr() -> *mut c_void {
    allocation_granularity().max(1) as *mut c_void
}

pub struct MmapInner {
    handle: Option<RawHandle>,
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
                handle: None,
                ptr: empty_slice_ptr(),
                len: 0,
                copy,
            });
        }

        unsafe {
            let mapping = CreateFileMappingW(handle, ptr::null_mut(), protect, 0, 0, ptr::null());
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

            Ok(MmapInner {
                handle: Some(new_handle),
                ptr: ptr.offset(alignment as isize),
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
        huge: Option<u8>,
    ) -> io::Result<MmapInner> {
        // Ensure a non-zero length for the underlying mapping
        let mapped_len = len.max(1);
        unsafe {
            let large_page_size = get_large_page_minimum();
            let large_page_protection_flags = PAGE_EXECUTE_READWRITE | SEC_COMMIT | SEC_LARGE_PAGES;
            let use_large_page = if huge.is_some()
                && large_page_size > 1
                && enable_se_lock_memory_privilege().is_ok()
            {
                protection_supported_with_size(
                    INVALID_HANDLE_VALUE,
                    large_page_protection_flags,
                    large_page_size as u64,
                )
            } else {
                false
            };

            let flProtect = if use_large_page {
                large_page_protection_flags
            } else {
                PAGE_EXECUTE_READWRITE
            };

            let mapped_len = if use_large_page {
                // align up to large_page_size multiple
                mapped_len.saturating_add(large_page_size - 1) / large_page_size * large_page_size
            } else {
                mapped_len
            };

            let large_page_access_flag = if use_large_page {
                FILE_MAP_LARGE_PAGES
            } else {
                0
            };

            // Create a mapping and view with maximum access permissions, then use `VirtualProtect`
            // to set the actual `Protection`. This way, we can set more permissive protection later
            // on.
            // Also see https://msdn.microsoft.com/en-us/library/windows/desktop/aa366537.aspx

            let mapping = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                ptr::null_mut(),
                flProtect,
                (mapped_len >> 16 >> 16) as DWORD,
                (mapped_len & 0xffffffff) as DWORD,
                ptr::null(),
            );
            if mapping.is_null() {
                return Err(io::Error::last_os_error());
            }

            // TODO: in case of huge page should se_lock_memory_privilege be disabled/removed after creating file mapping?
            // (there's likely no need, but would be nicer / more elegant)

            let access = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE | large_page_access_flag;
            let ptr = MapViewOfFile(mapping, access, 0, 0, mapped_len as SIZE_T);
            CloseHandle(mapping);

            if ptr.is_null() {
                return Err(io::Error::last_os_error());
            }

            let mut old = 0;
            let protectFlag = if use_large_page {
                // it seems that when large page is used, protection passed to VirtualProtect has to match
                // access passed to MapViewOfFile *exactly*, without narrowing:
                // FILE_MAP_READ                          | PAGE_READONLY
                // FILE_MAP_READ + FILE_MAP_WRITE         | PAGE_READWRITE
                // FILE_MAP_ALL_ACCESS                    | PAGE_READWRITE
                // FILE_MAP_ALL_ACCESS + FILE_MAP_EXECUTE | PAGE_EXECUTE_READWRITE
                // FILE_MAP_READ + FILE_MAP_EXECUTE       | PAGE_EXECUTE_READ
                //
                // TODO: so in this case maybe it'd be better to just skip VirtualProtect completely?
                PAGE_EXECUTE_READWRITE
            } else {
                PAGE_READWRITE
            };
            let result = VirtualProtect(ptr, mapped_len as SIZE_T, protectFlag, &mut old);

            if result != 0 {
                Ok(MmapInner {
                    handle: None,
                    ptr,
                    len, // TODO: should this be mapped_len in case of huge page
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

            if let Some(handle) = self.handle {
                CloseHandle(handle);
            }
        }
    }
}

unsafe impl Sync for MmapInner {}
unsafe impl Send for MmapInner {}

fn protection_supported(handle: RawHandle, protection: DWORD) -> bool {
    protection_supported_with_size(handle, protection, 0)
}

fn protection_supported_with_size(handle: RawHandle, protection: DWORD, size: u64) -> bool {
    unsafe {
        let mapping = CreateFileMappingW(
            handle,
            ptr::null_mut(),
            protection,
            (size >> 32) as u32,
            (size & 0xFFFF_FFFF) as u32,
            ptr::null(),
        );

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

pub struct CloseHandleGuard {
    handle: HANDLE,
}

impl Drop for CloseHandleGuard {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

impl Deref for CloseHandleGuard {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl DerefMut for CloseHandleGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handle
    }
}

impl CloseHandleGuard {
    #[must_use]
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }
}

fn get_current_process_token() -> io::Result<HANDLE> {
    unsafe {
        let cur_proc = GetCurrentProcess();
        let mut process_token = 0 as RawHandle;
        let status = OpenProcessToken(
            cur_proc,
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut process_token,
        );
        if status != 0 {
            Ok(process_token)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn get_lock_memory_privilege_luid() -> io::Result<LUID> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let status = unsafe { LookupPrivilegeValueW(ptr::null(), SE_PRIVILEGE_LOCK_MEMORY, &mut luid) };
    if status != 0 {
        Ok(luid)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn enable_privilege(token: CloseHandleGuard, luid: LUID) -> io::Result<()> {
    let new_token_privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ATTR_ENABLED,
        }],
    };

    let status = unsafe {
        AdjustTokenPrivileges(
            *token,
            0,
            &new_token_privileges as *const _,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    // When called with more than a single privilege change,
    // AdjustTokenPrivilege might return status != 0
    // even if it did NOT adjust all privileges.
    // However, this should only happen when removing previously added
    // privilege.
    // The call above adds and only a single privilege,
    // so the following check should be fine to get the result.
    if status != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn enable_se_lock_memory_privilege() -> io::Result<()> {
    let token = CloseHandleGuard::new(get_current_process_token()?);
    let luid = get_lock_memory_privilege_luid()?;
    enable_privilege(token, luid)?;
    Ok(())
}

pub fn get_large_page_minimum() -> usize {
    let result = unsafe { GetLargePageMinimum() };
    result
}

#[cfg(test)]
mod test {
    use super::enable_se_lock_memory_privilege;

    #[test]
    fn enable_se_lock_memory_privilege_is_idempotent() {
        let initial = enable_se_lock_memory_privilege().unwrap();

        for _ in 0..3 {
            let subsequent = enable_se_lock_memory_privilege().unwrap();
            assert_eq!(initial, subsequent);
        }
    }
}
