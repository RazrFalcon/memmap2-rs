//! WASI has no `mmap`, so file-backed maps are emulated by reading the requested range of the
//! file into a heap buffer.
//!
//! The buffer is a private snapshot of the file taken when the map is created. This matches
//! copy-on-write maps exactly. Read-only maps behave like a `MAP_PRIVATE` mapping: later changes
//! to the file are not visible through the map. Maps that would write back to the file or be
//! executable return [`io::ErrorKind::Unsupported`].

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

pub struct MmapInner {
    data: Box<[u8]>,
    /// Writes to the buffer are allowed only when they would not reach the file on other
    /// platforms either (copy-on-write and anonymous maps).
    private: bool,
}

impl MmapInner {
    fn read(len: usize, file: &File, offset: u64, private: bool) -> io::Result<MmapInner> {
        let mut data = vec![0u8; len].into_boxed_slice();
        let mut file = file;
        // A real map does not move the file cursor, and callers may keep reading from the same
        // descriptor afterwards, so restore it.
        let position = file.stream_position()?;
        file.seek(SeekFrom::Start(offset))?;
        let read = file.read_exact(&mut data);
        file.seek(SeekFrom::Start(position))?;
        read?;
        Ok(MmapInner { data, private })
    }

    pub fn map(
        len: usize,
        file: &File,
        offset: u64,
        _populate: bool,
        _no_reserve: bool,
        _probe_handle: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::read(len, file, offset, false)
    }

    pub fn map_exec(
        _: usize,
        _: &File,
        _: u64,
        _: bool,
        _: bool,
        _: bool,
    ) -> io::Result<MmapInner> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub fn map_mut(_: usize, _: &File, _: u64, _: bool, _: bool, _: bool) -> io::Result<MmapInner> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub fn map_copy(
        len: usize,
        file: &File,
        offset: u64,
        _populate: bool,
        _no_reserve: bool,
        _probe_handle: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::read(len, file, offset, true)
    }

    pub fn map_copy_read_only(
        len: usize,
        file: &File,
        offset: u64,
        _populate: bool,
        _no_reserve: bool,
        _probe_handle: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::read(len, file, offset, true)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn map_anon(
        len: usize,
        _stack: bool,
        _populate: bool,
        _huge: Option<u8>,
        _no_reserve: bool,
    ) -> io::Result<MmapInner> {
        Ok(MmapInner {
            data: vec![0u8; len].into_boxed_slice(),
            private: true,
        })
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    pub fn flush(&self, _: usize, _: usize) -> io::Result<()> {
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    pub fn flush_async(&self, _: usize, _: usize) -> io::Result<()> {
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    pub fn make_read_only(&mut self) -> io::Result<()> {
        Ok(())
    }

    #[allow(clippy::unused_self)]
    pub fn make_exec(&mut self) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub fn make_mut(&mut self) -> io::Result<()> {
        if self.private {
            Ok(())
        } else {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    #[inline]
    pub fn ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    #[inline]
    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn check_safe_to_map(
        _file: &File,
        _offset: u64,
        _len: usize,
    ) -> Result<(), crate::MapIfSafeError> {
        Err(crate::MapIfSafeError::new_not_supported())
    }
}

pub fn file_len(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.len())
}

#[cfg(test)]
mod tests {
    use crate::{Mmap, MmapMut, MmapOptions};
    use std::fs::OpenOptions;
    use std::io::{self, Read, Seek, SeekFrom, Write};

    fn file_with(contents: &[u8]) -> (tempfile::TempDir, std::fs::File) {
        // `std::env::temp_dir()` panics on WASI, so use a directory under the current one.
        // Run with a preopened current directory, e.g. `wasmtime run --dir=.`.
        let dir = tempfile::tempdir_in(".").unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.path().join("mmap"))
            .unwrap();
        file.write_all(contents).unwrap();
        (dir, file)
    }

    #[test]
    fn map_reads_range_and_keeps_cursor() {
        let (_dir, mut file) = file_with(b"0123456789");
        file.seek(SeekFrom::Start(3)).unwrap();

        let mmap = unsafe { MmapOptions::new().offset(2).len(5).map(&file).unwrap() };
        assert_eq!(&mmap[..], b"23456");

        let mut rest = String::new();
        file.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "3456789");
    }

    #[test]
    fn map_copy_is_private() {
        let (_dir, mut file) = file_with(b"hello");

        let mut mmap = unsafe { MmapOptions::new().map_copy(&file).unwrap() };
        mmap[0] = b'j';
        mmap.flush().unwrap();
        assert_eq!(&mmap[..], b"jello");

        let mut contents = String::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "hello");
    }

    #[test]
    fn writable_file_maps_are_unsupported() {
        let (_dir, file) = file_with(b"hello");

        let err = unsafe { MmapMut::map_mut(&file) }.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);

        let mmap = unsafe { Mmap::map(&file).unwrap() };
        let err = mmap.make_mut().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn map_copy_read_only_can_be_made_mutable() {
        let (_dir, file) = file_with(b"hello");

        let mmap = unsafe { MmapOptions::new().map_copy_read_only(&file).unwrap() };
        let mut mmap = mmap.make_mut().unwrap();
        mmap[4] = b'!';
        assert_eq!(&mmap[..], b"hell!");
    }

    #[test]
    fn map_past_end_fails() {
        let (_dir, file) = file_with(b"hello");

        let err = unsafe { MmapOptions::new().offset(3).len(5).map(&file) }.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn map_anon_is_zeroed_and_writable() {
        let mut mmap = MmapMut::map_anon(16).unwrap();
        assert!(mmap.iter().all(|&b| b == 0));
        mmap[15] = 1;
        let mmap = mmap.make_read_only().unwrap();
        assert_eq!(mmap[15], 1);
        mmap.make_mut().unwrap();
    }
}
