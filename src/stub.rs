//! Unsupported-platform implementation stub.
//!
//! `MmapInner` is intentionally unconstructible using an uninhabited type
//! so that all instance methods are statically proven unreachable.
use std::convert::Infallible;
use std::fs::File;
use std::io;

pub struct MmapInner {
    never: Infallible,
}

impl MmapInner {
    fn new() -> io::Result<MmapInner> {
        Err(io::ErrorKind::Unsupported.into())
    }

    pub fn map(_: usize, _: &File, _: u64, _: bool, _: bool, _: bool) -> io::Result<MmapInner> {
        MmapInner::new()
    }

    pub fn map_exec(
        _: usize,
        _: &File,
        _: u64,
        _: bool,
        _: bool,
        _: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::new()
    }

    pub fn map_mut(_: usize, _: &File, _: u64, _: bool, _: bool, _: bool) -> io::Result<MmapInner> {
        MmapInner::new()
    }

    pub fn map_copy(
        _: usize,
        _: &File,
        _: u64,
        _: bool,
        _: bool,
        _: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::new()
    }

    pub fn map_copy_read_only(
        _: usize,
        _: &File,
        _: u64,
        _: bool,
        _: bool,
        _: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::new()
    }

    pub fn map_anon(_: usize, _: bool, _: bool, _: Option<u8>, _: bool) -> io::Result<MmapInner> {
        MmapInner::new()
    }

    pub fn flush(&self, _: usize, _: usize) -> io::Result<()> {
        match self.never {}
    }

    pub fn flush_async(&self, _: usize, _: usize) -> io::Result<()> {
        match self.never {}
    }

    pub fn make_read_only(&mut self) -> io::Result<()> {
        match self.never {}
    }

    pub fn make_exec(&mut self) -> io::Result<()> {
        match self.never {}
    }

    pub fn make_mut(&mut self) -> io::Result<()> {
        match self.never {}
    }

    #[inline]
    pub fn ptr(&self) -> *const u8 {
        match self.never {}
    }

    #[inline]
    pub fn mut_ptr(&mut self) -> *mut u8 {
        match self.never {}
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self.never {}
    }
}

pub fn file_len(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.len())
}
