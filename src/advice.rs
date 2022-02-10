// The use statement is needed for the `cargo docs`
#[allow(unused_imports)]
use crate::{Mmap, MmapMut};

// TODO: Once stmt_expr_attributes becomes stable, it might be possible to rewrite this without duplicating enum names
// See https://github.com/rust-lang/rfcs/blob/161ce8a26e70226a88e0d4d43c7914a714050330/text/0016-more-attributes.md

/// Values supported by [Mmap::advise] and [MmapMut::advise] functions.
/// Non unix platforms will ignore these values and return an error.
/// See [madvise()](https://man7.org/linux/man-pages/man2/madvise.2.html) map page.
#[non_exhaustive]
pub enum Advice {
    /// MADV_NORMAL
    #[cfg(unix)]
    Normal = libc::MADV_NORMAL as isize,
    #[cfg(not(unix))]
    Normal,

    /// MADV_RANDOM
    #[cfg(unix)]
    Random = libc::MADV_RANDOM as isize,
    #[cfg(not(unix))]
    Random,

    /// MADV_SEQUENTIAL
    #[cfg(unix)]
    Sequential = libc::MADV_SEQUENTIAL as isize,
    #[cfg(not(unix))]
    Sequential,

    /// MADV_WILLNEED
    #[cfg(unix)]
    WillNeed = libc::MADV_WILLNEED as isize,
    #[cfg(not(unix))]
    WillNeed,

    /// MADV_DONTNEED
    #[cfg(unix)]
    DontNeed = libc::MADV_DONTNEED as isize,
    #[cfg(not(unix))]
    DontNeed,

    //
    // The rest are Linux-specific
    //
    /// MADV_FREE - Linux only (since Linux 4.5)
    #[cfg(target_os = "linux")]
    Free = libc::MADV_FREE as isize,
    #[cfg(not(unix))]
    Free,

    /// MADV_REMOVE - Linux only (since Linux 2.6.16)
    #[cfg(target_os = "linux")]
    Remove = libc::MADV_REMOVE as isize,
    #[cfg(not(unix))]
    Remove,

    /// MADV_DONTFORK - Linux only (since Linux 2.6.16)
    #[cfg(target_os = "linux")]
    DontFork = libc::MADV_DONTFORK as isize,
    #[cfg(not(unix))]
    DontFork,

    /// MADV_DOFORK - Linux only (since Linux 2.6.16)
    #[cfg(target_os = "linux")]
    DoFork = libc::MADV_DOFORK as isize,
    #[cfg(not(unix))]
    DoFork,

    /// MADV_MERGEABLE - Linux only (since Linux 2.6.32)
    #[cfg(target_os = "linux")]
    Mergeable = libc::MADV_MERGEABLE as isize,
    #[cfg(not(unix))]
    Mergeable,

    /// MADV_UNMERGEABLE - Linux only (since Linux 2.6.32)
    #[cfg(target_os = "linux")]
    Unmergeable = libc::MADV_UNMERGEABLE as isize,
    #[cfg(not(unix))]
    Unmergeable,

    /// MADV_HUGEPAGE - Linux only (since Linux 2.6.38)
    #[cfg(target_os = "linux")]
    HugePage = libc::MADV_HUGEPAGE as isize,
    #[cfg(not(unix))]
    HugePage,

    /// MADV_NOHUGEPAGE - Linux only (since Linux 2.6.38)
    #[cfg(target_os = "linux")]
    NoHugePage = libc::MADV_NOHUGEPAGE as isize,
    #[cfg(not(unix))]
    NoHugePage,

    /// MADV_DONTDUMP - Linux only (since Linux 3.4)
    #[cfg(target_os = "linux")]
    DontDump = libc::MADV_DONTDUMP as isize,
    #[cfg(not(unix))]
    DontDump,

    /// MADV_DODUMP - Linux only (since Linux 3.4)
    #[cfg(target_os = "linux")]
    DoDump = libc::MADV_DODUMP as isize,
    #[cfg(not(unix))]
    DoDump,

    /// MADV_HWPOISON - Linux only (since Linux 2.6.32)
    #[cfg(target_os = "linux")]
    HwPoison = libc::MADV_HWPOISON as isize,
    #[cfg(not(unix))]
    HwPoison,
    // Future expansion:
    // MADV_SOFT_OFFLINE  (since Linux 2.6.33)
    // MADV_WIPEONFORK  (since Linux 4.14)
    // MADV_KEEPONFORK  (since Linux 4.14)
    // MADV_COLD  (since Linux 5.4)
    // MADV_PAGEOUT  (since Linux 5.4)
}
