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

    /// MADV_FREE
    #[cfg(unix)]
    Free = libc::MADV_FREE as isize,
    #[cfg(not(unix))]
    Free,

    /// MADV_REMOVE
    #[cfg(unix)]
    Remove = libc::MADV_REMOVE as isize,
    #[cfg(not(unix))]
    Remove,

    /// MADV_DONTFORK
    #[cfg(unix)]
    DontFork = libc::MADV_DONTFORK as isize,
    #[cfg(not(unix))]
    DontFork,

    /// MADV_DOFORK
    #[cfg(unix)]
    DoFork = libc::MADV_DOFORK as isize,
    #[cfg(not(unix))]
    DoFork,

    /// MADV_MERGEABLE
    #[cfg(unix)]
    Mergeable = libc::MADV_MERGEABLE as isize,
    #[cfg(not(unix))]
    Mergeable,

    /// MADV_UNMERGEABLE
    #[cfg(unix)]
    Unmergeable = libc::MADV_UNMERGEABLE as isize,
    #[cfg(not(unix))]
    Unmergeable,

    /// MADV_HUGEPAGE
    #[cfg(unix)]
    HugePage = libc::MADV_HUGEPAGE as isize,
    #[cfg(not(unix))]
    HugePage,

    /// MADV_NOHUGEPAGE
    #[cfg(unix)]
    NoHugePage = libc::MADV_NOHUGEPAGE as isize,
    #[cfg(not(unix))]
    NoHugePage,

    /// MADV_DONTDUMP
    #[cfg(unix)]
    DontDump = libc::MADV_DONTDUMP as isize,
    #[cfg(not(unix))]
    DontDump,

    /// MADV_DODUMP
    #[cfg(unix)]
    DoDump = libc::MADV_DODUMP as isize,
    #[cfg(not(unix))]
    DoDump,

    /// MADV_HWPOISON
    #[cfg(unix)]
    HwPoison = libc::MADV_HWPOISON as isize,
    #[cfg(not(unix))]
    HwPoison,
}
