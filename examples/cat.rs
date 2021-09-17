#[cfg(not(feature = "async"))]
extern crate memmap2;
#[cfg(not(feature = "async"))]
use memmap2::Mmap;
#[cfg(not(feature = "async"))]
use std::env;
#[cfg(not(feature = "async"))]
use std::fs::File;
#[cfg(not(feature = "async"))]
use std::io::{self, Write};

/// Output a file's contents to stdout. The file path must be provided as the first process
/// argument.
#[cfg(not(feature = "async"))]
fn main() {
    let path = env::args()
        .nth(1)
        .expect("supply a single path as the program argument");

    let file = File::open(path).expect("failed to open the file");

    let mmap = unsafe { Mmap::map(&file).expect("failed to map the file") };

    io::stdout()
        .write_all(&mmap[..])
        .expect("failed to output the file contents");
}

#[cfg(feature = "async")]
fn main() {
    println!("Nothing to do")
}
