//! A cross-platform Rust API for memory mapped buffers.

#[cfg(feature = "async")]
#[cfg(test)]
mod test {
    extern crate tempdir;

    use async_std::fs::OpenOptions;
    use async_std::io::{ReadExt, WriteExt};
    #[cfg(unix)]
    use async_std::os::unix::io::AsRawFd;
    use std::io::Write;
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    #[cfg(windows)]
    const GENERIC_ALL: u32 = 0x10000000;

    use memmap2::{Mmap, MmapMut, MmapOptions};

    #[async_std::test]
    async fn map_file() {
        let expected_len = 128;
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();

        file.set_len(expected_len as u64).await.unwrap();

        let mut mmap = unsafe { MmapMut::map_mut(&file).unwrap() };
        let len = mmap.len();
        assert_eq!(expected_len, len);

        let zeros = vec![0; len];
        let incr: Vec<u8> = (0..len as u8).collect();

        // check that the mmap is empty
        assert_eq!(&zeros[..], &mmap[..]);

        // write values into the mmap
        (&mut mmap[..]).write_all(&incr[..]).unwrap();

        // read values back
        assert_eq!(&incr[..], &mmap[..]);
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn map_fd() {
        let expected_len = 128;
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();

        file.set_len(expected_len as u64).await.unwrap();

        let mut mmap = unsafe { MmapMut::map_mut(file.as_raw_fd()).unwrap() };
        let len = mmap.len();
        assert_eq!(expected_len, len);

        let zeros = vec![0; len];
        let incr: Vec<u8> = (0..len as u8).collect();

        // check that the mmap is empty
        assert_eq!(&zeros[..], &mmap[..]);

        // write values into the mmap
        (&mut mmap[..]).write_all(&incr[..]).unwrap();

        // read values back
        assert_eq!(&incr[..], &mmap[..]);
    }

    /// Checks that a 0-length file will not be mapped.
    #[async_std::test]
    async fn map_empty_file() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();
        let mmap = unsafe { Mmap::map(&file) };
        assert!(mmap.is_err());
    }

    #[async_std::test]
    async fn map_anon() {
        let expected_len = 128;
        let mut mmap = MmapMut::map_anon(expected_len).unwrap();
        let len = mmap.len();
        assert_eq!(expected_len, len);

        let zeros = vec![0; len];
        let incr: Vec<u8> = (0..len as u8).collect();

        // check that the mmap is empty
        assert_eq!(&zeros[..], &mmap[..]);

        // write values into the mmap
        (&mut mmap[..]).write_all(&incr[..]).unwrap();

        // read values back
        assert_eq!(&incr[..], &mmap[..]);
    }

    #[async_std::test]
    async fn map_anon_zero_len() {
        assert!(MmapOptions::new().map_anon().is_err())
    }

    #[async_std::test]
    async fn file_write() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();
        file.set_len(128).await.unwrap();

        let write = b"abc123";
        let mut read = [0u8; 6];

        let mut mmap = unsafe { MmapMut::map_mut(&file).unwrap() };
        (&mut mmap[..]).write_all(write).unwrap();
        mmap.flush().unwrap();

        file.read_exact(&mut read).await.unwrap();
        assert_eq!(write, &read);
    }

    #[async_std::test]
    async fn flush_range() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();
        file.set_len(128).await.unwrap();
        let write = b"abc123";

        let mut mmap = unsafe {
            MmapOptions::new()
                .offset(2)
                .len(write.len())
                .map_mut(&file)
                .unwrap()
        };
        (&mut mmap[..]).write_all(write).unwrap();
        mmap.flush_async_range(0, write.len()).unwrap();
        mmap.flush_range(0, write.len()).unwrap();
    }

    #[async_std::test]
    async fn map_copy() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();
        file.set_len(128).await.unwrap();

        let nulls = b"\0\0\0\0\0\0";
        let write = b"abc123";
        let mut read = [0u8; 6];

        let mut mmap = unsafe { MmapOptions::new().map_copy(&file).unwrap() };

        (&mut mmap[..]).write_all(write).unwrap();
        mmap.flush().unwrap();

        // The mmap contains the write
        (&mmap[..]).read_exact(&mut read).await.unwrap();
        assert_eq!(write, &read);

        // The file does not contain the write
        file.read_exact(&mut read).await.unwrap();
        assert_eq!(nulls, &read);

        // another mmap does not contain the write
        let mmap2 = unsafe { MmapOptions::new().map(&file).unwrap() };
        (&mmap2[..]).read_exact(&mut read).await.unwrap();
        assert_eq!(nulls, &read);
    }

    #[async_std::test]
    async fn map_copy_read_only() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();
        file.set_len(128).await.unwrap();

        let nulls = b"\0\0\0\0\0\0";
        let mut read = [0u8; 6];

        let mmap = unsafe { MmapOptions::new().map_copy_read_only(&file).unwrap() };
        (&mmap[..]).read_exact(&mut read).await.unwrap();
        assert_eq!(nulls, &read);

        let mmap2 = unsafe { MmapOptions::new().map(&file).unwrap() };
        (&mmap2[..]).read_exact(&mut read).await.unwrap();
        assert_eq!(nulls, &read);
    }

    // 32bit Linux cannot map a file larger than i32, but Windows can.
    #[async_std::test]
    #[cfg(all(target_os = "linux", target_pointer_width = "32"))]
    async fn map_offset() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();

        let offset = u32::max_value() as u64 + 2;
        let len = 5432;
        file.set_len(offset + len as u64).unwrap();

        let mmap = unsafe { MmapOptions::new().offset(offset).map_mut(&file) };
        assert!(mmap.is_err());
    }

    #[async_std::test]
    #[cfg(not(all(target_os = "linux", target_pointer_width = "32")))]
    async fn map_offset() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .unwrap();

        let offset = u32::max_value() as u64 + 2;
        let len = 5432;
        file.set_len(offset + len as u64).await.unwrap();

        // Check inferred length mmap.
        let mmap = unsafe { MmapOptions::new().offset(offset).map_mut(&file).unwrap() };
        assert_eq!(len, mmap.len());

        // Check explicit length mmap.
        let mut mmap = unsafe {
            MmapOptions::new()
                .offset(offset)
                .len(len)
                .map_mut(&file)
                .unwrap()
        };
        assert_eq!(len, mmap.len());

        let zeros = vec![0; len];
        let incr: Vec<_> = (0..len).map(|i| i as u8).collect();

        // check that the mmap is empty
        assert_eq!(&zeros[..], &mmap[..]);

        // write values into the mmap
        (&mut mmap[..]).write_all(&incr[..]).unwrap();

        // read values back
        assert_eq!(&incr[..], &mmap[..]);
    }

    #[async_std::test]
    async fn index() {
        let mut mmap = MmapMut::map_anon(128).unwrap();
        mmap[0] = 42;
        assert_eq!(42, mmap[0]);
    }

    #[async_std::test]
    async fn sync_send() {
        let mmap = MmapMut::map_anon(129).unwrap();

        fn is_sync_send<T>(_val: T)
        where
            T: Sync + Send,
        {
        }

        is_sync_send(mmap);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn jit_x86(mut mmap: MmapMut) {
        use std::mem;
        mmap[0] = 0xB8; // mov eax, 0xAB
        mmap[1] = 0xAB;
        mmap[2] = 0x00;
        mmap[3] = 0x00;
        mmap[4] = 0x00;
        mmap[5] = 0xC3; // ret

        let mmap = mmap.make_exec().expect("make_exec");

        let jitfn: extern "C" fn() -> u8 = unsafe { mem::transmute(mmap.as_ptr()) };
        assert_eq!(jitfn(), 0xab);
    }

    #[async_std::test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    async fn jit_x86_anon() {
        jit_x86(MmapMut::map_anon(4096).unwrap());
    }

    #[async_std::test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    async fn jit_x86_file() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let mut options = OpenOptions::new();
        #[cfg(windows)]
        options.access_mode(GENERIC_ALL);

        let file = options
            .read(true)
            .write(true)
            .create(true)
            .open(&tempdir.path().join("jit_x86"))
            .await
            .expect("open");

        file.set_len(4096).await.expect("set_len");
        jit_x86(unsafe { MmapMut::map_mut(&file).expect("map_mut") });
    }

    #[async_std::test]
    async fn mprotect_file() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let mut options = OpenOptions::new();
        #[cfg(windows)]
        options.access_mode(GENERIC_ALL);

        let mut file = options
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .expect("open");
        file.set_len(256_u64).await.expect("set_len");

        let mmap = unsafe { MmapMut::map_mut(&file).expect("map_mut") };

        let mmap = mmap.make_read_only().expect("make_read_only");
        let mut mmap = mmap.make_mut().expect("make_mut");

        let write = b"abc123";
        let mut read = [0u8; 6];

        (&mut mmap[..]).write_all(write).unwrap();
        mmap.flush().unwrap();

        // The mmap contains the write
        (&mmap[..]).read_exact(&mut read).await.unwrap();
        assert_eq!(write, &read);

        // The file should contain the write
        file.read_exact(&mut read).await.unwrap();
        assert_eq!(write, &read);

        // another mmap should contain the write
        let mmap2 = unsafe { MmapOptions::new().map(&file).unwrap() };
        (&mmap2[..]).read_exact(&mut read).await.unwrap();
        assert_eq!(write, &read);

        let mmap = mmap.make_exec().expect("make_exec");

        drop(mmap);
    }

    #[async_std::test]
    async fn mprotect_copy() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmap");

        let mut options = OpenOptions::new();
        #[cfg(windows)]
        options.access_mode(GENERIC_ALL);

        let mut file = options
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .expect("open");
        file.set_len(256_u64).await.expect("set_len");

        let mmap = unsafe { MmapOptions::new().map_copy(&file).expect("map_mut") };

        let mmap = mmap.make_read_only().expect("make_read_only");
        let mut mmap = mmap.make_mut().expect("make_mut");

        let nulls = b"\0\0\0\0\0\0";
        let write = b"abc123";
        let mut read = [0u8; 6];

        (&mut mmap[..]).write_all(write).unwrap();
        mmap.flush().unwrap();

        // The mmap contains the write
        (&mmap[..]).read_exact(&mut read).await.unwrap();
        assert_eq!(write, &read);

        // The file does not contain the write
        file.read_exact(&mut read).await.unwrap();
        assert_eq!(nulls, &read);

        // another mmap does not contain the write
        let mmap2 = unsafe { MmapOptions::new().map(&file).unwrap() };
        (&mmap2[..]).read_exact(&mut read).await.unwrap();
        assert_eq!(nulls, &read);

        let mmap = mmap.make_exec().expect("make_exec");

        drop(mmap);
    }

    #[test]
    fn mprotect_anon() {
        let mmap = MmapMut::map_anon(256).expect("map_mut");

        let mmap = mmap.make_read_only().expect("make_read_only");
        let mmap = mmap.make_mut().expect("make_mut");
        let mmap = mmap.make_exec().expect("make_exec");
        drop(mmap);
    }

    #[async_std::test]
    async fn raw() {
        let tempdir = tempdir::TempDir::new("mmap").unwrap();
        let path = tempdir.path().join("mmapraw");

        let mut options = OpenOptions::new();
        let mut file = options
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .await
            .expect("open");
        file.write_all(b"abc123").await.unwrap();
        file.sync_all().await.unwrap();
        let mmap = MmapOptions::new().map_raw(&file).unwrap();
        assert_eq!(mmap.len(), 6);
        assert!(!mmap.as_ptr().is_null());
        assert_eq!(unsafe { std::ptr::read(mmap.as_ptr()) }, b'a');
    }

    #[test]
    /// Something that relies on StableDeref
    #[cfg(feature = "stable_deref_trait")]
    fn owning_ref() {
        extern crate owning_ref;

        let mut map = MmapMut::map_anon(128).unwrap();
        map[10] = 42;
        let owning = owning_ref::OwningRef::new(map);
        let sliced = owning.map(|map| &map[10..20]);
        assert_eq!(42, sliced[0]);

        let map = sliced.into_owner().make_read_only().unwrap();
        let owning = owning_ref::OwningRef::new(map);
        let sliced = owning.map(|map| &map[10..20]);
        assert_eq!(42, sliced[0]);
    }
}
