//! Best-effort secure deletion: overwrite with random data, truncate, rename, delete.
//! This is honest about its limits: on SSDs, with shadow copies or cloud-synced folders the old
//! bytes may survive elsewhere. Full-disk encryption (BitLocker) is the real protection.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use data_encoding::HEXLOWER;

use crate::{
    crypto::random_bytes,
    util::{ioe, Res},
};

pub fn shred(path: &Path) -> Res<()> {
    let md = fs::symlink_metadata(path).map_err(ioe)?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err("not a regular file".into());
    }
    let mut perm = md.permissions();
    if perm.readonly() {
        perm.set_readonly(false);
        fs::set_permissions(path, perm).map_err(ioe)?;
    }
    {
        let mut f = OpenOptions::new().write(true).open(path).map_err(ioe)?;
        let mut left = f.metadata().map_err(ioe)?.len();
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let n = left.min(buf.len() as u64) as usize;
            random_bytes(&mut buf[..n]);
            f.write_all(&buf[..n]).map_err(ioe)?;
            left -= n as u64;
        }
        f.sync_all().map_err(ioe)?;
        f.set_len(0).map_err(ioe)?;
        f.sync_all().map_err(ioe)?;
    }
    let mut rnd = [0u8; 12];
    random_bytes(&mut rnd);
    let renamed = path.with_file_name(HEXLOWER.encode(&rnd));
    let target = if fs::rename(path, &renamed).is_ok() {
        renamed
    } else {
        path.to_path_buf()
    };
    fs::remove_file(target).map_err(ioe)
}
