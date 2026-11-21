use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::protect;

/// Errors are short fixed strings. They never carry paths or file contents.
pub type Res<T> = Result<T, String>;

pub fn ioe(e: io::Error) -> String {
    e.kind().to_string()
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write-then-rename so a crash never leaves a half-written file. The temporary file gets
/// complete data protection before any byte is written.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Res<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(ioe)?;
        protect::complete(&f)?;
        f.write_all(bytes).map_err(ioe)?;
        f.sync_all().map_err(ioe)?;
    }
    fs::rename(&tmp, path).map_err(ioe)
}
