use std::{
    fs::{self, File},
    io::{self, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

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

/// Seconds since epoch -> "YYYY-MM-DD HH:MM:SS" (UTC).
pub fn fmt_utc(t: u64) -> String {
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

pub fn fmt_dur(s: u64) -> String {
    format!("{:02}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60)
}

pub fn fmt_size(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Write-then-rename so a crash never leaves a half-written file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Res<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(ioe)?;
        f.write_all(bytes).map_err(ioe)?;
        f.sync_all().map_err(ioe)?;
    }
    fs::rename(&tmp, path).map_err(ioe)
}
