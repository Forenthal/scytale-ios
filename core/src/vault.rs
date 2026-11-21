//! The vault: key hierarchy, encrypted index, encrypted blobs. Ported from the Windows build; the
//! only change is where the second factor of the password key comes from.
//!
//! Key hierarchy
//!   password --Argon2id--+
//!                        +--HKDF--> KEK_pw --AES-GCM--> master key (MK)
//!   device pepper -------+   (32 random bytes, stored only wrapped by a Secure Enclave key that
//!                             needs Face ID; on Windows this was DPAPI)
//!   recovery key --HKDF--> KEK_rk --AES-GCM--> master key (MK)
//!   MK --HKDF--> index key, wrap key, TOTP key
//!   per-item random data key (DEK) --wrapped by wrap key--> stored in the item's own blob header
//!
//! Because each blob carries its own wrapped DEK, deleting the blob destroys the only copy of
//! that key (crypto-shredding) in addition to overwriting the ciphertext.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use data_encoding::HEXLOWER;
use zeroize::Zeroizing;

use crate::{
    crypto::{self, Kdf},
    harden, protect,
    secret::{Secret32, SecretInput},
    util::{ioe, unix_now, write_atomic, Res},
    wipe,
};

pub const MSG_CAP: usize = 16 * 1024;
/// Largest file the in-memory viewer will decrypt.
pub const VIEW_CAP: u64 = 64 * 1024 * 1024;
pub const NAME_CAP: usize = 1024;

const HDR_MAGIC: &[u8; 4] = b"SCYV";
const IDX_MAGIC: &[u8; 5] = b"SCYI\x01";
const BLOB_MAGIC: &[u8; 5] = b"SCYB\x01";
const WRAP_LEN: usize = 12 + 32 + 16;
const TOTP_LEN: usize = 12 + 20 + 16;
const BLOB_HDR: usize = 5 + 16 + WRAP_LEN;

// ---------------------------------------------------------------- items

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    File = 1,
    Msg = 2,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: [u8; 16],
    pub kind: Kind,
    pub created: u64,
    pub size: u64,
    pub name: String,
}

impl Item {
    pub fn short(&self) -> String {
        HEXLOWER.encode(&self.id[..3])
    }
}

pub struct Session {
    pub mk: Secret32,
    index_key: Secret32,
    wrap_key: Secret32,
    pub items: Vec<Item>,
}

impl Session {
    pub fn new(mk: Secret32) -> Session {
        let index_key = crypto::hkdf(mk.as_bytes(), b"scytale/v1", b"index");
        let wrap_key = crypto::hkdf(mk.as_bytes(), b"scytale/v1", b"wrap");
        Session { mk, index_key, wrap_key, items: Vec::new() }
    }

    pub fn get(&self, id: &[u8; 16]) -> Option<&Item> {
        self.items.iter().find(|i| &i.id == id)
    }
}

// ---------------------------------------------------------------- header

struct Header {
    kdf: Kdf,
    salt: [u8; 16],
    /// The device pepper, wrapped by the Secure Enclave key. Opaque to this module.
    dp: Vec<u8>,
    wrap_pw: Vec<u8>,
    wrap_rk: Vec<u8>,
    totp: Vec<u8>,
}

impl Header {
    /// Everything that is bound into the password wrap as associated data.
    fn prefix(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(HDR_MAGIC);
        v.push(1);
        for n in [self.kdf.m, self.kdf.t, self.kdf.p] {
            v.extend_from_slice(&n.to_le_bytes());
        }
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&(self.dp.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.dp);
        v
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.prefix();
        v.extend_from_slice(&self.wrap_pw);
        v.extend_from_slice(&self.wrap_rk);
        v.extend_from_slice(&self.totp);
        v
    }

    fn parse(b: &[u8]) -> Res<Header> {
        let bad = || "vault header is corrupt".to_string();
        if b.len() < 4 + 1 + 12 + 16 + 4 || &b[..4] != HDR_MAGIC || b[4] != 1 {
            return Err(bad());
        }
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let kdf = Kdf { m: u32_at(5), t: u32_at(9), p: u32_at(13) };
        if !kdf.valid() {
            return Err(bad());
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[17..33]);
        let dlen = u32_at(33) as usize;
        let rest = 37 + dlen;
        if dlen > 4096 || b.len() != rest + WRAP_LEN + WRAP_LEN + TOTP_LEN {
            return Err(bad());
        }
        Ok(Header {
            kdf,
            salt,
            dp: b[37..rest].to_vec(),
            wrap_pw: b[rest..rest + WRAP_LEN].to_vec(),
            wrap_rk: b[rest + WRAP_LEN..rest + 2 * WRAP_LEN].to_vec(),
            totp: b[rest + 2 * WRAP_LEN..].to_vec(),
        })
    }
}

fn pw_kek(password: &[u8], salt: &[u8; 16], kdf: &Kdf, pepper: &[u8; 32]) -> Res<Secret32> {
    let a = crypto::argon2id(password, salt, kdf)?;
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(a.as_bytes());
    ikm[32..].copy_from_slice(pepper);
    Ok(crypto::hkdf(&ikm[..], salt, b"scytale/kek/pw"))
}

fn rk_kek(rk: &Secret32) -> Secret32 {
    crypto::hkdf(rk.as_bytes(), b"scytale/v1", b"kek/rk")
}

fn totp_key(mk: &Secret32) -> Secret32 {
    crypto::hkdf(mk.as_bytes(), b"scytale/v1", b"totp")
}

const RK_AAD: &[u8] = b"scytale/rk";
const TOTP_AAD: &[u8] = b"scytale/totp";

// ---------------------------------------------------------------- index (de)serialisation

fn ser_items(items: &[Item]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::new());
    v.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for i in items {
        v.extend_from_slice(&i.id);
        v.push(i.kind as u8);
        v.extend_from_slice(&i.created.to_le_bytes());
        v.extend_from_slice(&i.size.to_le_bytes());
        let n = i.name.as_bytes();
        v.extend_from_slice(&(n.len() as u16).to_le_bytes());
        v.extend_from_slice(n);
    }
    v
}

fn de_items(b: &[u8]) -> Res<Vec<Item>> {
    let bad = || "index is corrupt".to_string();
    let mut pos = 0usize;
    let mut take = |n: usize| -> Res<&[u8]> {
        let s = b.get(pos..pos + n).ok_or_else(bad)?;
        pos += n;
        Ok(s)
    };
    let count = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        let mut id = [0u8; 16];
        id.copy_from_slice(take(16)?);
        let kind = match take(1)?[0] {
            1 => Kind::File,
            2 => Kind::Msg,
            _ => return Err(bad()),
        };
        let created = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let size = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let nl = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let name = String::from_utf8(take(nl)?.to_vec()).map_err(|_| bad())?;
        out.push(Item { id, kind, created, size, name });
    }
    Ok(out)
}

/// Counts bytes as they stream through, so sizes are known for sources without metadata.
struct Counting<'a, R: Read> {
    inner: &'a mut R,
    n: u64,
}

impl<R: Read> Read for Counting<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n += k as u64;
        Ok(k)
    }
}

// ---------------------------------------------------------------- vault

pub struct Vault {
    pub dir: PathBuf,
}

impl Vault {
    pub fn new(dir: PathBuf) -> Vault {
        Vault { dir }
    }

    fn p(&self, n: &str) -> PathBuf {
        self.dir.join(n)
    }

    fn blobs(&self) -> PathBuf {
        self.dir.join("blobs")
    }

    fn blob_path(&self, id: &[u8; 16]) -> PathBuf {
        self.blobs().join(format!("{}.scy", HEXLOWER.encode(id)))
    }

    pub fn exists(&self) -> bool {
        self.p("vault.hdr").is_file()
    }

    fn load_header(&self) -> Res<Header> {
        Header::parse(&fs::read(self.p("vault.hdr")).map_err(ioe)?)
    }

    /// The Secure-Enclave-wrapped pepper stored in the header, for the platform layer to unwrap.
    pub fn wrapped_pepper(&self) -> Res<Vec<u8>> {
        Ok(self.load_header()?.dp)
    }

    fn build_header(
        &self,
        mk: &Secret32,
        password: &[u8],
        pepper: &Secret32,
        wrapped_pepper: &[u8],
        wrap_rk: Vec<u8>,
        totp_blob: Vec<u8>,
    ) -> Res<Header> {
        if wrapped_pepper.is_empty() || wrapped_pepper.len() > 4096 {
            return Err("invalid device key data".into());
        }
        let mut salt = [0u8; 16];
        crypto::random_bytes(&mut salt);
        let mut h = Header {
            kdf: Kdf::DEFAULT,
            salt,
            dp: wrapped_pepper.to_vec(),
            wrap_pw: Vec::new(),
            wrap_rk,
            totp: totp_blob,
        };
        let kek = pw_kek(password, &salt, &h.kdf, pepper.as_bytes())?;
        h.wrap_pw = crypto::seal(kek.as_bytes(), &h.prefix(), mk.as_bytes());
        Ok(h)
    }

    /// Create a brand-new vault. Returns the master key.
    pub fn create(
        &self,
        password: &[u8],
        totp: &[u8],
        rk: &Secret32,
        pepper: &Secret32,
        wrapped_pepper: &[u8],
    ) -> Res<Secret32> {
        if self.exists() {
            return Err("a vault already exists".into());
        }
        fs::create_dir_all(self.blobs()).map_err(ioe)?;
        let mk = Secret32::random();
        let wrap_rk = crypto::seal(rk_kek(rk).as_bytes(), RK_AAD, mk.as_bytes());
        let totp_blob = crypto::seal(totp_key(&mk).as_bytes(), TOTP_AAD, totp);
        let h = self.build_header(&mk, password, pepper, wrapped_pepper, wrap_rk, totp_blob)?;
        let s = Session::new(Secret32::from_slice(mk.as_bytes()));
        self.save_index(&s)?;
        write_atomic(&self.p("vault.hdr"), &h.to_bytes())?;
        Ok(mk)
    }

    /// Password + device pepper -> master key. `pepper` is None when Face ID or the Secure Enclave
    /// refused; the full KDF still runs so timing does not reveal which factor failed.
    pub fn unlock(&self, password: &[u8], pepper: Option<&Secret32>) -> Option<Secret32> {
        let h = self.load_header().ok()?;
        let zero = [0u8; 32];
        let kek = pw_kek(password, &h.salt, &h.kdf, pepper.map_or(&zero, |p| p.as_bytes())).ok()?;
        pepper?;
        let mk = crypto::open(kek.as_bytes(), &h.prefix(), &h.wrap_pw)?;
        (mk.len() == 32).then(|| Secret32::from_slice(&mk))
    }

    pub fn unlock_recovery(&self, rk: &Secret32) -> Option<Secret32> {
        let h = self.load_header().ok()?;
        let mk = crypto::open(rk_kek(rk).as_bytes(), RK_AAD, &h.wrap_rk)?;
        (mk.len() == 32).then(|| Secret32::from_slice(&mk))
    }

    pub fn totp_secret(&self, mk: &Secret32) -> Option<Zeroizing<Vec<u8>>> {
        let h = self.load_header().ok()?;
        crypto::open(totp_key(mk).as_bytes(), TOTP_AAD, &h.totp)
    }

    /// New password and new device pepper. Optionally replaces the recovery key and TOTP.
    #[allow(clippy::too_many_arguments)]
    pub fn rewrite_header(
        &self,
        mk: &Secret32,
        password: &[u8],
        pepper: &Secret32,
        wrapped_pepper: &[u8],
        new_rk: Option<&Secret32>,
        new_totp: Option<&[u8]>,
    ) -> Res<()> {
        let old = self.load_header()?;
        let wrap_rk = match new_rk {
            Some(rk) => crypto::seal(rk_kek(rk).as_bytes(), RK_AAD, mk.as_bytes()),
            None => old.wrap_rk.clone(),
        };
        let totp_blob = match new_totp {
            Some(t) => crypto::seal(totp_key(mk).as_bytes(), TOTP_AAD, t),
            None => old.totp.clone(),
        };
        let h = self.build_header(mk, password, pepper, wrapped_pepper, wrap_rk, totp_blob)?;
        write_atomic(&self.p("vault.hdr"), &h.to_bytes())
    }

    // ------------------------------------------------------------ index

    fn save_index(&self, s: &Session) -> Res<()> {
        let sealed = crypto::seal(s.index_key.as_bytes(), b"scytale/index", &ser_items(&s.items));
        let mut out = IDX_MAGIC.to_vec();
        out.extend_from_slice(&sealed);
        write_atomic(&self.p("index.scy"), &out)
    }

    /// Load the index and reconcile with the blob directory. Returns
    /// (index entries whose blob vanished, leftover blobs shredded).
    pub fn load_index(&self, s: &mut Session) -> Res<(usize, usize)> {
        let raw = match fs::read(self.p("index.scy")) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err("index missing".into()),
            Err(e) => return Err(ioe(e)),
        };
        if raw.len() < IDX_MAGIC.len() || &raw[..IDX_MAGIC.len()] != IDX_MAGIC {
            return Err("index is corrupt".into());
        }
        let pt = crypto::open(s.index_key.as_bytes(), b"scytale/index", &raw[IDX_MAGIC.len()..])
            .ok_or("index failed authentication (corrupt or modified)")?;
        s.items = de_items(&pt)?;

        let mut dropped = 0;
        let before = s.items.len();
        s.items.retain(|i| self.blob_path(&i.id).is_file());
        dropped += before - s.items.len();
        let mut shredded = 0;
        if let Ok(rd) = fs::read_dir(self.blobs()) {
            for e in rd.flatten() {
                let path = e.path();
                let stem = path.file_stem().and_then(|x| x.to_str()).unwrap_or("");
                let known = path.extension().and_then(|x| x.to_str()) == Some("scy")
                    && s.items.iter().any(|i| HEXLOWER.encode(&i.id) == stem);
                if !known && wipe::shred(&path).is_ok() {
                    shredded += 1;
                }
            }
        }
        if dropped > 0 {
            self.save_index(s)?;
        }
        Ok((dropped, shredded))
    }

    fn new_id(&self, s: &Session) -> [u8; 16] {
        loop {
            let mut id = [0u8; 16];
            crypto::random_bytes(&mut id);
            let hex = HEXLOWER.encode(&id[..3]);
            if !s.items.iter().any(|i| HEXLOWER.encode(&i.id[..3]) == hex) {
                return id;
            }
        }
    }

    // ------------------------------------------------------------ blobs

    /// Encrypt `src` into a new blob, verify it by decrypting what was written, then publish it.
    /// Returns the plaintext length.
    fn write_blob<R: Read>(&self, s: &Session, id: &[u8; 16], src: &mut R) -> Res<u64> {
        let dek = Secret32::random();
        let tmp = self.blob_path(id).with_extension("part");
        let fin = self.blob_path(id);
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(ioe)?;
        let result = (|| -> Res<u64> {
            protect::complete(&file)?;
            let mut w = BufWriter::new(&mut file);
            w.write_all(BLOB_MAGIC).map_err(ioe)?;
            w.write_all(id).map_err(ioe)?;
            w.write_all(&crypto::seal(s.wrap_key.as_bytes(), id, dek.as_bytes())).map_err(ioe)?;
            let mut counted = Counting { inner: src, n: 0 };
            let h1 = crypto::encrypt_stream(&mut counted, &mut w, dek.as_bytes(), id)?;
            let n = counted.n;
            w.flush().map_err(ioe)?;
            drop(w);
            file.sync_all().map_err(ioe)?;
            let mut chk = BufReader::new(File::open(&tmp).map_err(ioe)?);
            let mut hdr = [0u8; BLOB_HDR];
            chk.read_exact(&mut hdr).map_err(ioe)?;
            let h2 = crypto::decrypt_stream(&mut chk, &mut io::sink(), dek.as_bytes(), id)?;
            if !crypto::ct_eq(&h1, &h2) {
                return Err("verification failed".into());
            }
            Ok(n)
        })();
        drop(file);
        match result {
            Ok(n) => fs::rename(&tmp, &fin).map(|_| n).map_err(ioe),
            Err(e) => {
                let _ = wipe::shred(&tmp);
                Err(e)
            }
        }
    }

    fn open_blob(&self, s: &Session, id: &[u8; 16]) -> Res<(BufReader<File>, Secret32)> {
        let mut f = BufReader::new(File::open(self.blob_path(id)).map_err(ioe)?);
        let mut hdr = [0u8; BLOB_HDR];
        f.read_exact(&mut hdr).map_err(|_| "blob is corrupt".to_string())?;
        if &hdr[..5] != BLOB_MAGIC || &hdr[5..21] != id {
            return Err("blob is corrupt".into());
        }
        let dek = crypto::open(s.wrap_key.as_bytes(), id, &hdr[21..])
            .ok_or("blob key failed authentication")?;
        if dek.len() != 32 {
            return Err("blob is corrupt".into());
        }
        Ok((f, Secret32::from_slice(&dek)))
    }

    fn commit_item(&self, s: &mut Session, item: Item) -> Res<Item> {
        s.items.push(item.clone());
        if let Err(e) = self.save_index(s) {
            s.items.pop();
            let _ = wipe::shred(&self.blob_path(&item.id));
            return Err(e);
        }
        Ok(item)
    }

    // ------------------------------------------------------------ files

    fn check_name(name: &str) -> Res<()> {
        if name.is_empty() || name.len() > NAME_CAP {
            return Err("file name is empty or too long".into());
        }
        Ok(())
    }

    /// Encrypt any byte stream (camera capture, photo library, file) into the vault.
    pub fn add_stream<R: Read>(&self, s: &mut Session, name: &str, src: &mut R) -> Res<Item> {
        Self::check_name(name)?;
        let id = self.new_id(s);
        let size = self.write_blob(s, &id, src)?;
        self.commit_item(s, Item { id, kind: Kind::File, created: unix_now(), size, name: name.to_string() })
    }

    /// Encrypt a file into the vault. With `erase_original`, the original is shredded only after
    /// the encrypted copy is verified and committed. Returns the item and, if the original could
    /// not be erased, a warning.
    pub fn add_file(&self, s: &mut Session, src: &Path, erase_original: bool) -> Res<(Item, Option<String>)> {
        let md = fs::symlink_metadata(src).map_err(ioe)?;
        if md.file_type().is_symlink() {
            return Err("refusing to follow a symbolic link".into());
        }
        if !md.is_file() {
            return Err("not a regular file (folders are not supported)".into());
        }
        if let (Ok(a), Ok(b)) = (fs::canonicalize(src), fs::canonicalize(&self.dir)) {
            if a.starts_with(b) {
                return Err("that file is inside the vault".into());
            }
        }
        let name = src
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("file name is not valid text")?
            .to_string();
        let mut input = BufReader::new(File::open(src).map_err(ioe)?);
        let item = self.add_stream(s, &name, &mut input)?;
        drop(input);
        let warn = if erase_original {
            wipe::shred(src).err().map(|e| {
                format!("the encrypted copy is safe, but the original could not be erased ({e}); delete it yourself")
            })
        } else {
            None
        };
        Ok((item, warn))
    }

    /// Decrypt a vault file into locked memory for the in-app viewer. Nothing touches the disk.
    pub fn open_file(&self, s: &Session, item: &Item) -> Res<SecretInput> {
        if item.size > VIEW_CAP {
            return Err("too large to view in memory".into());
        }
        let cap = item.size as usize + 64 * 1024;
        harden::working_set(cap + (96 << 20), cap + (256 << 20));
        let mut out = SecretInput::new(cap);
        let (mut r, dek) = self.open_blob(s, &item.id)?;
        crypto::decrypt_stream(&mut r, &mut out, dek.as_bytes(), &item.id).map_err(|e| {
            if e == "out of memory" {
                "file is larger than recorded; cannot view".into()
            } else {
                e
            }
        })?;
        Ok(out)
    }

    // ------------------------------------------------------------ messages

    pub fn add_message(&self, s: &mut Session, text: &[u8]) -> Res<Item> {
        if text.is_empty() {
            return Err("message is empty".into());
        }
        if text.len() > MSG_CAP {
            return Err("message is too long".into());
        }
        let id = self.new_id(s);
        let size = self.write_blob(s, &id, &mut &text[..])?;
        self.commit_item(s, Item { id, kind: Kind::Msg, created: unix_now(), size, name: String::new() })
    }

    /// Decrypt a message into locked memory, then destroy it on disk *before* returning it, so
    /// "gone forever" holds even if the app is killed while the message is on screen. If the
    /// on-disk copy cannot be destroyed, nothing is revealed.
    pub fn open_and_destroy_message(&self, s: &mut Session, id: &[u8; 16]) -> Res<SecretInput> {
        if s.get(id).map(|i| i.kind) != Some(Kind::Msg) {
            return Err("no such message".into());
        }
        let (mut r, dek) = self.open_blob(s, id)?;
        let mut out = SecretInput::new(MSG_CAP);
        crypto::decrypt_stream(&mut r, &mut out, dek.as_bytes(), id)?;
        drop(r);
        self.purge(s, id).map_err(|e| format!("could not destroy the stored message ({e}); not shown"))?;
        Ok(out)
    }

    // ------------------------------------------------------------ panic wipe

    /// Destroy the whole vault folder: header first (it holds the only wraps of the master key),
    /// then every other file. Returns the number of files that could not be erased.
    /// The platform layer deletes the Secure Enclave key and Keychain items before calling this.
    pub fn destroy_all(&self) -> usize {
        let mut failed = 0;
        let hdr = self.p("vault.hdr");
        if hdr.exists() && wipe::shred(&hdr).is_err() {
            failed += 1;
        }
        let mut stack = vec![self.dir.clone()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                match e.file_type() {
                    Ok(t) if t.is_dir() => stack.push(p),
                    Ok(t) if t.is_file() => {
                        if wipe::shred(&p).is_err() {
                            failed += 1;
                        }
                    }
                    _ => {
                        let _ = fs::remove_file(&p);
                    }
                }
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
        if self.dir.exists() && failed == 0 {
            failed = 1;
        }
        failed
    }

    // ------------------------------------------------------------ purge

    pub fn purge(&self, s: &mut Session, id: &[u8; 16]) -> Res<()> {
        let path = self.blob_path(id);
        if path.exists() {
            wipe::shred(&path)?;
        }
        s.items.retain(|i| &i.id != id);
        self.save_index(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scytale-ios-test-{n}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn pepper() -> (Secret32, Vec<u8>) {
        (Secret32::from_slice(&[0x42; 32]), b"wrapped-by-secure-enclave".to_vec())
    }

    fn setup(n: &str) -> (Vault, Session, PathBuf, Secret32) {
        let d = tmpdir(n);
        let v = Vault::new(d.join("vault"));
        let rk = Secret32::random();
        let (p, w) = pepper();
        let mk = v.create(b"correct horse battery", &[9u8; 20], &rk, &p, &w).unwrap();
        let mut s = Session::new(Secret32::from_slice(mk.as_bytes()));
        v.load_index(&mut s).unwrap();
        (v, s, d, rk)
    }

    #[test]
    fn login_needs_password_and_pepper() {
        let (v, s, d, rk) = setup("login");
        let (p, w) = pepper();
        assert_eq!(v.wrapped_pepper().unwrap(), w);
        assert!(v.unlock(b"wrong password", Some(&p)).is_none());
        assert!(v.unlock(b"correct horse battery", None).is_none(), "Face ID refused -> no unlock");
        assert!(v.unlock(b"correct horse battery", Some(&Secret32::from_slice(&[1; 32]))).is_none());
        let mk = v.unlock(b"correct horse battery", Some(&p)).unwrap();
        assert_eq!(mk.as_bytes(), s.mk.as_bytes());
        assert_eq!(&v.totp_secret(&mk).unwrap()[..], &[9u8; 20]);
        assert!(v.unlock_recovery(&Secret32::random()).is_none());
        assert_eq!(v.unlock_recovery(&rk).unwrap().as_bytes(), mk.as_bytes());

        // password change with a fresh pepper (new Secure Enclave wrap)
        let p2 = Secret32::from_slice(&[0x77; 32]);
        v.rewrite_header(&mk, b"a brand new passphrase", &p2, b"wrap-2", None, None).unwrap();
        assert!(v.unlock(b"correct horse battery", Some(&p)).is_none());
        assert!(v.unlock(b"a brand new passphrase", Some(&p)).is_none(), "old pepper must not work");
        assert!(v.unlock(b"a brand new passphrase", Some(&p2)).is_some());
        assert_eq!(v.wrapped_pepper().unwrap(), b"wrap-2");
        assert!(v.unlock_recovery(&rk).is_some());

        // recovery: new rk + new totp
        let rk2 = Secret32::random();
        v.rewrite_header(&mk, b"third passphrase here", &p2, b"wrap-3", Some(&rk2), Some(&[5u8; 20])).unwrap();
        assert!(v.unlock_recovery(&rk).is_none());
        assert!(v.unlock_recovery(&rk2).is_some());
        assert_eq!(&v.totp_secret(&mk).unwrap()[..], &[5u8; 20]);

        // header tamper: flip a salt byte -> password wrap no longer authenticates
        let hp = v.dir.join("vault.hdr");
        let mut b = fs::read(&hp).unwrap();
        b[20] ^= 1;
        fs::write(&hp, b).unwrap();
        assert!(v.unlock(b"third passphrase here", Some(&p2)).is_none());
        // tamper with the stored wrapped pepper -> also rejected (it is bound as AAD)
        let mut b = fs::read(&hp).unwrap();
        b[20] ^= 1;
        b[37] ^= 1;
        fs::write(&hp, b).unwrap();
        assert!(v.unlock(b"third passphrase here", Some(&p2)).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn file_roundtrip_erases_original() {
        let (v, mut s, d, _) = setup("file");
        let src = d.join("secret report.bin");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        fs::write(&src, &data).unwrap();
        let (item, warn) = v.add_file(&mut s, &src, true).unwrap();
        assert!(warn.is_none());
        assert!(!src.exists(), "original must be gone");
        assert_eq!(item.name, "secret report.bin");
        assert_eq!(item.size, data.len() as u64);

        let blob = fs::read(v.blob_path(&item.id)).unwrap();
        assert!(!blob.windows(16).any(|w| w == &data[1000..1016]));
        let idx = fs::read(v.p("index.scy")).unwrap();
        assert!(!idx.windows(6).any(|w| w == b"secret"));

        let view = v.open_file(&s, &item).unwrap();
        assert_eq!(view.as_bytes(), &data[..]);

        let mut s2 = Session::new(Secret32::from_slice(s.mk.as_bytes()));
        v.load_index(&mut s2).unwrap();
        assert_eq!(s2.items.len(), 1);
        assert_eq!(s2.get(&item.id).unwrap().name, "secret report.bin");

        let bp = v.blob_path(&item.id);
        let mut bytes = fs::read(&bp).unwrap();
        let n = bytes.len() / 2;
        bytes[n] ^= 1;
        fs::write(&bp, bytes).unwrap();
        assert!(v.open_file(&s, &item).is_err(), "tampered blob must not open");

        v.purge(&mut s, &item.id).unwrap();
        assert!(!bp.exists());
        assert!(s.items.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn stream_import_keeps_source_and_counts_size() {
        let (v, mut s, d, _) = setup("stream");
        let photo: Vec<u8> = (0..150_000u32).map(|i| (i * 7 % 255) as u8).collect();
        let item = v.add_stream(&mut s, "IMG_0001.heic", &mut &photo[..]).unwrap();
        assert_eq!(item.size, photo.len() as u64);
        assert_eq!(v.open_file(&s, &item).unwrap().as_bytes(), &photo[..]);
        assert!(v.add_stream(&mut s, "", &mut &photo[..]).is_err());

        let src = d.join("keep.txt");
        fs::write(&src, b"keep me").unwrap();
        let (_, warn) = v.add_file(&mut s, &src, false).unwrap();
        assert!(warn.is_none());
        assert!(src.exists(), "original kept when not asked to erase");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn message_is_single_use() {
        let (v, mut s, d, _) = setup("msg");
        let item = v.add_message(&mut s, "meet at 9 — the code is 4417".as_bytes()).unwrap();
        let bp = v.blob_path(&item.id);
        assert!(bp.exists());
        let m = v.open_and_destroy_message(&mut s, &item.id).unwrap();
        assert_eq!(m.as_str(), "meet at 9 — the code is 4417");
        assert!(!bp.exists(), "ciphertext must be gone once opened");
        assert!(s.items.is_empty());
        assert!(v.open_and_destroy_message(&mut s, &item.id).is_err());
        let mut s2 = Session::new(Secret32::from_slice(s.mk.as_bytes()));
        v.load_index(&mut s2).unwrap();
        assert!(s2.items.is_empty());

        // a file can never be "read once" (and destroyed) through the message path
        let f = v.add_stream(&mut s, "a.txt", &mut &b"x"[..]).unwrap();
        assert!(v.open_and_destroy_message(&mut s, &f.id).is_err());
        assert!(v.blob_path(&f.id).exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn panic_wipe_destroys_everything() {
        let (v, mut s, d, rk) = setup("wipe");
        v.add_message(&mut s, b"one").unwrap();
        v.add_stream(&mut s, "x.bin", &mut &b"data"[..]).unwrap();
        crate::audit::Store::create(&v.dir, Secret32::random()).unwrap().log("SETUP", 0).unwrap();
        assert_eq!(v.destroy_all(), 0);
        assert!(!v.dir.exists());
        let (p, _) = pepper();
        assert!(v.unlock(b"correct horse battery", Some(&p)).is_none());
        assert!(v.unlock_recovery(&rk).is_none());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn reconcile_shreds_orphans() {
        let (v, mut s, d, _) = setup("orphan");
        let orphan = v.blobs().join("00112233445566778899aabbccddeeff.scy");
        fs::write(&orphan, b"junk").unwrap();
        let part = v.blobs().join("deadbeef.part");
        fs::write(&part, b"junk").unwrap();
        let (dropped, shredded) = v.load_index(&mut s).unwrap();
        assert_eq!((dropped, shredded), (0, 2));
        assert!(!orphan.exists() && !part.exists());

        let item = v.add_message(&mut s, b"keep me").unwrap();
        let ip = v.p("index.scy");
        let mut b = fs::read(&ip).unwrap();
        let n = b.len() - 3;
        b[n] ^= 1;
        fs::write(&ip, b).unwrap();
        let mut s2 = Session::new(Secret32::from_slice(s.mk.as_bytes()));
        assert!(v.load_index(&mut s2).is_err());
        assert!(v.blob_path(&item.id).exists());
        let _ = fs::remove_dir_all(&d);
    }
}
