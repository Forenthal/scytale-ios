//! Courier: sealed messages between paired Scytale devices (PC <-> iPhone), carried by email as a
//! file or a text block that only the paired Scytale can open.
//!
//! Construction (every layer hybrid, so breaking one primitive is not enough):
//! - Identity per device: X25519 + Ed25519 + ML-DSA-65 (FIPS 204), created inside the vault.
//! - Pairing: each device exports a *key bundle* (identity public keys + one-time prekeys, each
//!   prekey = X25519 + ML-KEM-768 (FIPS 203)), signed with both Ed25519 and ML-DSA-65. The users
//!   compare a 60-digit safety number on both screens before the peer is trusted.
//! - Message: ephemeral X25519 against the prekey's X25519 key, plus ML-KEM-768 encapsulation to
//!   the prekey's KEM key. HKDF-SHA-512 over both shared secrets and the full header gives the
//!   AES-256-GCM key. The whole envelope is signed with both signature schemes and verified before
//!   anything is decrypted.
//! - Forward secrecy: every message consumes one prekey, whose private half the recipient deletes
//!   the moment the message opens. Every copy left in email is then undecryptable by anyone.
//! - The sender's rules (destroy-on-receipt) and a message id are sealed inside the ciphertext.
//!   Replays are refused. Plaintext is padded to fixed sizes so length is not revealed.

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit as _, Payload},
    Aes256Gcm,
};
use data_encoding::BASE64;
use ed25519_dalek::Signer as _;
use hkdf::Hkdf;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, Keypair as _, MlDsa65, SigningKey, VerifyingKey};
use ml_kem::{Decapsulate as _, Encapsulate as _, KeyExport as _, MlKem768};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::random_bytes;

const CTX: &[u8] = b"scytale/courier/v1";
const BUNDLE_MAGIC: &[u8; 5] = b"SCYK\x01";
const MSG_MAGIC: &[u8; 5] = b"SCYM\x01";
const STATE_MAGIC: &[u8; 5] = b"SCYC\x01";

pub const X_LEN: usize = 32;
#[allow(dead_code)]
pub const ED_LEN: usize = 32;
pub const ED_SIG: usize = 64;
pub const DSA_PK: usize = 1952;
pub const DSA_SIG: usize = 3309;
pub const KEM_EK: usize = 1184;
pub const KEM_CT: usize = 1088;
const HYBRID_SIG: usize = ED_SIG + DSA_SIG;

/// Unused own prekeys kept available after each bundle export.
pub const PREKEY_BATCH: usize = 100;
const OWN_PREKEY_CAP: usize = 500;
const CONSUMED_CAP: usize = 4096;
pub const TEXT_CAP: usize = 16 * 1024;
/// Plaintext (header + text + padding) is padded up to one of these sizes.
const BUCKETS: [usize; 3] = [1024, 4096, 17 * 1024];

pub type Res<T> = Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not a Scytale courier object, truncated, or wrong version.
    Malformed = 1,
    /// A signature did not verify (forged, altered, or from another device).
    BadSignature = 2,
    /// The message was not sent by the paired device, or not to this device.
    UnknownSender = 3,
    /// The paired device has not been verified with the safety number yet.
    NotVerified = 4,
    /// No paired device.
    NotPaired = 5,
    /// Its one-time key is gone: already opened, or never issued by this device.
    AlreadyOpened = 6,
    /// Decryption failed (tampered or corrupt).
    Decrypt = 7,
    /// No one-time keys left from the peer: a new key bundle is needed.
    NoPrekeys = 8,
    /// Message empty or larger than 16 KiB.
    TooLong = 9,
    /// A different device is already paired; unpair first.
    DifferentPeer = 10,
    /// The bundle is this device's own.
    OwnBundle = 11,
}

// ---------------------------------------------------------------- keys

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecret {
    x: [u8; 32],
    ed: [u8; 32],
    dsa: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityPublic {
    pub x: [u8; 32],
    pub ed: [u8; 32],
    pub dsa: Vec<u8>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrekeySecret {
    id: u32,
    x: [u8; 32],
    kem: [u8; 64],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrekeyPublic {
    pub id: u32,
    pub x: [u8; 32],
    pub kem: Vec<u8>,
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    random_bytes(&mut b);
    b
}

impl IdentitySecret {
    pub fn generate() -> Self {
        IdentitySecret { x: rand32(), ed: rand32(), dsa: rand32() }
    }

    fn dsa_seed(&self) -> ml_dsa::B32 {
        ml_dsa::B32::from(self.dsa)
    }

    pub fn public(&self) -> IdentityPublic {
        let x = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.x)).to_bytes();
        let ed = ed25519_dalek::SigningKey::from_bytes(&self.ed).verifying_key().to_bytes();
        let dsa = SigningKey::<MlDsa65>::from_seed(&self.dsa_seed()).verifying_key().encode().to_vec();
        IdentityPublic { x, ed, dsa }
    }

    /// Ed25519 signature || ML-DSA-65 signature (hedged: fresh randomness per signature).
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIG);
        let ed = ed25519_dalek::SigningKey::from_bytes(&self.ed);
        out.extend_from_slice(&ed.sign(msg).to_bytes());
        let esk = ExpandedSigningKey::<MlDsa65>::from_seed(&self.dsa_seed());
        let mut rnd = ml_dsa::B32::from(rand32());
        // FIPS 204 Algorithm 2 (hedged): M' = 0 || |ctx| || ctx || M
        let header = [0u8, CTX.len() as u8];
        let sig = esk.sign_internal(&[&header, CTX, msg], &rnd);
        rnd.zeroize();
        out.extend_from_slice(&sig.encode());
        out
    }
}

impl IdentityPublic {
    fn encode(&self, v: &mut Vec<u8>) {
        v.extend_from_slice(&self.x);
        v.extend_from_slice(&self.ed);
        v.extend_from_slice(&self.dsa);
    }

    fn decode(r: &mut Reader) -> Res<Self> {
        Ok(IdentityPublic { x: r.arr()?, ed: r.arr()?, dsa: r.take(DSA_PK)?.to_vec() })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"scytale/courier/id");
        h.update(self.x);
        h.update(self.ed);
        h.update(&self.dsa);
        h.finalize().into()
    }

    /// Both signatures must verify.
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != HYBRID_SIG {
            return false;
        }
        let (ed_sig, dsa_sig) = sig.split_at(ED_SIG);
        let ed_ok = ed25519_dalek::VerifyingKey::from_bytes(&self.ed)
            .ok()
            .zip(<[u8; ED_SIG]>::try_from(ed_sig).ok())
            .is_some_and(|(vk, s)| vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&s)).is_ok());
        let dsa_ok = EncodedVerifyingKey::<MlDsa65>::try_from(&self.dsa[..])
            .ok()
            .map(|e| VerifyingKey::<MlDsa65>::decode(&e))
            .zip(EncodedSignature::<MlDsa65>::try_from(dsa_sig).ok().and_then(|e| ml_dsa::Signature::decode(&e)))
            .is_some_and(|(vk, s)| vk.verify_with_context(msg, CTX, &s));
        ed_ok & dsa_ok
    }
}

impl PrekeySecret {
    fn generate(id: u32) -> Self {
        let mut kem = [0u8; 64];
        random_bytes(&mut kem);
        PrekeySecret { id, x: rand32(), kem }
    }

    fn kem_key(&self) -> ml_kem::DecapsulationKey<MlKem768> {
        ml_kem::DecapsulationKey::<MlKem768>::from_seed(ml_kem::Seed::from(self.kem))
    }

    fn public(&self) -> PrekeyPublic {
        let x = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(self.x)).to_bytes();
        let kem = self.kem_key().encapsulation_key().to_bytes().to_vec();
        PrekeyPublic { id: self.id, x, kem }
    }
}

// ---------------------------------------------------------------- byte reader

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let s = self.b.get(self.pos..self.pos.checked_add(n).ok_or(Error::Malformed)?).ok_or(Error::Malformed)?;
        self.pos += n;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Res<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn u16(&mut self) -> Res<u16> {
        Ok(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    fn rest(&self) -> &'a [u8] {
        &self.b[self.pos..]
    }
    fn done(&self) -> bool {
        self.pos == self.b.len()
    }
}

// ---------------------------------------------------------------- armor

const BUNDLE_ARMOR: &str = "SCYTALE KEY BUNDLE";
const MSG_ARMOR: &str = "SCYTALE MESSAGE";

pub fn armor(kind: &str, bytes: &[u8]) -> String {
    let b64 = BASE64.encode(bytes);
    let mut s = format!("-----BEGIN {kind}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str(&format!("-----END {kind}-----\n"));
    s
}

/// Accepts the raw binary file, or the armored text (with or without surrounding email text).
pub fn unarmor(input: &[u8], kind: &str, magic: &[u8]) -> Res<Vec<u8>> {
    if input.starts_with(magic) {
        return Ok(input.to_vec());
    }
    let text = std::str::from_utf8(input).map_err(|_| Error::Malformed)?;
    let begin = format!("-----BEGIN {kind}-----");
    let end = format!("-----END {kind}-----");
    let start = text.find(&begin).ok_or(Error::Malformed)? + begin.len();
    let stop = text[start..].find(&end).ok_or(Error::Malformed)? + start;
    let b64: String = text[start..stop].chars().filter(|c| !c.is_whitespace() && *c != '>').collect();
    BASE64.decode(b64.as_bytes()).map_err(|_| Error::Malformed)
}

// ---------------------------------------------------------------- bundle

#[allow(dead_code)]
pub struct Bundle {
    pub identity: IdentityPublic,
    pub created: u64,
    pub prekeys: Vec<PrekeyPublic>,
}

fn bundle_bytes(id: &IdentitySecret, created: u64, prekeys: &[PrekeyPublic]) -> Vec<u8> {
    let mut v = BUNDLE_MAGIC.to_vec();
    id.public().encode(&mut v);
    v.extend_from_slice(&created.to_le_bytes());
    v.extend_from_slice(&(prekeys.len() as u16).to_le_bytes());
    for p in prekeys {
        v.extend_from_slice(&p.id.to_le_bytes());
        v.extend_from_slice(&p.x);
        v.extend_from_slice(&p.kem);
    }
    let sig = id.sign(&v);
    v.extend_from_slice(&sig);
    v
}

pub fn parse_bundle(input: &[u8]) -> Res<Bundle> {
    let raw = unarmor(input, BUNDLE_ARMOR, BUNDLE_MAGIC)?;
    if raw.len() < HYBRID_SIG + BUNDLE_MAGIC.len() || &raw[..5] != BUNDLE_MAGIC {
        return Err(Error::Malformed);
    }
    let (body, sig) = raw.split_at(raw.len() - HYBRID_SIG);
    let mut r = Reader::new(body);
    r.take(5)?;
    let identity = IdentityPublic::decode(&mut r)?;
    let created = r.u64()?;
    let n = r.u16()? as usize;
    let mut prekeys = Vec::with_capacity(n);
    for _ in 0..n {
        prekeys.push(PrekeyPublic { id: r.u32()?, x: r.arr()?, kem: r.take(KEM_EK)?.to_vec() });
    }
    if !r.done() {
        return Err(Error::Malformed);
    }
    if !identity.verify(body, sig) {
        return Err(Error::BadSignature);
    }
    Ok(Bundle { identity, created, prekeys })
}

/// 60 digits (12 groups of 5), identical on both devices: the order of the two fingerprints does
/// not matter. Comparing it in person proves no key was swapped in transit.
pub fn safety_number(a: &IdentityPublic, b: &IdentityPublic) -> String {
    let (fa, fb) = (a.fingerprint(), b.fingerprint());
    let (lo, hi) = if fa <= fb { (fa, fb) } else { (fb, fa) };
    let mut h = Sha512::new();
    h.update(b"scytale/courier/safety");
    h.update(lo);
    h.update(hi);
    let d = h.finalize();
    let mut out = String::new();
    for i in 0..12 {
        let chunk = u64::from_le_bytes(d[i * 5..i * 5 + 8].try_into().unwrap()) % 100_000;
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{chunk:05}"));
    }
    out
}

// ---------------------------------------------------------------- state

pub struct Peer {
    pub identity: IdentityPublic,
    pub verified: bool,
    pub prekeys: Vec<PrekeyPublic>,
}

/// Everything the courier keeps, stored sealed inside the vault.
#[derive(Default)]
pub struct State {
    identity: Option<IdentitySecret>,
    own_prekeys: Vec<PrekeySecret>,
    next_prekey: u32,
    pub peer: Option<Peer>,
    consumed: Vec<[u8; 16]>,
}

#[allow(dead_code)]
pub struct Received {
    pub text: Zeroizing<Vec<u8>>,
    pub burn: bool,
    pub created: u64,
}

impl State {
    fn identity(&mut self) -> &IdentitySecret {
        self.identity.get_or_insert_with(IdentitySecret::generate)
    }

    pub fn own_public(&mut self) -> IdentityPublic {
        self.identity().public()
    }

    /// One-time keys the peer can still use (from the last bundle imported).
    pub fn peer_prekeys_left(&self) -> usize {
        self.peer.as_ref().map_or(0, |p| p.prekeys.len())
    }

    pub fn own_prekeys_unused(&self) -> usize {
        self.own_prekeys.len()
    }

    /// Top the own one-time keys up to `PREKEY_BATCH` and export a signed bundle with all of them.
    pub fn export_bundle(&mut self, now: u64) -> String {
        self.identity();
        while self.own_prekeys.len() < PREKEY_BATCH {
            self.next_prekey = self.next_prekey.wrapping_add(1).max(1);
            let p = PrekeySecret::generate(self.next_prekey);
            self.own_prekeys.push(p);
        }
        if self.own_prekeys.len() > OWN_PREKEY_CAP {
            let extra = self.own_prekeys.len() - OWN_PREKEY_CAP;
            self.own_prekeys.drain(..extra);
        }
        let pubs: Vec<PrekeyPublic> = self.own_prekeys.iter().map(PrekeySecret::public).collect();
        let bytes = bundle_bytes(self.identity.as_ref().unwrap(), now, &pubs);
        armor(BUNDLE_ARMOR, &bytes)
    }

    /// Import the peer's bundle. A first import pairs (unverified until the safety numbers are
    /// compared); later bundles from the same device add fresh one-time keys.
    pub fn import_bundle(&mut self, input: &[u8]) -> Res<String> {
        let b = parse_bundle(input)?;
        let own = self.own_public();
        if b.identity == own {
            return Err(Error::OwnBundle);
        }
        match self.peer.as_mut() {
            Some(p) if p.identity != b.identity => return Err(Error::DifferentPeer),
            Some(p) => {
                for k in b.prekeys {
                    if !p.prekeys.iter().any(|q| q.id == k.id) {
                        p.prekeys.push(k);
                    }
                }
            }
            None => self.peer = Some(Peer { identity: b.identity.clone(), verified: false, prekeys: b.prekeys }),
        }
        Ok(safety_number(&own, &b.identity))
    }

    pub fn safety_number(&mut self) -> Option<String> {
        let own = self.own_public();
        self.peer.as_ref().map(|p| safety_number(&own, &p.identity))
    }

    pub fn verify_peer(&mut self) -> bool {
        match self.peer.as_mut() {
            Some(p) => {
                p.verified = true;
                true
            }
            None => false,
        }
    }

    pub fn unpair(&mut self) {
        self.peer = None;
    }

    /// Seal `text` for the paired device. Consumes one of its one-time keys; the caller must
    /// persist the state before releasing the envelope.
    pub fn seal(&mut self, text: &[u8], burn: bool, now: u64) -> Res<Vec<u8>> {
        if text.is_empty() || text.len() > TEXT_CAP {
            return Err(Error::TooLong);
        }
        let own = self.own_public();
        let peer = self.peer.as_mut().ok_or(Error::NotPaired)?;
        if !peer.verified {
            return Err(Error::NotVerified);
        }
        if peer.prekeys.is_empty() {
            return Err(Error::NoPrekeys);
        }
        let pk = peer.prekeys.remove(0);
        let recipient_fp = peer.identity.fingerprint();

        // classical part: ephemeral X25519
        let eph = x25519_dalek::StaticSecret::from(rand32());
        let eph_pub = x25519_dalek::PublicKey::from(&eph).to_bytes();
        let dh = eph.diffie_hellman(&x25519_dalek::PublicKey::from(pk.x));
        if !dh.was_contributory() {
            return Err(Error::Malformed);
        }
        // post-quantum part: ML-KEM-768
        let ek_bytes = ml_kem::Key::<ml_kem::EncapsulationKey<MlKem768>>::try_from(&pk.kem[..]).map_err(|_| Error::Malformed)?;
        let ek = ml_kem::EncapsulationKey::<MlKem768>::new(&ek_bytes).map_err(|_| Error::Malformed)?;
        let (kem_ct, kem_ss) = ek.encapsulate();

        let mut nonce = [0u8; 12];
        random_bytes(&mut nonce);
        let mut header = MSG_MAGIC.to_vec();
        header.extend_from_slice(&own.fingerprint());
        header.extend_from_slice(&recipient_fp);
        header.extend_from_slice(&pk.id.to_le_bytes());
        header.extend_from_slice(&eph_pub);
        header.extend_from_slice(&kem_ct);
        header.extend_from_slice(&nonce);

        let key = message_key(dh.as_bytes(), &kem_ss, &header);

        let mut msg_id = [0u8; 16];
        random_bytes(&mut msg_id);
        let plain = pad_payload(text, burn, &msg_id, now);
        let ct = Aes256Gcm::new(GenericArray::from_slice(&key[..]))
            .encrypt(GenericArray::from_slice(&nonce), Payload { msg: &plain, aad: &header })
            .map_err(|_| Error::Decrypt)?;

        let mut env = header;
        env.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        env.extend_from_slice(&ct);
        let sig = self.identity.as_ref().unwrap().sign(&env);
        env.extend_from_slice(&sig);
        Ok(env)
    }

    /// Verify, decrypt and consume a message from the paired device. The one-time key is deleted
    /// and the message id recorded before the text is returned; the caller must persist the
    /// state before showing it.
    pub fn open(&mut self, input: &[u8]) -> Res<Received> {
        let env = unarmor(input, MSG_ARMOR, MSG_MAGIC)?;
        let fixed = 5 + 32 + 32 + 4 + X_LEN + KEM_CT + 12;
        if env.len() < fixed + 4 + HYBRID_SIG || &env[..5] != MSG_MAGIC {
            return Err(Error::Malformed);
        }
        let (body, sig) = env.split_at(env.len() - HYBRID_SIG);
        let mut r = Reader::new(body);
        r.take(5)?;
        let sender_fp: [u8; 32] = r.arr()?;
        let recipient_fp: [u8; 32] = r.arr()?;
        let prekey_id = r.u32()?;
        let eph_pub: [u8; 32] = r.arr()?;
        let kem_ct = r.take(KEM_CT)?;
        let nonce: [u8; 12] = r.arr()?;
        let header = &body[..r.pos];
        let ct_len = r.u32()? as usize;
        let ct = r.take(ct_len)?;
        if !r.done() {
            return Err(Error::Malformed);
        }

        let own = self.own_public();
        let peer = self.peer.as_ref().ok_or(Error::NotPaired)?;
        if sender_fp != peer.identity.fingerprint() || recipient_fp != own.fingerprint() {
            return Err(Error::UnknownSender);
        }
        if !peer.verified {
            return Err(Error::NotVerified);
        }
        if !peer.identity.verify(body, sig) {
            return Err(Error::BadSignature);
        }
        let idx = self.own_prekeys.iter().position(|p| p.id == prekey_id).ok_or(Error::AlreadyOpened)?;

        let pk = &self.own_prekeys[idx];
        let dh = x25519_dalek::StaticSecret::from(pk.x).diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
        if !dh.was_contributory() {
            return Err(Error::Decrypt);
        }
        let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct).map_err(|_| Error::Malformed)?;
        let kem_ss = pk.kem_key().decapsulate(&ct_arr);
        let key = message_key(dh.as_bytes(), &kem_ss, header);
        let plain = Zeroizing::new(
            Aes256Gcm::new(GenericArray::from_slice(&key[..]))
                .decrypt(GenericArray::from_slice(&nonce), Payload { msg: ct, aad: header })
                .map_err(|_| Error::Decrypt)?,
        );
        let (text, burn, msg_id, created) = unpad_payload(&plain)?;
        if self.consumed.contains(&msg_id) {
            return Err(Error::AlreadyOpened);
        }
        // Forward secrecy: the one-time key is destroyed now; no copy of this message can ever be
        // decrypted again.
        self.own_prekeys.remove(idx);
        self.consumed.push(msg_id);
        if self.consumed.len() > CONSUMED_CAP {
            self.consumed.remove(0);
        }
        Ok(Received { text, burn, created })
    }

    // ---- persistence (sealed by the caller with a vault-derived key)

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(STATE_MAGIC.to_vec());
        match &self.identity {
            Some(i) => {
                v.push(1);
                v.extend_from_slice(&i.x);
                v.extend_from_slice(&i.ed);
                v.extend_from_slice(&i.dsa);
            }
            None => v.push(0),
        }
        v.extend_from_slice(&self.next_prekey.to_le_bytes());
        v.extend_from_slice(&(self.own_prekeys.len() as u32).to_le_bytes());
        for p in &self.own_prekeys {
            v.extend_from_slice(&p.id.to_le_bytes());
            v.extend_from_slice(&p.x);
            v.extend_from_slice(&p.kem);
        }
        match &self.peer {
            Some(p) => {
                v.push(1);
                p.identity.encode(&mut v);
                v.push(u8::from(p.verified));
                v.extend_from_slice(&(p.prekeys.len() as u32).to_le_bytes());
                for k in &p.prekeys {
                    v.extend_from_slice(&k.id.to_le_bytes());
                    v.extend_from_slice(&k.x);
                    v.extend_from_slice(&k.kem);
                }
            }
            None => v.push(0),
        }
        v.extend_from_slice(&(self.consumed.len() as u32).to_le_bytes());
        for c in &self.consumed {
            v.extend_from_slice(c);
        }
        v
    }

    pub fn from_bytes(b: &[u8]) -> Res<State> {
        let mut r = Reader::new(b);
        if r.take(5)? != STATE_MAGIC {
            return Err(Error::Malformed);
        }
        let mut s = State::default();
        if r.take(1)?[0] == 1 {
            s.identity = Some(IdentitySecret { x: r.arr()?, ed: r.arr()?, dsa: r.arr()? });
        }
        s.next_prekey = r.u32()?;
        let n = r.u32()? as usize;
        if n > OWN_PREKEY_CAP {
            return Err(Error::Malformed);
        }
        for _ in 0..n {
            s.own_prekeys.push(PrekeySecret { id: r.u32()?, x: r.arr()?, kem: r.arr()? });
        }
        if r.take(1)?[0] == 1 {
            let identity = IdentityPublic::decode(&mut r)?;
            let verified = r.take(1)?[0] == 1;
            let n = r.u32()? as usize;
            let mut prekeys = Vec::new();
            for _ in 0..n {
                prekeys.push(PrekeyPublic { id: r.u32()?, x: r.arr()?, kem: r.take(KEM_EK)?.to_vec() });
            }
            s.peer = Some(Peer { identity, verified, prekeys });
        }
        let n = r.u32()? as usize;
        for _ in 0..n.min(CONSUMED_CAP) {
            s.consumed.push(r.arr()?);
        }
        if !r.done() {
            return Err(Error::Malformed);
        }
        Ok(s)
    }
}

pub fn armor_message(env: &[u8]) -> String {
    armor(MSG_ARMOR, env)
}

/// HKDF-SHA-512 over both shared secrets, bound to the whole header.
fn message_key(dh: &[u8; 32], kem: &[u8], header: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(dh);
    ikm.extend_from_slice(kem);
    let info = Sha512::digest(header);
    let hk = Hkdf::<Sha512>::new(Some(CTX), &ikm);
    let mut k = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut k[..]).expect("hkdf length");
    k
}

/// version | flags | msg id | created | text length | text | zero padding to a bucket size.
fn pad_payload(text: &[u8], burn: bool, id: &[u8; 16], now: u64) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::new());
    v.push(1);
    v.push(u8::from(burn));
    v.extend_from_slice(id);
    v.extend_from_slice(&now.to_le_bytes());
    v.extend_from_slice(&(text.len() as u32).to_le_bytes());
    v.extend_from_slice(text);
    let target = BUCKETS.iter().copied().find(|&b| b >= v.len()).unwrap_or(v.len());
    v.resize(target, 0);
    v
}

fn unpad_payload(p: &[u8]) -> Res<(Zeroizing<Vec<u8>>, bool, [u8; 16], u64)> {
    let mut r = Reader::new(p);
    if r.take(1)?[0] != 1 {
        return Err(Error::Malformed);
    }
    let flags = r.take(1)?[0];
    let id: [u8; 16] = r.arr()?;
    let created = r.u64()?;
    let n = r.u32()? as usize;
    if n > TEXT_CAP {
        return Err(Error::Malformed);
    }
    let text = Zeroizing::new(r.take(n)?.to_vec());
    if r.rest().iter().any(|&b| b != 0) {
        return Err(Error::Malformed);
    }
    Ok((text, flags & 1 == 1, id, created))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two devices paired the proper way: bundles exchanged, safety numbers compared.
    fn paired() -> (State, State) {
        let (mut pc, mut phone) = (State::default(), State::default());
        let b_pc = pc.export_bundle(1);
        let b_phone = phone.export_bundle(1);
        let n1 = phone.import_bundle(b_pc.as_bytes()).unwrap();
        let n2 = pc.import_bundle(b_phone.as_bytes()).unwrap();
        assert_eq!(n1, n2, "both screens show the same safety number");
        assert_eq!(n1.split(' ').count(), 12);
        assert!(pc.verify_peer() && phone.verify_peer());
        (pc, phone)
    }

    #[test]
    fn round_trip_both_directions_and_forward_secrecy() {
        let (mut pc, mut phone) = paired();
        let env = pc.seal(b"meet at 9, code 4417", true, 1000).unwrap();
        let armored = armor_message(&env);
        assert!(armored.starts_with("-----BEGIN SCYTALE MESSAGE-----"));
        // pasted out of an email, quoted with '>' and surrounded by other text
        let quoted: String = format!("Hi,\n\n{}\nthanks", armored.lines().map(|l| format!("> {l}\n")).collect::<String>());
        let got = phone.open(quoted.as_bytes()).unwrap();
        assert_eq!(&got.text[..], b"meet at 9, code 4417");
        assert!(got.burn);
        assert_eq!(got.created, 1000);
        // the one-time key is gone: the same message (any copy) can never be opened again
        assert_eq!(phone.open(&env).err(), Some(Error::AlreadyOpened));
        // the other direction, raw file form, keep flag
        let back = phone.seal(b"received", false, 2000).unwrap();
        let r = pc.open(&back).unwrap();
        assert_eq!(&r.text[..], b"received");
        assert!(!r.burn);
        assert_eq!(pc.peer_prekeys_left(), PREKEY_BATCH - 1);
        assert_eq!(phone.own_prekeys_unused(), PREKEY_BATCH - 1);
    }

    #[test]
    fn tampering_and_strangers_are_rejected() {
        let (mut pc, mut phone) = paired();
        let env = pc.seal(b"secret", false, 1).unwrap();
        // flip one bit anywhere: header, ciphertext or signature
        for i in [3usize, 40, 80, 200, env.len() / 2, env.len() - 5] {
            let mut bad = env.clone();
            bad[i] ^= 1;
            assert!(phone.open(&bad).is_err(), "bit {i}");
        }
        assert!(phone.open(&env).is_ok(), "the untouched envelope still opens");

        // a third device that obtained the phone's bundle (e.g. from the email) cannot send as the PC
        let mut mallory = State::default();
        mallory.import_bundle(phone.export_bundle(5).as_bytes()).unwrap();
        mallory.verify_peer();
        let forged = mallory.seal(b"I am your PC", false, 1).unwrap();
        assert_eq!(phone.open(&forged).err(), Some(Error::UnknownSender));
        // and a bundle from a different device cannot replace the paired one
        assert_eq!(phone.import_bundle(mallory.export_bundle(1).as_bytes()).err(), Some(Error::DifferentPeer));
        // a modified bundle fails its signature
        let mut b = unarmor(pc.export_bundle(2).as_bytes(), BUNDLE_ARMOR, BUNDLE_MAGIC).unwrap();
        b[100] ^= 1;
        assert_eq!(phone.import_bundle(&b).err(), Some(Error::BadSignature));
    }

    #[test]
    fn unverified_peer_cannot_send_or_receive() {
        let (mut a, mut b) = (State::default(), State::default());
        a.import_bundle(b.export_bundle(1).as_bytes()).unwrap();
        b.import_bundle(a.export_bundle(1).as_bytes()).unwrap();
        assert_eq!(a.seal(b"x", false, 1).err(), Some(Error::NotVerified));
        b.verify_peer();
        let env = b.seal(b"x", false, 1).unwrap();
        assert_eq!(a.open(&env).err(), Some(Error::NotVerified));
    }

    #[test]
    fn prekeys_run_out_then_refill_and_state_round_trips() {
        let (mut pc, mut phone) = paired();
        for i in 0..PREKEY_BATCH {
            let env = pc.seal(format!("m{i}").as_bytes(), true, 1).unwrap();
            phone.open(&env).unwrap();
        }
        assert_eq!(pc.seal(b"one more", true, 1).err(), Some(Error::NoPrekeys), "no weaker fallback");
        // refill by a new signed bundle; still verified, same identity
        pc.import_bundle(phone.export_bundle(9).as_bytes()).unwrap();
        assert_eq!(pc.peer_prekeys_left(), PREKEY_BATCH);
        // persist and restore both sides mid-conversation
        let env = pc.seal(b"after restore", false, 1).unwrap();
        let mut pc2 = State::from_bytes(&pc.to_bytes()).unwrap();
        let mut phone2 = State::from_bytes(&phone.to_bytes()).unwrap();
        assert_eq!(&phone2.open(&env).unwrap().text[..], b"after restore");
        let reply = phone2.seal(b"ok", false, 1).unwrap();
        assert_eq!(&pc2.open(&reply).unwrap().text[..], b"ok");
        assert!(State::from_bytes(&pc.to_bytes()[..50]).is_err());
    }

    /// A bundle exported on Windows, carried by email, opened on the phone: CRLF line endings,
    /// a leading byte-order mark, quoting and surrounding text must not matter. A message is
    /// not accepted as a bundle, nor a bundle as a message.
    #[test]
    fn bundles_survive_email_and_kinds_are_not_confused() {
        let mut pc = State::default();
        let mut phone = State::default();
        let bundle = pc.export_bundle(1);
        let crlf = format!("\u{feff}{}", bundle.replace('\n', "\r\n"));
        let quoted: String = format!("Fwd:\r\n{}\r\n-- \r\nsent from my PC", crlf.lines().map(|l| format!("> {l}\r\n")).collect::<String>());
        let n = phone.import_bundle(quoted.as_bytes()).unwrap();
        assert_eq!(n, phone.safety_number().unwrap());
        // raw binary form too
        let raw = unarmor(bundle.as_bytes(), BUNDLE_ARMOR, BUNDLE_MAGIC).unwrap();
        assert!(phone.import_bundle(&raw).is_ok());

        let (mut a, mut b) = paired();
        let env = a.seal(b"hello", false, 1).unwrap();
        assert_eq!(b.import_bundle(armor_message(&env).as_bytes()).err(), Some(Error::Malformed));
        assert_eq!(b.open(a.export_bundle(2).as_bytes()).err(), Some(Error::Malformed));
    }

    #[test]
    fn padding_hides_length() {
        let (mut pc, _) = paired();
        let a = pc.seal(b"x", false, 1).unwrap();
        let b = pc.seal(&[b'y'; 900], false, 1).unwrap();
        assert_eq!(a.len(), b.len(), "1 byte and 900 bytes look the same");
        assert!(pc.seal(&vec![0u8; TEXT_CAP + 1], false, 1).is_err());
        assert!(pc.seal(b"", false, 1).is_err());
    }
}
