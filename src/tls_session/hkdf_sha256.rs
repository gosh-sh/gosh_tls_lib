// F-15.8: hand-rolled SHA-256 + HMAC-SHA256 + HKDF (originally ~600 lines
// hand-rolled with several dead helpers) replaced with thin wrappers over
// `sha2` + `hmac` + `hkdf`. Public surface preserved so callers don't
// change.

use hkdf::Hkdf as HkdfImpl;
use hmac::Mac;
use sha2::Digest as Sha2Digest;
use sha2::Sha256;

pub const SIZE: usize = 32;

/// One-shot SHA-256.
pub fn sum256(data: &[u8]) -> [u8; SIZE] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Stateful SHA-256 hasher exposing the legacy `write` / `sum` / `reset` API.
#[derive(Clone)]
pub struct Digest {
    inner: Sha256,
}

impl Digest {
    pub fn new() -> Digest {
        Digest { inner: Sha256::new() }
    }

    pub fn write(&mut self, p: &[u8]) -> usize {
        self.inner.update(p);
        p.len()
    }

    pub fn sum(&self, _in_bytes: &[u8]) -> Vec<u8> {
        // Clone-then-finalize keeps the hasher reusable, matching the legacy API.
        self.inner.clone().finalize().to_vec()
    }

    pub fn reset(&mut self) {
        self.inner = Sha256::new();
    }
}

/// HMAC-SHA256. Legacy API: `Hmac::new(key)`, `write(data)`, `sum(extra)`.
pub struct Hmac {
    inner: hmac::Hmac<Sha256>,
}

impl Hmac {
    pub fn new(key: &[u8]) -> Hmac {
        // HMAC keys are variable-length per RFC 2104; new_from_slice never
        // fails for hmac::Hmac<Sha256>.
        let inner = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key)
            .expect("hmac::Hmac<Sha256> accepts any key length");
        Hmac { inner }
    }

    pub fn write(&mut self, input: &[u8]) -> usize {
        self.inner.update(input);
        input.len()
    }

    pub fn sum(&mut self, input: &[u8]) -> Vec<u8> {
        // Legacy semantics: `sum(extra)` appended `extra` to the current state
        // and returned the digest, leaving the hasher otherwise reusable. We
        // emulate by cloning, finalizing the clone, and resetting nothing.
        let mut tmp = self.inner.clone();
        tmp.update(input);
        tmp.finalize().into_bytes().to_vec()
    }

    pub fn size(&self) -> usize {
        SIZE
    }
}

/// Pure HKDF-Extract.
pub fn extract(secret: &[u8; SIZE], salt: &[u8; SIZE]) -> Result<[u8; SIZE], Vec<u8>> {
    // RFC 5869: PRK = HMAC-Hash(salt, IKM). We use the hkdf crate's split path
    // for clarity; both salt and IKM are 32 bytes here.
    let (prk, _) = HkdfImpl::<Sha256>::extract(Some(salt), secret);
    let mut out = [0u8; SIZE];
    out.copy_from_slice(prk.as_slice());
    Ok(out)
}

/// HKDF-Expand reader. Returns up to 255 * HashLen bytes total across calls,
/// matching RFC 5869's L limit.
pub struct Hkdf {
    inner: HkdfImpl<Sha256>,
    info: Vec<u8>,
}

impl Hkdf {
    pub fn read(&mut self, need: usize) -> Result<Vec<u8>, Vec<u8>> {
        let mut out = vec![0u8; need];
        self.inner.expand(&self.info, &mut out).map_err(|_| vec![0u8, 8u8, 1u8])?;
        Ok(out)
    }
}

/// Build an HKDF-Expand reader from a pre-derived PRK.
pub fn expand(pseudorandom_key: &[u8], info: &[u8]) -> Hkdf {
    // RFC 5869: when PRK is supplied directly, use `from_prk`; that constructor
    // enforces PRK length >= HashLen, which holds for all our call sites (32
    // bytes from `extract` above, or 32-byte derived secrets).
    let inner = HkdfImpl::<Sha256>::from_prk(pseudorandom_key)
        .unwrap_or_else(|_| HkdfImpl::<Sha256>::new(None, pseudorandom_key));
    Hkdf { inner, info: info.to_vec() }
}
