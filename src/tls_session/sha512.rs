// F-15.7: hand-rolled SHA-384/SHA-512 (originally ~600 lines including dead
// SHA-224/256 paths and marshal_binary/unmarshal_binary plumbing) replaced
// with thin wrappers over `sha2`. Public surface kept identical so call
// sites do not change.

use sha2::Digest as _;
use sha2::Sha384;
use sha2::Sha512;

/// One-shot SHA-384. Output is 48 bytes.
pub fn sum384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().into()
}

/// One-shot SHA-512. Output is 64 bytes.
pub fn sum512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
}

/// Stateful SHA-384 / SHA-512 hasher exposing the legacy API used by the PSS
/// verifier (write / sum / reset). The `kind` discriminates the two algorithms
/// so PssHash in rsa.rs can keep a single enum variant per hash.
#[derive(Clone)]
pub struct Digest {
    kind: Kind,
    state: State,
}

#[derive(Clone, Copy)]
enum Kind {
    Sha384,
    Sha512,
}

#[derive(Clone)]
enum State {
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Digest {
    pub fn new384() -> Digest {
        Digest { kind: Kind::Sha384, state: State::Sha384(Sha384::new()) }
    }

    pub fn new512() -> Digest {
        Digest { kind: Kind::Sha512, state: State::Sha512(Sha512::new()) }
    }

    pub fn write(&mut self, p: &[u8]) -> usize {
        match &mut self.state {
            State::Sha384(h) => h.update(p),
            State::Sha512(h) => h.update(p),
        }
        p.len()
    }

    pub fn sum(&self, _in_bytes: &[u8]) -> Vec<u8> {
        // sha2 finalize consumes the hasher; clone to preserve sum-without-reset semantics.
        match &self.state {
            State::Sha384(h) => h.clone().finalize().to_vec(),
            State::Sha512(h) => h.clone().finalize().to_vec(),
        }
    }

    pub fn reset(&mut self) {
        self.state = match self.kind {
            Kind::Sha384 => State::Sha384(Sha384::new()),
            Kind::Sha512 => State::Sha512(Sha512::new()),
        };
    }
}
