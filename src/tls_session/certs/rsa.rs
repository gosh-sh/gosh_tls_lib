use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::Zero;

use crate::tls_session::hkdf_sha256;
use crate::tls_session::sha512;

// F-05: pluggable hash for PSS. RSA-PSS verifiers must honour the hash
// algorithm declared by the certificate's signature algorithm OID (SHA-256
// for PSS-SHA256, SHA-384 for PSS-SHA384, SHA-512 for PSS-SHA512). Previously
// the inner hash was hard-wired to SHA-256, which silently mis-validates
// SHA-384/SHA-512 PSS certificates.
#[derive(Clone)]
enum PssHash {
    Sha256(hkdf_sha256::Digest),
    Sha384(sha512::Digest),
    Sha512(sha512::Digest),
}

impl PssHash {
    fn new(hash_len_in_bits: usize) -> Option<PssHash> {
        match hash_len_in_bits {
            256 => Some(PssHash::Sha256(hkdf_sha256::Digest::new())),
            384 => Some(PssHash::Sha384(sha512::Digest::new384())),
            512 => Some(PssHash::Sha512(sha512::Digest::new512())),
            _ => None,
        }
    }

    fn output_size(&self) -> usize {
        match self {
            PssHash::Sha256(_) => 32,
            PssHash::Sha384(_) => 48,
            PssHash::Sha512(_) => 64,
        }
    }

    fn write(&mut self, data: &[u8]) {
        match self {
            PssHash::Sha256(d) => {
                d.write(data);
            }
            PssHash::Sha384(d) | PssHash::Sha512(d) => {
                d.write(data);
            }
        }
    }

    fn sum(&self) -> Vec<u8> {
        match self {
            PssHash::Sha256(d) => d.sum(&[]),
            PssHash::Sha384(d) | PssHash::Sha512(d) => d.sum(&[]),
        }
    }

    fn reset(&mut self) {
        match self {
            PssHash::Sha256(d) => d.reset(),
            PssHash::Sha384(d) | PssHash::Sha512(d) => d.reset(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    pub n: BigInt, // modulus
    pub e: i64,    // public exponent
}

impl PublicKey {
    pub fn size(&self) -> usize {
        ((self.n.bits() as usize) + 7) / 8
    }

    // F-11: constant-time equality on public-key material. RSA public keys
    // are not secret, so today there is no leak — but pinned PublicKey::equal
    // sits next to authenticator-comparison sites and should default to CT to
    // avoid regression hazards.
    pub fn equal(&self, other: &PublicKey) -> bool {
        use subtle::ConstantTimeEq;
        let a_n = self.n.to_signed_bytes_be();
        let b_n = other.n.to_signed_bytes_be();
        let n_eq: bool = a_n.ct_eq(&b_n).into();
        let e_eq: bool = self.e.to_be_bytes().ct_eq(&other.e.to_be_bytes()).into();
        n_eq & e_eq
    }
}

#[derive(Debug)]
pub struct OAEPOptions {
    hash: String,     // Placeholder for crypto hash type
    mgf_hash: String, // Placeholder for MGF hash type
    label: Vec<u8>,
}

// pub fn check_pub(pub_key: &PublicKey) -> Result<(), Box<dyn Error>> {
pub fn check_pub(pub_key: &PublicKey) -> bool {
    if pub_key.n.is_zero() {
        return false; //return Err(Box::new(PublicModulusError));
    }
    if pub_key.e < 2 {
        return false; //return Err(Box::new(PublicExponentSmallError));
    }
    if pub_key.e > ((1u64 << 31) - 1) as i64 {
        return false; //return Err(Box::new(PublicExponentLargeError));
    }
    true //Ok(())
}

// F-05: zero-pad to the modulus byte length. `BigUint::to_bytes_be` strips
// leading zeros, which is wrong for RSA encoded-message buffers — callers
// assume a fixed-size em of (em_bits + 7) / 8 (or k for PKCS#1 v1.5) and
// index into it. Without padding, small m^e mod n values yield em.len() <
// expected_len and slice indexing panics.
fn encrypt(pubkey: &PublicKey, plaintext: &[u8], em_len: usize) -> Vec<u8> {
    let base = BigUint::from_bytes_be(&plaintext);
    let modulus = match pubkey.n.to_biguint() {
        Some(m) => m,
        None => return vec![0u8; em_len],
    };
    let exponent = match BigInt::from(pubkey.e.clone()).to_biguint() {
        Some(e) => e,
        None => return vec![0u8; em_len],
    };

    let result = base.modpow(&exponent, &modulus).to_bytes_be();

    if result.len() >= em_len {
        result[result.len() - em_len..].to_vec()
    } else {
        let mut padded = vec![0u8; em_len - result.len()];
        padded.extend_from_slice(&result);
        padded
    }
}

pub fn verify_pkcs1v15(pub_key: &PublicKey, hash: usize, hashed: &[u8], sig: &[u8]) -> bool {
    let (hash_len, prefix_opt) = pkcs1v15_hash_info(hash, hashed.len());
    let prefix = match prefix_opt {
        Some(p) => p,
        None => return false,
    };
    let t_len = prefix.len() + hash_len / 8;
    let k = pub_key.size();

    if k < t_len + 11 {
        return false;
    }

    if k != sig.len() {
        return false;
    }

    let em = encrypt(pub_key, sig, k);

    // PKCS#1 v1.5 EMSA encoded message layout (RFC 8017 §9.2):
    //   EM = 0x00 || 0x01 || PS || 0x00 || T
    // where T = DigestInfo (prefix || hashed). encrypt() now zero-pads to k,
    // so em[0] is the literal 0x00 prefix byte (previously to_bytes_be stripped
    // it, and the indices below were skewed by one to compensate).
    let mut ok = em[0] == 0x00;
    ok &= em[1] == 0x01;
    ok &= &em[k - hash_len / 8..k] == hashed;
    ok &= &em[k - t_len..k - hash_len / 8] == &prefix[..];
    ok &= em[k - t_len - 1] == 0x00;
    for i in 2..(k - t_len - 1) {
        ok &= em[i] == 0xff;
    }

    if !ok {
        return false;
    }

    true
}

fn pkcs1v15_hash_info(hash: usize, in_len: usize) -> (usize, Option<Vec<u8>>) {
    if hash == 0 {
        return (in_len, None);
    }
    if in_len != hash / 8 {
        // F-03: malformed cert can hit this path; signal failure to the caller
        // instead of crashing the process.
        return (0, None);
    }
    let prefix = get_hash_prefix(hash);
    (hash, prefix)
}

// fn get_hash_prefix(hash: usize) -> Result<Vec<u8>, Box<dyn Error>> {
fn get_hash_prefix(hash: usize) -> Option<Vec<u8>> {
    match hash {
        224 => {
            // SHA224
            Some(vec![
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x04, 0x05, 0x00, 0x04, 0x1c,
            ])
        }
        256 => {
            // SHA256
            Some(vec![
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ])
        }
        384 => {
            // SHA384
            Some(vec![
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ])
        }
        512 => {
            // SHA512
            Some(vec![
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ])
        }
        _ => None, // Err("unsupported hash function".into()),
    }
}

// PSS_SALT_LENGTH_AUTO causes the salt in a PSS signature to be as large
// as possible when signing, and to be auto-detected when verifying.
pub const PSS_SALT_LENGTH_AUTO: isize = 0;

// PSS_SALT_LENGTH_EQUALS_HASH causes the salt length to equal the length
// of the hash used in the signature.
pub const PSS_SALT_LENGTH_EQUALS_HASH: isize = -1;

// PSSOptions contains options for creating and verifying PSS signatures.
pub struct PSSOptions {
    // salt_length controls the length of the salt used in the PSS signature. It
    // can either be a positive number of bytes, or one of the special
    // PSSSaltLength constants.
    pub salt_length: isize,

    // Hash is the hash function used to generate the message digest. If not
    // zero, it overrides the hash function passed to SignPSS. It's required
    // when using PrivateKey.Sign.
    pub hash: usize,
}

// verify_pss verifies a PSS signature.
//
// A valid signature is indicated by returning a nil error. digest must be the
// result of hashing the input message using the given hash function. The opts
// argument may be nil, in which case sensible defaults are used. opts.Hash is
// ignored.
pub fn verify_pss(
    pub_key: &PublicKey,
    hash: usize,
    digest: &[u8],
    sig: &[u8],
    opts: &PSSOptions,
) -> bool {
    if sig.len() != pub_key.size() {
        return false;
    }

    if opts.salt_length < PSS_SALT_LENGTH_EQUALS_HASH {
        return false;
    }
    // F-05: pick the hash that matches the certificate's PSS signature
    // algorithm. SHA-256 / SHA-384 / SHA-512 are the only valid choices
    // for TLS 1.3 RSA-PSS.
    let hasher = match PssHash::new(hash) {
        Some(h) => h,
        None => return false,
    };
    let em_bits = (pub_key.n.bits() as usize) - 1;
    let em_len = (em_bits + 7) / 8;
    // F-05: encode at em_len exactly. encrypt() now zero-pads internally,
    // so the obsolete "strip leading zeros" loop is gone.
    let em = encrypt(pub_key, sig, em_len);

    return emsa_pss_verify(digest, &em, em_bits, opts.salt_length, hasher);
}

fn emsa_pss_verify(
    m_hash: &[u8],
    em: &[u8],
    em_bits: usize,
    mut s_len: isize,
    mut hasher: PssHash,
) -> bool {
    let h_len = hasher.output_size() as isize;
    if s_len == PSS_SALT_LENGTH_EQUALS_HASH {
        s_len = h_len;
    }
    let em_len = (em_bits + 7) / 8;

    if em_len != em.len() {
        return false;
    }

    // 1.  If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
    //     and stop.
    //
    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    if h_len != m_hash.len() as isize {
        return false; // ErrVerification
    }

    let h_len = h_len as usize;
    let mut s_len = s_len as usize;

    // 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    if em_len < h_len + s_len + 2 {
        return false; // ErrVerification
    }

    // 4.  If the rightmost octet of EM does not have hexadecimal value
    //     0xbc, output "inconsistent" and stop.
    if em[em_len - 1] != 0xbc {
        return false; // ErrVerification
    }

    // 5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
    //     let H be the next hLen octets.
    let mut db: Vec<u8> = Vec::from(&em[..em_len - h_len - 1]);
    let h = &em[em_len - h_len - 1..em_len - 1];

    // 6.  If the leftmost 8 * emLen - emBits bits of the leftmost octet in
    //     maskedDB are not all equal to zero, output "inconsistent" and
    //     stop.
    let bit_mask: u8 = 0xff >> (8 * em_len - em_bits);
    if em[0] & !bit_mask != 0 {
        return false; // ErrVerification
    }

    // 7.  Let dbMask = MGF(H, emLen - hLen - 1).
    // 8.  Let DB = maskedDB \xor dbMask.
    mgf1_xor(&mut db, &mut hasher, &h);

    // 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    db[0] &= bit_mask;

    // If we don't know the salt length, look for the 0x01 delimiter.
    if s_len == PSS_SALT_LENGTH_AUTO as usize {
        //let ps_len = bytes.IndexByte(db, 0x01);
        let mut ps_len: isize = -1;
        for i in 0..db.len() {
            if db[i] == 0x01 {
                ps_len = i as isize;
                break;
            }
        }

        if ps_len < 0 {
            return false; // ErrVerification
        }
        s_len = db.len() - (ps_len as usize) - 1;
    }

    // 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
    //     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
    //     position is "position 1") does not have hexadecimal value 0x01,
    //     output "inconsistent" and stop.
    let ps_len = em_len - h_len - s_len - 2;
    for i in 0..ps_len {
        // for _, e := range db[:psLen] {
        if db[i] != 0x00 {
            return false; // ErrVerification
        }
    }
    if db[ps_len] != 0x01 {
        return false; // ErrVerification
    }

    // 11.  Let salt be the last sLen octets of DB.
    let salt = &db[db.len() - s_len..];

    // 12. M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
    // 13. Let H' = Hash(M').
    // mgf1_xor used the same hasher above; reset before computing H'.
    hasher.reset();
    let prefix = [0u8; 8];
    hasher.write(&prefix);
    hasher.write(m_hash);
    hasher.write(&salt);
    let h0 = hasher.sum();

    if h0 != h {
        return false;
    }
    return true;
}

// F-05: MGF1 uses the *same* hash as the PSS message hash. The hasher passed
// in here is mutated (write/reset) per RFC 8017 Appendix B.2.1.
fn mgf1_xor(out: &mut [u8], hash: &mut PssHash, seed: &[u8]) {
    let mut counter: [u8; 4] = [0; 4];
    let mut done = 0;

    while done < out.len() {
        hash.write(seed);
        hash.write(&counter);
        let digest = hash.sum();
        hash.reset();

        for i in 0..digest.len() {
            if done < out.len() {
                out[done] ^= digest[i];
                done += 1;
            } else {
                break;
            }
        }
        inc_counter(&mut counter);
    }
}

fn inc_counter(counter: &mut [u8; 4]) {
    if counter[3].wrapping_add(1) != 0 {
        counter[3] += 1;
        return;
    }
    if counter[2].wrapping_add(1) != 0 {
        counter[2] += 1;
        return;
    }
    if counter[1].wrapping_add(1) != 0 {
        counter[1] += 1;
        return;
    }
    counter[0] += 1;
}
