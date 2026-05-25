// F-07 strategic: hand-rolled curve25519 donna port (~700 lines of adapted
// reference-implementation arithmetic) replaced with a thin wrapper over the
// audited, constant-time `x25519-dalek` crate.
//
// Public surface is preserved (`BASE_POINT`, `curve25519_donna`) so callers
// don't change. `curve25519_donna` returns `Err(...)` when the result is the
// all-zero shared secret, matching RFC 7748 §6.1's small-subgroup rejection.
// (We keep the same check on the call site in `make_handshake_keys` as
// defence-in-depth — that's the F-07 we already shipped.)

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

/// X25519 base point (u = 9), encoded little-endian.
pub const BASE_POINT: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Compute scalar * basepoint on Curve25519, returning the 32-byte u-coordinate.
///
/// The error path encodes one specific condition: the result is the all-zero
/// point, which signals the peer sent a small-subgroup public key (RFC 7748
/// §6.1). Other malformed inputs aren't possible — scalars and u-coordinates
/// are fixed-size byte arrays.
pub fn curve25519_donna(secret: &[u8; 32], basepoint: &[u8; 32]) -> Result<[u8; 32], Vec<u8>> {
    // dalek's StaticSecret applies RFC 7748 clamping (bits 0..2 cleared, bit
    // 254 set, bit 255 cleared) on construction, so the hand-rolled
    //     e[0] &= 248; e[31] &= 127; e[31] |= 64;
    // from the donna port is now implicit.
    let scalar = StaticSecret::from(*secret);
    let point = PublicKey::from(*basepoint);
    let shared = scalar.diffie_hellman(&point);
    let bytes = shared.to_bytes();

    if bytes == [0u8; 32] {
        // RFC 7748 §6.1 small-subgroup point — dalek does NOT reject this for
        // us, only the upstream consumer can decide. We surface it as Err so
        // the existing F-07 check in tls_session.rs catches it.
        return Err(vec![0u8, 4u8, 1u8]);
    }

    Ok(bytes)
}
