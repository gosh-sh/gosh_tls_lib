use std::fmt;
use std::io;

/// Errors surfaced by the public TLS API.
///
/// `Display` strings are intentionally generic and do not include attacker-supplied
/// data (record bytes, hostnames, exact failure point, etc.) so they are safe to
/// log at debug level without leaking key material or chain contents (F-13).
#[derive(Debug)]
pub enum TlsError {
    /// The peer certificate chain failed validation.
    CertificateValidationFailed,
    /// A TLS record (or piece of a record) could not be parsed.
    MalformedRecord,
    /// AEAD authentication failed (bad tag, replay, or active tampering).
    AeadAuthFailed,
    /// The peer used a TLS algorithm we do not support.
    UnsupportedAlgorithm,
    /// Peer certificate did not match the hostname we asked for (F-09).
    HostnameMismatch,
    /// X25519 peer key produced an all-zero shared secret (F-07).
    InvalidPeerPublicKey,
    /// The domain argument could not be parsed or resolved.
    InvalidDomain,
    /// Underlying I/O failure on the TCP socket.
    Io(io::Error),
    /// Catch-all for legacy call sites that still surface a string.
    Other(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::CertificateValidationFailed => f.write_str("certificate validation failed"),
            TlsError::MalformedRecord => f.write_str("malformed TLS record"),
            TlsError::AeadAuthFailed => f.write_str("AEAD authentication failed"),
            TlsError::UnsupportedAlgorithm => f.write_str("unsupported TLS algorithm"),
            TlsError::HostnameMismatch => f.write_str("peer certificate does not match hostname"),
            TlsError::InvalidPeerPublicKey => f.write_str("peer public key rejected"),
            TlsError::InvalidDomain => f.write_str("invalid domain"),
            TlsError::Io(_) => f.write_str("I/O error"),
            TlsError::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TlsError {
    fn from(e: io::Error) -> Self {
        TlsError::Io(e)
    }
}
