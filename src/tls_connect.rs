use std::collections::HashMap;

use crate::error::TlsError;
use crate::tls_session::*;

// F-13: the public API now returns TlsError. Callers can match on the failure
// category (CertificateValidationFailed, MalformedRecord, AeadAuthFailed, …)
// instead of parsing free-form strings.
pub fn get_root_certs_map(domain: &str) -> Result<HashMap<String, String>, TlsError> {
    get_root_certs_map_(domain).map_err(|_| TlsError::InvalidDomain)
}

pub fn get_jwk_tls_data(domain: &str, get_request: &str) -> Result<(String, String), TlsError> {
    let mut session = Session::new(String::from(domain))?;
    session.connect()?;
    let req_ = format!("{}\r\nConnection: close\r\n\r\n", domain);
    let req = format!("{}{}", get_request, req_);
    session.send_data(req.as_bytes())?;

    let _ticket = session.receive_data()?;
    let _resp = session.receive_http_response()?;
    let serialized_session = session.serialize();
    Ok((session.root_cert_sn, hex::encode(serialized_session)))
}
