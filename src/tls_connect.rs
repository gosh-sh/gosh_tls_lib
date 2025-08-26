use std::collections::HashMap;

use crate::tls_session::*;
//use hex::*;

pub fn get_root_certs_map(domain: &str) -> Result<HashMap<String, String>, String> {
    get_root_certs_map_(domain)
}

pub fn get_jwk_tls_data(domain: &str, get_request: &str) -> Result<(String, String), String> {
    let mut session = match Session::new(String::from(domain)) {
        Ok(session) => session,
        Err(_) => return Err("Failed to connect to domain".to_string()),
    };
    session.connect();
    let req_ = format!("{}\r\nConnection: close\r\n\r\n", domain);
    let req = format!("{}{}", get_request, req_);
    println!("req.as_bytes() is : {:?}", req);
    session.send_data(req.as_bytes());
    println!("SendData done");

    let ticket = session.receive_data();
    //println!("ticket is : {:?}", ticket);
    println!("ReceiveData done");
    let resp = session.receive_http_response(); // let resp = session.receive_http_response().expect("Failed to receive HTTP response")
    println!("ReceiveHTTPResponse done");
    let serialized_session = session.serialize();
    Ok((session.root_cert_sn, hex::encode(serialized_session)))
}
