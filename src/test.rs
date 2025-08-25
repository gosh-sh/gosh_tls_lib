extern crate core;
use crate::tls_connect::get_jwk_tls_data;
use crate::tls_session;

use std::io::{self, Write, BufRead, Read};
use std::net::TcpStream;
use std::fs::File;
use num_traits::Num;

use hex::FromHex;

fn deserialize_from_hex_str(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
    Vec::from_hex(data)
}

fn append_uint32(b: &mut Vec<u8>, v: u32) {
    b.push((v >> 24) as u8);
    b.push((v >> 16) as u8);
    b.push((v >> 8) as u8);
    b.push(v as u8);
}

#[test]
fn test() {
    //https://www.facebook.com/.well-known/oauth/openid/jwks/
    //let domain = "www.facebook.com";
    //let jwk_get_request = "GET /.well-known/oauth/openid/jwks/ HTTP/1.1\r\nHost: ";

    //https://kauth.kakao.com/.well-known/jwks.json
    //let domain = "kauth.kakao.com";
    //let jwk_get_request =  "GET /.well-known/jwks.json HTTP/1.1\r\nHost: ";

    //https://www.googleapis.com/oauth2/v3/certs
    let domain = "www.googleapis.com";
    //let jwk_get_request = "GET /oauth2/v3/certs HTTP/1.1\r\nHost: ";

    let jwk_get_request = match domain {
        "www.googleapis.com" => "GET /oauth2/v3/certs HTTP/1.1\r\nHost: ",
        "kauth.kakao.com" => "GET /.well-known/jwks.json HTTP/1.1\r\nHost: ",
        _ => "GET /.well-known/oauth/openid/jwks/ HTTP/1.1\r\nHost: ", // facebook
    };

    let tls_session = get_jwk_tls_data(domain, jwk_get_request).unwrap();

    println!("TLS session data in hex: {:?}", tls_session.1);
    println!("root cert serial number: {:?}", tls_session.0);

    let tls_session_hex =  tls_session.1;
    let mut tls_session_bytes = hex::decode(tls_session_hex.clone()).unwrap();

    //println!("tls_session_hex: {:?}", tls_session_hex);

    let current_timestamp = 1000u32;// SystemTime::now()
    let mut data: Vec<u8> = Vec::new();
    append_uint32(&mut data, current_timestamp);
    println!("tls_session_bytes is : {:?}", tls_session_bytes);

    let mut kid = hex::decode("1499c154ccc8a25e24d8de8b1a9f845aefb6f3ca").unwrap();
    //let mut kid = hex::decode("9f252dadd5f233f93d2fa528d12fea").unwrap();
    //let mut kid = hex::decode("3f96980381e451efad0d2ddd30e3d3").unwrap();
    println!("kid is : {:?}", kid);
    let mut len_and_root_cert = match domain {
        "www.googleapis.com" => tls_session::get_root_cert_google_g1().to_vec(),
        "kauth.kakao.com" => tls_session::get_root_cert_kakao().to_vec(),
        _ => tls_session::get_root_cert_facebook().to_vec(),
    };

    data.push(kid.len() as u8);
    data.append(&mut kid);
    data.append(&mut len_and_root_cert);

    println!("data is : {:?}", data);
    data.append(&mut tls_session_bytes);

    println!("THE data is : {:?}", data);
    let public_key_data = tls_session::extract_json_public_key_from_tls(data);

    println!("jwk public_key_data is : {:?}", public_key_data);
    println!("jwk public_key_data hex is : {:?}", hex::encode(public_key_data));
    
}

