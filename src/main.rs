extern crate core;

pub mod tls_session;
pub mod format;
pub mod network;
pub mod tls_connect;

use num_bigint::BigInt;
use tls_session::Session;
use tls_connect::*;

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

fn main_() {
    //https://www.facebook.com/.well-known/oauth/openid/jwks/
    let domain = "www.facebook.com";
    let jwk_get_request = "GET /.well-known/oauth/openid/jwks/ HTTP/1.1\r\nHost: ";

    //https://kauth.kakao.com/.well-known/jwks.json
    //let domain = "kauth.kakao.com";
    //let jwk_get_request =  "GET /.well-known/jwks.json HTTP/1.1\r\nHost: ";

    //https://www.googleapis.com/oauth2/v3/certs
    //let domain = "www.googleapis.com";
    //let jwk_get_request = "GET /oauth2/v3/certs HTTP/1.1\r\nHost: ";

    let tls_session = get_jwk_tls_data(domain, jwk_get_request).unwrap();

    println!("TLS session data in hex: {:?}", tls_session.1);
    println!("root cert serial number: {:?}", tls_session.0);

    println!("root certs map: {:?}", get_root_certs_map(domain).unwrap());

    let tls_session_hex =  tls_session.1;
    let mut tls_session_bytes = hex::decode(tls_session_hex.clone()).unwrap();

    //println!("tls_session_hex: {:?}", tls_session_hex);

    /*let root_cert = tls_session::get_root_cert_google_g2();
    let mut len_of_root_cert = vec![5u8, 91u8];

    let mut data: Vec<u8> = Vec::new();
    data.append(&mut len_of_root_cert);
    data.append(&mut root_cert.to_vec());

    println!("cert 2: {:?}", hex::encode(data));*/

   /* let root_cert = tls_session::get_root_cert_google_g4();
    let mut len_of_root_cert = vec![2u8, 13u8];

    let mut data: Vec<u8> = Vec::new();
    data.append(&mut len_of_root_cert);
    data.append(&mut root_cert.to_vec());

    println!("cert 4: {:?}", hex::encode(data));*/

    let current_timestamp = 1000u32;// SystemTime::now()
    let mut data: Vec<u8> = Vec::new();
    append_uint32(&mut data, current_timestamp);
    println!("tls_session_bytes is : {:?}", tls_session_bytes);

    //let mut kid = hex::decode("b509c5138768f7cf2e827e04b27e7e4cbc7bb919").unwrap();
    let mut kid = hex::decode("d87d2474896f213ee52e6069ae0dd1553340a08c").unwrap();
    //let mut kid = hex::decode("9f252dadd5f233f93d2fa528d12fea").unwrap();
    println!("kid is : {:?}", kid);
    let mut root_cert = match domain {
        "www.googleapis.com" => tls_session::get_root_cert_google_g1().to_vec(),
        "kauth.kakao.com" => tls_session::get_root_cert_kakao().to_vec(),
        _ => tls_session::get_root_cert_facebook().to_vec(),
    };

    let mut len_of_root_cert = format::u16_to_bytes(root_cert.len() as u16).to_vec();
    println!("len_of_root_cert is : {:?}", len_of_root_cert);
    data.push(kid.len() as u8);
    data.append(&mut kid);
    data.append(&mut len_of_root_cert);
    data.append(&mut root_cert);

    println!("data is : {:?}", data);
    data.append(&mut tls_session_bytes);

    println!("THE data is : {:?}", data);
    let public_key_data = tls_session::extract_json_public_key_from_tls(data);

    println!("jwk public_key_data is : {:?}", public_key_data);
    println!("jwk public_key_data hex is : {:?}", hex::encode(public_key_data));
    
}

