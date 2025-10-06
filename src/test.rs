use chrono::Utc;
use hex::FromHex;

use crate::format;
use crate::tls_connect::get_jwk_tls_data;
//use crate::tls_session::Session;
use crate::tls_connect::*;
use crate::tls_session;

fn deserialize_from_hex_str(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
    Vec::from_hex(data)
}

fn append_uint32(b: &mut Vec<u8>, v: u32) {
    b.push((v >> 24) as u8);
    b.push((v >> 16) as u8);
    b.push((v >> 8) as u8);
    b.push(v as u8);
}

struct ProviderData<'a> {
    domain: &'a str,
    jwk_get_request: &'a str,
    issuer: &'a str,
    issuer_decoded: &'a str,
    index_mod_4: u8,
    kid: Vec<u8>,
    root_cert: Vec<u8>,
}

impl ProviderData<'_> {
    pub fn get_google() -> Self {
        //https://www.googleapis.com/oauth2/v3/certs
        //let domain = "www.googleapis.com";
        //let jwk_get_request = "GET /oauth2/v3/certs HTTP/1.1\r\nHost: ";
        let google_kid: Vec<u8> = hex::decode("c8ab71530972bba20b49f78a09c9852c43ff9118").unwrap();
        //let google_root_cert: Vec<u8> = tls_session::get_root_cert_google_g4().to_vec();
        let google_root_cert: Vec<u8> = tls_session::get_root_cert_google_g1().to_vec();
        ProviderData {
            domain: "www.googleapis.com",
            jwk_get_request: "GET /oauth2/v3/certs HTTP/1.1\r\nHost: ",
            issuer: "yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC",
            issuer_decoded: "676f6f676c65", //"794a7063334d694f694a6f64485277637a6f764c32466a59323931626e527a4c6d6476623264735a53356a623230694c43", // "https://accounts.google.com",
            index_mod_4: 1,
            kid: google_kid,
            root_cert: google_root_cert,
        }
    }

    pub fn get_kakao() -> Self {
        //https://kauth.kakao.com/.well-known/jwks.json
        //let domain = "kauth.kakao.com";
        //let jwk_get_request =  "GET /.well-known/jwks.json HTTP/1.1\r\nHost: ";
        let kakao_kid: Vec<u8> = hex::decode("3f96980381e451efad0d2ddd30e3d3").unwrap();
        let kakao_root_cert: Vec<u8> = tls_session::get_root_cert_kakao().to_vec();
        ProviderData {
            domain: "kauth.kakao.com",
            jwk_get_request: "GET /.well-known/jwks.json HTTP/1.1\r\nHost: ",
            issuer: "ImlzcyI6Imh0dHBzOi8va2F1dGgua2FrYW8uY29tIiw", //
            issuer_decoded: "6b616b616f", //"496d6c7a63794936496d68306448427a4f6938766132463164476775613246725957387559323974496977", //"https://kauth.kakao.com",
            index_mod_4: 0,
            kid: kakao_kid,
            root_cert: kakao_root_cert,
        }
    }

    pub fn get_facebook() -> Self {
        // https://www.facebook.com/.well-known/oauth/openid/jwks/
        // let domain = "www.facebook.com";
        // let jwk_get_request = "GET /.well-known/oauth/openid/jwks/ HTTP/1.1\r\nHost: ";
        let facebook_kid: Vec<u8> =
            hex::decode("e4f6715b789895089f5c26d53b01a2991ed2772b").unwrap();
        let facebook_root_cert: Vec<u8> = tls_session::get_root_cert_facebook_2().to_vec();
        ProviderData {
            domain: "www.facebook.com",
            jwk_get_request: "GET /.well-known/oauth/openid/jwks/ HTTP/1.1\r\nHost: ",
            issuer: "yJpc3MiOiJodHRwczpcL1wvd3d3LmZhY2Vib29rLmNvbSIs", //
            issuer_decoded: "66616365626f6f6b", //"794a7063334d694f694a6f64485277637a70634c317776643364334c6d5a6859325669623239724c6d4e7662534973", // "https://www.facebook.com",
            index_mod_4: 1,
            kid: facebook_kid,
            root_cert: facebook_root_cert,
        }
    }
}

#[test]
fn main_test() {
    //let p = ProviderData::get_google();
    //let p = ProviderData::get_kakao();
    let p = ProviderData::get_facebook();
    let tls_session = get_jwk_tls_data(&p.domain, &p.jwk_get_request).unwrap();

    println!("TLS session data in hex: {:?}", tls_session.1);
    println!("root cert serial number: {:?}", tls_session.0);
    println!("root certs map: {:?}", get_root_certs_map(&p.domain).unwrap());

    let tls_session_hex_ = tls_session.clone().1;

    let tls_session_hex = tls_session.1;
    let mut tls_session_bytes = hex::decode(tls_session_hex.clone()).unwrap();

    //println!("tls_session_hex: {:?}", tls_session_hex);

    //let root_cert = tls_session::get_root_cert_google_g2();
    //let mut len_of_root_cert = vec![5u8, 91u8];

    //let mut data: Vec<u8> = Vec::new();
    //data.append(&mut len_of_root_cert);
    //data.append(&mut root_cert.to_vec());

    //println!("cert 2: {:?}", hex::encode(data));

    let current_timestamp = Utc::now().timestamp() as u32; // SystemTime::now()
    let mut data: Vec<u8> = Vec::new();
    append_uint32(&mut data, current_timestamp);
    println!("tls_session_bytes is : {:?}", tls_session_bytes);

    let mut issuer_decoded: Vec<u8> = hex::decode(p.issuer_decoded).unwrap();
    data.push(issuer_decoded.len() as u8);
    data.append(&mut issuer_decoded);

    let mut kid = p.kid;
    println!("kid is : {:?}", kid);
    data.push(kid.len() as u8);
    data.append(&mut kid);

    let mut root_cert = p.root_cert;
    let mut len_of_root_cert = format::u16_to_bytes(root_cert.len() as u16).to_vec();
    println!("len_of_root_cert is : {:?}", len_of_root_cert);
    data.append(&mut len_of_root_cert);
    data.append(&mut root_cert);

    println!("data is : {:?}", data);
    data.append(&mut tls_session_bytes);

    println!("THE data is : {:?}", data);
    let public_key_data = tls_session::extract_json_public_key_from_tls(data);

    println!("jwk public_key_data is : {:?}", public_key_data);
    println!("jwk public_key_data hex is : {:?}", hex::encode(public_key_data));

    println!("tls_session_hex: {:?}", tls_session_hex_);
}
