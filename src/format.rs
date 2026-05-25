use std::io::Read;
use std::net::TcpStream;

use chrono::DateTime;
use chrono::FixedOffset;

pub struct Messages {
    pub client_hello: Record,
    pub server_hello: Record,
    pub server_handshake: DecryptedRecord,
    pub encrypted_server_handshake: Record, // not needed
    pub application_request: Record,        // not needed
    pub encrypted_ticket: Record,           // not needed
    pub http_response: Record,
}

//pub type DecryptedRecord = Vec<u8>;

//impl DecryptedRecord {
//pub fn type_(&self) -> u8 {
//&self.last().expect("DecryptedRecord is empty")
//}

//pub fn contents(&self) -> &[u8] {
//&self[..self.len() - 1]
//}
//}

pub struct DecryptedRecord(pub(crate) Vec<u8>);

impl DecryptedRecord {
    pub fn new() -> DecryptedRecord {
        DecryptedRecord { 0: vec![] }
    }

    // F-03: saturating accessors. Empty / short records used to panic via
    // `.expect()` and `[..len-1]` indexing; both were reachable from malformed
    // wire input. Callers already gate logic on cert validation downstream, so
    // returning 0 / empty here is fail-closed.
    pub fn rtype(&self) -> u8 {
        self.0.last().copied().unwrap_or(0)
    }

    pub fn contents(&self) -> &[u8] {
        if self.0.is_empty() { &[] } else { &self.0[..self.0.len() - 1] }
    }
}

//pub type Record = Vec<u8>;

//impl Record {
//pub fn contents(&self) -> &[u8] {
//&self[5..]
//}

//pub fn rtype(&self) -> u8 {
//*self[0].expect("Record is empty")
//}
//}

#[derive(Clone)]
pub struct Record(pub Vec<u8>);

impl Record {
    pub fn new() -> Record {
        Record { 0: vec![] }
    }

    // F-03: contents()/rtype()/spoken_len() must not panic on a short record.
    // The 5-byte TLS header (type | 0x03 0x03 | length-be16) might be absent
    // for a malformed peer; callers already detect bad records via downstream
    // AEAD / handshake checks.
    pub fn contents(&self) -> &[u8] {
        if self.0.len() >= 5 { &self.0[5..] } else { &[] }
    }

    pub fn spoken_len(&self) -> u16 {
        if self.0.len() >= 5 { u16::from_be_bytes([self.0[3], self.0[4]]) } else { 0 }
    }

    pub fn rtype(&self) -> u8 {
        self.0.first().copied().unwrap_or(0)
    }
}

pub struct ServerHello {
    pub random: [u8; 32],
    pub public_key: [u8; 32],
}

pub fn server_name(name: &str) -> Vec<u8> {
    let bytes = name.as_bytes();
    concatenate(&[
        &u16_to_bytes((name.len() + 3) as u16),
        &[0x00],
        &u16_to_bytes(name.len() as u16),
        &bytes,
    ])
}

pub fn key_share(public_key: &[u8]) -> Vec<u8> {
    concatenate(&[
        &u16_to_bytes((public_key.len() + 4) as u16),
        &u16_to_bytes(0x1d).as_slice(), // x25519
        &u16_to_bytes(public_key.len() as u16).as_slice(),
        &public_key,
    ])
}

pub fn trunc_end_with_trailer(message: &Vec<u8>, trailer: u8) -> Vec<u8> {
    let mut ind = message.len() - 1;
    while ind > 0 && message[ind] != trailer {
        ind = ind - 1;
    }
    if ind > 0 { message[..ind].to_vec() } else { message[..].to_vec() }
}

pub fn contains_handshake_finish(message: &Vec<u8>) -> bool {
    for i in 0..message.len() {
        if message[i] == 20 {
            if i + 3 < message.len()
                && message[i + 1] == 0
                && message[i + 2] == 0
                && message[i + 3] == 32
            {
                return true;
            }
        }
    }
    return false;
}

// pub fn parse_server_hello(buf: &[u8]) -> ServerHello {
pub fn parse_server_hello(buf: &[u8]) -> Result<ServerHello, Vec<u8>> {
    // error codes from [5][1] to [5][255]
    let mut hello = ServerHello { random: [0u8; 32], public_key: [0u8; 32] };
    let mut current_pos: usize = 0;

    // Skip handshake type:
    current_pos = current_pos + 2; // 02 00 ("server hello") // buf.take(2);

    // Skip length_of_message:
    current_pos = current_pos + 2; // buf.take(2);

    // Skip tls type of message:
    current_pos = current_pos + 2; // 03 03 (client protocol version = "TLS 1.2") // buf.take(2);

    // F-03: every slice read below must be bounds-checked before indexing.
    // Previously each `&buf[i..i+n]` on attacker-controlled `i` was a process
    // crash on malformed ServerHello.
    if current_pos + 32 > buf.len() {
        return Err(vec![0u8, 5u8, 1u8]);
    }
    let random_bytes: [u8; 32] = match buf[current_pos..current_pos + 32].try_into() {
        Ok(b) => b,
        Err(_) => return Err(vec![0u8, 5u8, 1u8]),
    };
    hello.random = random_bytes;
    current_pos += 32;

    if current_pos + 1 > buf.len() {
        return Err(vec![0u8, 5u8, 2u8]);
    }
    let session_id_len = buf[current_pos] as usize;
    current_pos += 1 + session_id_len;

    // cipher suite (2) + compression (1) + extensions_len (2)
    current_pos += 5;
    if current_pos > buf.len() {
        return Err(vec![0u8, 5u8, 3u8]);
    }

    while current_pos + 2 <= buf.len() {
        let typ = u16::from_be_bytes([buf[current_pos], buf[current_pos + 1]]);
        match typ {
            0x0033 => {
                // key_share extension: ext_type(2) ext_len(2) group(2) key_len(2) key(key_len)
                if current_pos + 8 > buf.len() {
                    return Err(vec![0u8, 5u8, 4u8]);
                }
                current_pos += 6;
                let public_key_length =
                    u16::from_be_bytes([buf[current_pos], buf[current_pos + 1]]) as usize;
                current_pos += 2;
                if current_pos + public_key_length > buf.len() {
                    return Err(vec![0u8, 5u8, 5u8]);
                }
                let public_key_bytes = &buf[current_pos..current_pos + public_key_length];
                hello.public_key = match public_key_bytes.try_into() {
                    Ok(b) => b,
                    Err(_) => return Err(vec![0u8, 5u8, 6u8]),
                };
            }
            0x002b => {
                // supported_versions; ignore (type(2) len(2) version(2)).
                current_pos += 6;
            }
            _ => {
                if current_pos + 4 > buf.len() {
                    return Err(vec![0u8, 5u8, 7u8]);
                }
                let extension_len =
                    u16::from_be_bytes([buf[current_pos + 2], buf[current_pos + 3]]) as usize;
                current_pos += 4 + extension_len;
            }
        }
    }

    Ok(hello)
}

// F-03: read_record now returns io::Result. Previously a broken socket / EOF
// during handshake panicked via `expect`, so any peer that closes the
// connection mid-record DoSed the client.
pub fn read_record(reader: &mut TcpStream) -> std::io::Result<Record> {
    let mut buf = [0u8; 5];
    reader.read_exact(&mut buf)?;

    let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let contents = read(length, reader)?;

    let mut record = buf.to_vec();
    record.extend_from_slice(&contents);

    Ok(Record { 0: record })
}

//pub fn read_record<R: Read>(reader: &mut R) -> Record {
//let mut buf = vec![0; 5];
//reader.read_exact(&mut buf).unwrap();

//let length = BigEndian::read_u16(&buf[3..5]);
//let contents = read(length as usize
//concatenate(buf, contents)
//}

pub fn read(length: usize, reader: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    while buf.len() < length {
        let chunk = read_upto(length - buf.len(), reader)?;
        if chunk.is_empty() {
            // F-03: peer closed mid-record; surface as UnexpectedEof rather
            // than spinning indefinitely.
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "short record"));
        }
        buf.extend(chunk);
    }
    Ok(buf)
}

pub fn read_upto(length: usize, reader: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; length];
    let n = reader.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

// pub fn concatenate(bufs: Vec<&[u8]>) -> Vec<u8> {
pub fn concatenate(bufs: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    for b in bufs {
        buf.extend_from_slice(b);
    }
    buf
}

pub fn u16_to_bytes(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

pub fn extension(id: u16, contents: Vec<u8>) -> Vec<u8> {
    concatenate(&[&u16_to_bytes(id), &u16_to_bytes(contents.len() as u16), &contents])
}

pub fn extract_all_items(item: &str, data: &str) -> Vec<String> {
    let target = format!("{}{}{}", r#"""#, item, r#"":"#); // Substring to search for
    let mut results = Vec::new();
    let mut start = 0;

    while let Some(start_index) = data[start..].find(&target) {
        if let Some(open_quote_pos) = data[start + start_index + target.len()..].find('"') {
            let start_pos = start + start_index + target.len() + open_quote_pos + 1; // Position after substring "n":"

            // Looking for the end of a substring
            if let Some(end_index) = data[start_pos..].find('"') {
                let end_pos = start_pos + end_index;
                results.push(data[start_pos..end_pos].to_string()); // Add a substring to the results
                start = end_pos; // Updating the starting position for the next search
            } else {
                break; // If the quote is not found, exit the loop
            }
        } else {
            break;
        };
    }

    results // outputs an vector of found substrings
}

// F-03: HTTP response is attacker-controlled (forged Date: / Expires: headers
// in a malformed reply previously panicked via .unwrap()). Return Option and
// let the caller decide what to do.
pub fn extract_expires(data: &str) -> Option<i64> {
    fn extract_line<'a>(data: &'a str, target: &str) -> Option<&'a str> {
        let start = data.find(target)?;
        let start_pos = start + target.len();
        let end = data[start_pos..].find('\n')?;
        Some(&data[start_pos..start_pos + end])
    }

    if let Some(expires) = extract_line(data, "Expires: ") {
        let dt = DateTime::parse_from_rfc2822(expires.trim()).ok()?;
        return Some(dt.timestamp());
    }

    let date = extract_line(data, "Date: ")?;
    let dt: DateTime<FixedOffset> = DateTime::parse_from_rfc2822(date.trim()).ok()?;
    Some(dt.timestamp() + 18223) // Date + 18223 = Expires (Google default)
}
