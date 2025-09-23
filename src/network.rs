use std::io::Write;

pub fn send(conn: &mut dyn Write, buf: &[u8]) {
    match conn.write(buf) {
        Ok(n) => {
            if n != buf.len() {
                eprintln!("didn't send all bytes");
            }
        }
        Err(err) => {
            eprintln!("error in Send: {}", err);
        }
    }
}
