use std::io;
use std::io::Write;

// F-10: use write_all so partial-writes do not silently drop the tail of a
// TLS record. Partial writes corrupt the AEAD frame on the wire — the next
// open() at the peer will fail authentication. Callers want a clean error,
// not a half-sent record.
pub fn send(conn: &mut dyn Write, buf: &[u8]) -> io::Result<()> {
    conn.write_all(buf)
}
