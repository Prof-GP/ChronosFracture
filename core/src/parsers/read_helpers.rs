/// Bounds-checked little-endian read helpers shared across parsers.
/// All functions return 0 / empty string on out-of-bounds rather than panicking.

#[inline]
pub(crate) fn r_u16(d: &[u8], o: usize) -> u16 {
    if o + 2 > d.len() { return 0; }
    u16::from_le_bytes([d[o], d[o + 1]])
}

#[inline]
pub(crate) fn r_u32(d: &[u8], o: usize) -> u32 {
    if o + 4 > d.len() { return 0; }
    u32::from_le_bytes([d[o], d[o+1], d[o+2], d[o+3]])
}

#[inline]
pub(crate) fn r_u64(d: &[u8], o: usize) -> u64 {
    if o + 8 > d.len() { return 0; }
    u64::from_le_bytes([d[o],d[o+1],d[o+2],d[o+3],d[o+4],d[o+5],d[o+6],d[o+7]])
}

/// Null-terminated UTF-16LE string, capped at 512 code units.
pub(crate) fn r_utf16_null(d: &[u8], off: usize) -> String {
    let mut units = Vec::new();
    let mut i = off;
    while i + 1 < d.len() {
        let c = u16::from_le_bytes([d[i], d[i+1]]);
        if c == 0 { break; }
        units.push(c);
        i += 2;
        if units.len() > 512 { break; }
    }
    String::from_utf16_lossy(&units).to_string()
}

/// Length-prefixed UTF-16LE string (n = count of UTF-16 code units).
pub(crate) fn r_utf16_counted(d: &[u8], off: usize, n: usize) -> String {
    let end = (off + n * 2).min(d.len());
    if off >= end { return String::new(); }
    let pairs: Vec<u16> = d[off..end]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&pairs).to_string()
}

/// Null-terminated ASCII string, capped at 512 bytes.
pub(crate) fn r_ascii_null(d: &[u8], off: usize) -> String {
    if off >= d.len() { return String::new(); }
    let slice = &d[off..];
    let n = slice.iter().take(512).position(|&b| b == 0)
        .unwrap_or_else(|| slice.len().min(512));
    String::from_utf8_lossy(&slice[..n]).to_string()
}
