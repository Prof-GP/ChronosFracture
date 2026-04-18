//! LZXPRESS Huffman decompressor — fully cross-platform, zero OS dependencies.
//!
//! Implements [MS-XCA] Section 2.6 (LZXPRESS with Huffman Coding).
//! Used to decompress Windows 10/11 MAM-wrapped prefetch files.
//!
//! MAM format:
//!   [0..4]  b"MAM\x04"           magic
//!   [4..8]  u32 LE               uncompressed size
//!   [8..]   LZXPRESS Huffman     compressed payload
//!
//! LZXPRESS Huffman format (per block of up to 65536 output bytes):
//!   [0..256]  Huffman table      512 symbols × 4-bit code lengths = 256 bytes
//!   [256..]   encoded data       bits read LSB-first from each byte

const NUM_SYMBOLS: usize  = 512;
const TABLE_BYTES: usize  = 256;   // 512 symbols × 4 bits / 8 bits per byte
const CHUNK_SIZE:  usize  = 65536;
const MAX_UNCOMPRESSED: usize = 128 * 1024 * 1024; // sanity cap: 128 MB

/// Decompress a MAM-wrapped LZXPRESS Huffman buffer.
/// Returns `Err` with a description on any structural violation.
pub fn decompress_mam(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 8 {
        return Err(format!("MAM header requires 8 bytes, got {}", input.len()));
    }
    if &input[0..4] != b"MAM\x04" {
        return Err("not a MAM-compressed file (magic mismatch)".into());
    }
    let uncompressed_size =
        u32::from_le_bytes(input[4..8].try_into().map_err(|_| "header read error")?) as usize;

    if uncompressed_size == 0 {
        return Ok(Vec::new());
    }
    if uncompressed_size > MAX_UNCOMPRESSED {
        return Err(format!(
            "claimed uncompressed size {} exceeds sanity cap {}",
            uncompressed_size, MAX_UNCOMPRESSED
        ));
    }

    decompress_lzxpress_huffman(&input[8..], uncompressed_size)
}

// ── Bit reader ────────────────────────────────────────────────────────────────

struct BitReader<'a> {
    data:  &'a [u8],
    pos:   usize,
    bits:  u32,
    avail: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader { data, pos: 0, bits: 0, avail: 0 }
    }

    /// Fill the 32-bit buffer with up to 4 more bytes (always keeps ≥ avail bits).
    #[inline]
    fn refill(&mut self) {
        while self.avail <= 24 && self.pos < self.data.len() {
            self.bits |= (self.data[self.pos] as u32) << self.avail;
            self.avail += 8;
            self.pos += 1;
        }
    }

    /// Read exactly `n` bits (LSB-first) and return them. Returns None on underflow.
    #[inline]
    fn read(&mut self, n: u32) -> Option<u32> {
        self.refill();
        if self.avail < n {
            return None;
        }
        let v = self.bits & ((1u32 << n) - 1);
        self.bits  >>= n;
        self.avail  -= n;
        Some(v)
    }

    /// Peek at up to 15 bits without consuming them.
    #[inline]
    fn peek(&mut self) -> u32 {
        self.refill();
        self.bits
    }

    /// Consume `n` bits already peeked.
    #[inline]
    fn consume(&mut self, n: u32) {
        self.bits  >>= n;
        self.avail  -= n;
    }

    fn avail(&self) -> u32 { self.avail }
}

// ── Huffman table ─────────────────────────────────────────────────────────────

/// Reverse the `n` least-significant bits of `v`.
#[inline]
fn reverse_bits(mut v: u32, n: u8) -> u32 {
    let mut out = 0u32;
    for _ in 0..n {
        out = (out << 1) | (v & 1);
        v >>= 1;
    }
    out
}

/// Parse a 256-byte Huffman table into 512 code lengths (4 bits each, packed two per byte).
fn parse_lengths(table: &[u8]) -> [u8; NUM_SYMBOLS] {
    let mut lengths = [0u8; NUM_SYMBOLS];
    for (i, &byte) in table.iter().enumerate() {
        lengths[i * 2]     = byte & 0x0F;
        lengths[i * 2 + 1] = byte >> 4;
    }
    lengths
}

/// Canonical Huffman lookup entry.
struct CodeEntry {
    code: u32,   // bit-reversed canonical code (for LSB-first comparison)
    len:  u8,    // code length in bits
    sym:  u16,   // symbol (0-511)
}

/// Build a lookup table from code lengths.
/// Returns entries sorted by length (ascending) for correct prefix-free decode.
fn build_table(lengths: &[u8; NUM_SYMBOLS]) -> Vec<CodeEntry> {
    // Step 1: count codes per length
    let mut bl_count = [0u32; 16];
    for &l in lengths.iter() {
        if l > 0 { bl_count[l as usize] += 1; }
    }

    // Step 2: first code per length (canonical assignment)
    let mut next_code = [0u32; 16];
    let mut code = 0u32;
    for bits in 1usize..16 {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }

    // Step 3: assign codes and reverse for LSB-first reading
    let mut entries: Vec<CodeEntry> = Vec::new();
    for (sym, &len) in lengths.iter().enumerate() {
        if len == 0 { continue; }
        let c = next_code[len as usize];
        next_code[len as usize] += 1;
        entries.push(CodeEntry {
            code: reverse_bits(c, len),
            len,
            sym: sym as u16,
        });
    }
    entries.sort_unstable_by_key(|e| e.len);
    entries
}

/// Decode one Huffman symbol from the bit reader.
/// Scans codes shortest-first; prefix-free property guarantees unique match.
#[inline]
fn decode_sym(table: &[CodeEntry], reader: &mut BitReader) -> Option<usize> {
    let bits = reader.peek();
    let avail = reader.avail();
    for entry in table {
        if avail < entry.len as u32 { continue; }
        let mask = (1u32 << entry.len) - 1;
        if (bits & mask) == entry.code {
            reader.consume(entry.len as u32);
            return Some(entry.sym as usize);
        }
    }
    None
}

// ── Decompressor ──────────────────────────────────────────────────────────────

fn decompress_lzxpress_huffman(input: &[u8], out_size: usize) -> Result<Vec<u8>, String> {
    let mut output: Vec<u8> = Vec::with_capacity(out_size);
    let mut reader = BitReader::new(input);

    while output.len() < out_size {
        // ── Read Huffman table for this 65536-byte block ──────────────────
        if reader.pos + TABLE_BYTES > input.len() {
            // Partial final block — no more data
            break;
        }
        let table_slice = &input[reader.pos..reader.pos + TABLE_BYTES];
        let lengths = parse_lengths(table_slice);
        reader.pos += TABLE_BYTES;
        reader.bits  = 0;
        reader.avail = 0;

        let code_table = build_table(&lengths);
        if code_table.is_empty() {
            return Err("Huffman table has no entries".into());
        }

        let chunk_end = (output.len() + CHUNK_SIZE).min(out_size);

        while output.len() < chunk_end {
            let sym = decode_sym(&code_table, &mut reader)
                .ok_or("Huffman decode failure — corrupt or truncated data")?;

            if sym < 256 {
                // ── Literal byte ──────────────────────────────────────────
                output.push(sym as u8);
            } else {
                // ── Length/distance back-reference ────────────────────────
                let extra      = sym - 256;
                let len_header = extra & 0x0F;
                let off_header = extra >> 4;

                // Decode match length
                let match_len = if len_header < 15 {
                    len_header + 3
                } else {
                    let b = reader.read(8)
                        .ok_or("unexpected end of input reading length byte")? as usize;
                    if b < 255 {
                        b + 3 + 15   // 18 – 272
                    } else {
                        reader.read(16)
                            .ok_or("unexpected end of input reading length u16")? as usize + 3
                    }
                };

                // Decode match offset (MS-XCA 2.6.3.1)
                let match_off = if off_header == 0 {
                    // Read 4-bit nibble, add 1 → [1, 16]
                    let lo = reader.read(4)
                        .ok_or("unexpected end of input reading offset nibble")? as usize;
                    lo + 1
                } else if off_header < 15 {
                    // Read off_header bits, OR with implicit leading 1 → [1<<off_header, (1<<(off_header+1))-1]
                    let lo = reader.read(off_header as u32)
                        .ok_or("unexpected end of input reading offset bits")? as usize;
                    lo | (1 << off_header)
                } else {
                    // Read 16-bit value, add 1 → [1, 65536]
                    reader.read(16)
                        .ok_or("unexpected end of input reading offset u16")? as usize + 1
                };

                if match_off > output.len() {
                    return Err(format!(
                        "back-reference offset {} > output length {} (corrupt input)",
                        match_off, output.len()
                    ));
                }

                // Copy with potential overlap (run-length style)
                let src = output.len() - match_off;
                for i in 0..match_len {
                    if output.len() >= out_size { break; }
                    let b = output[src + (i % match_off)];
                    output.push(b);
                }
            }
        }
    }

    if output.len() < out_size {
        // Warn but don't error — truncated prefetch is still partially useful
        output.resize(out_size, 0);
    }

    Ok(output)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_magic_rejected() {
        let bad = b"BAD\x04\x10\x00\x00\x00";
        assert!(decompress_mam(bad).is_err());
    }

    #[test]
    fn test_too_short_rejected() {
        assert!(decompress_mam(b"MAM").is_err());
    }

    #[test]
    fn test_zero_size_returns_empty() {
        // MAM header claiming 0 uncompressed bytes
        let mut buf = b"MAM\x04".to_vec();
        buf.extend_from_slice(&[0u8; 4]); // uncompressed_size = 0
        let result = decompress_mam(&buf).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(0b10110, 5), 0b01101);
        assert_eq!(reverse_bits(0b1, 1), 0b1);
        assert_eq!(reverse_bits(0b0, 1), 0b0);
        assert_eq!(reverse_bits(0b10000000, 8), 0b00000001);
    }

    #[test]
    fn test_parse_lengths_nibbles() {
        let table = [0xABu8; TABLE_BYTES];
        let lengths = parse_lengths(&table);
        // Each byte 0xAB splits to: low nibble = 0xB = 11, high nibble = 0xA = 10
        assert_eq!(lengths[0], 0xB);
        assert_eq!(lengths[1], 0xA);
        assert_eq!(lengths[2], 0xB);
    }
}
