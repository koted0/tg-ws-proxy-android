use byteorder::{ByteOrder, LittleEndian};

// AES-256-CTR с «клонированием» состояния и маска WS живут в tgws-fastpath
// (собирается с opt-level 3 — это горячий путь каждого байта трафика).
pub use tgws_fastpath::{xor_mask_in_place, TrackedStream};

pub fn new_aes_ctr(key: &[u8], iv: &[u8]) -> TrackedStream {
    TrackedStream::new(key, iv)
}

// ---------------------------------------------------------------------------
// MTProto Splitter
// ---------------------------------------------------------------------------

pub const PROTO_ABRIDGED: i32 = 0;
pub const PROTO_INTERMEDIATE: i32 = 1;
pub const PROTO_PADDED_INTERMEDIATE: i32 = 2;

pub fn proto_tag_to_type(proto: u32) -> i32 {
    match proto {
        0xEEEEEEEE => PROTO_INTERMEDIATE,
        0xDDDDDDDD => PROTO_PADDED_INTERMEDIATE,
        _ => PROTO_ABRIDGED,
    }
}

/// Делит поток клиента на отдельные MTProto-пакеты, чтобы каждый ушёл
/// отдельным WS-фреймом (proxy/bridge.py::MsgSplitter). Границы считаются по
/// открытому тексту, который у моста уже есть после расшифровки клиента, —
/// без собственного прохода AES, как в оригинале после оптимизаций.
pub struct MsgSplitter {
    proto_type: i32,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

/// Длина следующего пакета в начале `plain`: None — пакет ещё не пришёл
/// целиком, Some(0) — длина не разбирается (дальше поток идёт без деления).
fn next_packet_len(proto_type: i32, plain: &[u8]) -> Option<usize> {
    if plain.is_empty() {
        return None;
    }
    let (header_len, payload_len) = match proto_type {
        PROTO_ABRIDGED => {
            // Порт _next_abridged_len: long-form при first == 0x7F или 0xFF.
            let first = plain[0];
            if first == 0x7F || first == 0xFF {
                if plain.len() < 4 {
                    return None;
                }
                let words = (plain[1] as usize) | ((plain[2] as usize) << 8) | ((plain[3] as usize) << 16);
                (4usize, words * 4)
            } else {
                (1usize, (first as usize & 0x7F) * 4)
            }
        }
        PROTO_INTERMEDIATE | PROTO_PADDED_INTERMEDIATE => {
            if plain.len() < 4 {
                return None;
            }
            (4usize, (LittleEndian::read_u32(&plain[..4]) & 0x7FFF_FFFF) as usize)
        }
        _ => return Some(0),
    };
    if payload_len == 0 {
        return Some(0);
    }
    let pkt_len = header_len + payload_len;
    if plain.len() < pkt_len {
        return None;
    }
    Some(pkt_len)
}

impl MsgSplitter {
    pub fn new(proto: u32) -> Option<MsgSplitter> {
        Some(MsgSplitter {
            proto_type: proto_tag_to_type(proto),
            cipher_buf: Vec::new(),
            plain_buf: Vec::new(),
            disabled: false,
        })
    }

    /// `cipher` и `plain` — один и тот же кусок потока (уже зашифрованный для
    /// Telegram и открытый). Для каждого целого пакета вызывает `emit` с его
    /// шифротекстом; неполный хвост ждёт следующего куска.
    pub fn split_with(&mut self, cipher: &[u8], plain: &[u8], mut emit: impl FnMut(&[u8])) {
        debug_assert_eq!(cipher.len(), plain.len());
        if cipher.is_empty() {
            return;
        }
        if self.disabled {
            emit(cipher);
            return;
        }
        if self.cipher_buf.is_empty() {
            // Частый случай: кусок начинается с границы пакета — без копий.
            let consumed = Self::walk(self.proto_type, cipher, plain, &mut self.disabled, &mut emit);
            if consumed < cipher.len() {
                self.cipher_buf.extend_from_slice(&cipher[consumed..]);
                self.plain_buf.extend_from_slice(&plain[consumed..]);
            }
            return;
        }
        self.cipher_buf.extend_from_slice(cipher);
        self.plain_buf.extend_from_slice(plain);
        let consumed = Self::walk(self.proto_type, &self.cipher_buf, &self.plain_buf, &mut self.disabled, &mut emit);
        self.cipher_buf.drain(..consumed);
        self.plain_buf.drain(..consumed);
    }

    fn walk(proto_type: i32, cipher: &[u8], plain: &[u8], disabled: &mut bool, emit: &mut impl FnMut(&[u8])) -> usize {
        let mut offset = 0;
        while offset < cipher.len() {
            match next_packet_len(proto_type, &plain[offset..]) {
                None => break,
                Some(0) => {
                    emit(&cipher[offset..]);
                    *disabled = true;
                    return cipher.len();
                }
                Some(n) => {
                    emit(&cipher[offset..offset + n]);
                    offset += n;
                }
            }
        }
        offset
    }

    /// Совместимый вариант: части отдельными векторами.
    pub fn split(&mut self, cipher: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        let mut parts = Vec::new();
        self.split_with(cipher, plain, |p| parts.push(p.to_vec()));
        parts
    }

    /// Неполный хвост при закрытии клиента.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            return Vec::new();
        }
        self.plain_buf.clear();
        vec![std::mem::take(&mut self.cipher_buf)]
    }
}

#[cfg(test)]
mod splitter_tests {
    use super::*;

    fn intermediate(n: usize, fill: u8) -> Vec<u8> {
        let mut v = (n as u32).to_le_bytes().to_vec();
        v.extend(std::iter::repeat(fill).take(n));
        v
    }

    #[test]
    fn splits_across_chunks_and_flushes_tail() {
        let mut plain = Vec::new();
        for (i, n) in [8usize, 100, 2000, 4].iter().enumerate() {
            plain.extend(intermediate(*n, i as u8));
        }
        // "Шифр" — тот же поток с XOR, чтобы отличался от открытого текста.
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x5A).collect();
        let mut sp = MsgSplitter::new(0xEEEEEEEE).unwrap();
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for (c, p) in cipher.chunks(37).zip(plain.chunks(37)) {
            sp.split_with(c, p, |x| parts.push(x.to_vec()));
        }
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), vec![12, 104, 2004, 8]);
        assert_eq!(parts.concat(), cipher);
        assert!(sp.flush().is_empty());

        let mut sp = MsgSplitter::new(0xEFEFEFEF).unwrap();
        // abridged: 1 слово (4 байта) + неполный длинный пакет в хвосте.
        let mut p = vec![0x01, 1, 2, 3, 4];
        p.extend_from_slice(&[0x7F, 0x10, 0x00, 0x00, 9, 9]);
        let parts = sp.split(&p, &p);
        assert_eq!(parts, vec![vec![0x01, 1, 2, 3, 4]]);
        assert_eq!(sp.flush(), vec![vec![0x7F, 0x10, 0x00, 0x00, 9, 9]]);
    }

    #[test]
    fn zero_length_disables_splitting() {
        let mut sp = MsgSplitter::new(0xEEEEEEEE).unwrap();
        let p = [0u8, 0, 0, 0, 1, 2, 3];
        assert_eq!(sp.split(&p, &p), vec![p.to_vec()]);
        assert_eq!(sp.split(&[9, 9], &[9, 9]), vec![vec![9, 9]]);
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use std::time::Instant;

    /// Пропускная способность пути данных моста:
    /// cargo test --release --lib bench_data_path -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_data_path() {
        const CHUNK: usize = 64 * 1024;
        const TOTAL: usize = 128 * 1024 * 1024;
        let key = [7u8; 32];
        let iv = [9u8; 16];
        let mut buf = vec![0u8; CHUNK];

        let mut s = new_aes_ctr(&key, &iv);
        let t = Instant::now();
        for _ in 0..TOTAL / CHUNK {
            s.xor(&mut buf);
        }
        println!("BENCH aes_ctr_single_pass: {:.0} MB/s", TOTAL as f64 / t.elapsed().as_secs_f64() / 1e6);

        // Uplink: intermediate-пакеты по 1 КБ, tg_enc + MsgSplitter (как в bridge_ws).
        let mut plain = Vec::with_capacity(CHUNK);
        while plain.len() + 1028 <= CHUNK {
            plain.extend_from_slice(&1024u32.to_le_bytes());
            plain.extend(std::iter::repeat(0xAB).take(1024));
        }
        let mut tg = new_aes_ctr(&key, &iv);
        tg.xor(&mut [0u8; 64]);
        let mut sp = MsgSplitter::new(0xEEEEEEEE).unwrap();
        let (mut total, mut packets) = (0usize, 0usize);
        let mut wire = plain.clone();
        let mut frames: Vec<u8> = Vec::with_capacity(CHUNK + 4096);
        let t = Instant::now();
        while total < TOTAL {
            // Как bridge_ws: открытый текст -> шифр для Telegram -> фреймы.
            wire.copy_from_slice(&plain);
            tg.xor(&mut wire);
            frames.clear();
            sp.split_with(&wire, &plain, |p| {
                packets += 1;
                crate::ws::append_frame(&mut frames, crate::ws::OP_BINARY, p);
            });
            total += wire.len();
        }
        println!("BENCH uplink_encrypt_split: {:.0} MB/s ({} packets)", total as f64 / t.elapsed().as_secs_f64() / 1e6, packets);
    }
}
