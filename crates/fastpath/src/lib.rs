//! Горячий путь данных: AES-256-CTR (4 прохода на каждый байт трафика в мосте)
//! и XOR-маска клиентских WebSocket-фреймов.
//!
//! Отдельный крейт нужен ради профиля: обобщённый код `ctr`/`aes`
//! мономорфизируется там, где вызывается, и с `opt-level = "z"` основного
//! ядра шифрование было в разы медленнее. Здесь — `opt-level = 3`
//! (см. [profile.release.package.tgws-fastpath] в корневом Cargo.toml), а
//! остальное ядро собирается под размер.

use aes::cipher::{KeyIvInit, StreamCipher};

// CTR со 128-битным счётчиком — как modes.CTR в оригинале (cryptography).
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Поток AES-256-CTR с возможностью «клонировать» состояние: копия заново
/// проматывает keystream на уже обработанное число байт.
pub struct TrackedStream {
    key: [u8; 32],
    iv: [u8; 16],
    processed: u64,
    stream: Aes256Ctr,
}

impl TrackedStream {
    /// `key` — 32 байта, `iv` — 16 байт (лишнее отбрасывается, нехватка — нули).
    pub fn new(key: &[u8], iv: &[u8]) -> TrackedStream {
        let mut k = [0u8; 32];
        let mut v = [0u8; 16];
        let kl = key.len().min(32);
        let vl = iv.len().min(16);
        k[..kl].copy_from_slice(&key[..kl]);
        v[..vl].copy_from_slice(&iv[..vl]);
        TrackedStream {
            key: k,
            iv: v,
            processed: 0,
            stream: Aes256Ctr::new(&k.into(), &v.into()),
        }
    }

    /// XOR с keystream на месте (шифрование и расшифровка одинаковы).
    #[inline(never)]
    pub fn xor(&mut self, data: &mut [u8]) {
        self.stream.apply_keystream(data);
        self.processed += data.len() as u64;
    }

    pub fn clone_state(&self) -> TrackedStream {
        let mut clone = TrackedStream::new(&self.key, &self.iv);
        let mut dummy = [0u8; 16384];
        let mut rem = self.processed;
        while rem > 0 {
            let n = rem.min(dummy.len() as u64) as usize;
            clone.xor(&mut dummy[..n]);
            rem -= n as u64;
        }
        clone
    }
}

/// Маскирование payload WebSocket-фрейма (RFC 6455 §5.3), по 8 байт за шаг.
#[inline(never)]
pub fn xor_mask_in_place(data: &mut [u8], mask: &[u8]) {
    let m = [mask[0], mask[1], mask[2], mask[3]];
    let mask8 = u64::from_le_bytes([m[0], m[1], m[2], m[3], m[0], m[1], m[2], m[3]]);
    let mut chunks = data.chunks_exact_mut(8);
    for c in &mut chunks {
        let v = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) ^ mask8;
        c.copy_from_slice(&v.to_le_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= m[i & 3];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_state_continues_keystream() {
        let mut a = TrackedStream::new(&[1u8; 32], &[2u8; 16]);
        let mut first = vec![0u8; 100];
        a.xor(&mut first);
        let mut b = a.clone_state();
        let (mut x, mut y) = (vec![0u8; 50], vec![0u8; 50]);
        a.xor(&mut x);
        b.xor(&mut y);
        assert_eq!(x, y);
    }

    #[test]
    fn mask_matches_bytewise() {
        let mask = [0x12, 0x34, 0x56, 0x78];
        for n in [0usize, 1, 7, 8, 9, 31, 100] {
            let orig: Vec<u8> = (0..n as u8).collect();
            let mut fast = orig.clone();
            xor_mask_in_place(&mut fast, &mask);
            let slow: Vec<u8> = orig.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect();
            assert_eq!(fast, slow, "len {}", n);
        }
    }
}
