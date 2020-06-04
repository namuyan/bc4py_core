use bigint::U256;
use ripemd160::Ripemd160;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type Address = [u8; 21];

#[inline]
pub fn u32_to_bytes(i: u32) -> [u8; 4] {
    i.to_le_bytes()
}

#[inline]
pub fn f32_to_bytes(i: f32) -> [u8; 4] {
    i.to_le_bytes()
}

#[inline]
pub fn u64_to_bytes(i: u64) -> [u8; 8] {
    i.to_le_bytes()
}

#[inline]
pub fn i64_to_bytes(i: i64) -> [u8; 8] {
    i.to_le_bytes()
}

#[inline]
pub fn u256_to_bytes(i: &U256) -> [u8; 32] {
    let mut slice = [0u8; 32];
    i.to_big_endian(&mut slice);
    slice
}

#[inline]
pub fn u256_to_hex(i: &U256) -> String {
    hex::encode(u256_to_bytes(i).as_ref())
}

#[inline]
pub fn write_slice(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    for (a, b) in dst.iter_mut().zip(src.iter()) {
        *a = *b;
    }
}

#[inline]
pub fn bytes_to_u32(bytes: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    write_slice(&mut tmp, bytes);
    u32::from_le_bytes(tmp)
}

#[inline]
pub fn bytes_to_f32(bytes: &[u8]) -> f32 {
    let mut tmp = [0u8; 4];
    write_slice(&mut tmp, bytes);
    f32::from_le_bytes(tmp)
}

#[inline]
pub fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut tmp = [0u8; 8];
    write_slice(&mut tmp, bytes);
    u64::from_le_bytes(tmp)
}

#[inline]
pub fn bytes_to_i64(bytes: &[u8]) -> i64 {
    let mut tmp = [0u8; 8];
    write_slice(&mut tmp, bytes);
    i64::from_le_bytes(tmp)
}

#[cfg(test)]
pub fn string_to_u256(s: &str) -> U256 {
    assert_eq!(s.len(), 64);
    U256::from(hex::decode(s).unwrap().as_slice())
}

#[inline]
pub fn sha256double(b: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(b);
    let hash = Sha256::digest(hash.as_slice());
    hash.to_vec()
}

#[inline]
pub fn sha256ripemd160(ver: u8, pk: &[u8]) -> Address {
    assert_eq!(pk.len(), 33);
    let bytes = Sha256::digest(pk);
    let bytes = Ripemd160::digest(bytes.as_slice());
    let mut output = [0u8; 21];
    output[0] = ver;
    write_slice(&mut output[1..21], bytes.as_slice());
    output
}

#[inline]
pub fn get_current_time() -> f64 {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).unwrap();
    duration.as_secs_f64()
}
