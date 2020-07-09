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

/// calculate merkleroot hash
///
/// panic if you input empty hashs
pub fn calc_merkleroot_hash(mut hashs: Vec<U256>) -> U256 {
    assert!(0 < hashs.len());
    let mut buf = [0u8; 64];
    let mut new_hashs = Vec::with_capacity(hashs.len() / 2);
    while 1 < hashs.len() {
        if hashs.len() % 2 == 0 {
            new_hashs.clear();
            for i in 0..(hashs.len() / 2) {
                hashs[i * 2].to_big_endian(&mut buf[0..32]);
                hashs[i * 2 + 1].to_big_endian(&mut buf[32..64]);
                let hash = sha256double(buf.as_ref());
                new_hashs.push(U256::from(hash.as_slice()));
            }
            // swap
            hashs = new_hashs.clone();
        } else {
            let last = hashs.last().unwrap().clone();
            hashs.push(last);
        }
    }
    // check
    hashs.pop().unwrap()
}

#[allow(unused_imports)]
#[cfg(test)]
mod utils {
    use crate::utils::calc_merkleroot_hash;
    use bigint::U256;

    /// for test case only
    #[allow(dead_code)]
    fn hex_to_u256_reversed(s: &str) -> U256 {
        // Bitcoin's block & tx hash is looks reversed because they want work hash starts with zeros
        let mut vec = hex::decode(s).unwrap();
        vec.reverse();
        U256::from(vec.as_slice())
    }

    #[test]
    fn test_merkleroot_hash() {
        // https://btc.com/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
        let hashs = vec![
            hex_to_u256_reversed("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87"),
            hex_to_u256_reversed("fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4"),
            hex_to_u256_reversed("6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4"),
            hex_to_u256_reversed("e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"),
        ];
        let merkleroot =
            hex_to_u256_reversed("f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766");
        assert_eq!(calc_merkleroot_hash(hashs), merkleroot);
    }
}
