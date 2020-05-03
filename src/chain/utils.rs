use crate::utils::*;

#[inline]
pub fn big_endian_from_u32(i: u32) -> [u8; 4] {
    i.to_be_bytes()
}

#[inline]
pub fn big_endian_to_u32(bytes: &[u8]) -> u32 {
    let mut tmp = [0u8; 4];
    write_slice(&mut tmp, bytes);
    u32::from_be_bytes(tmp)
}
