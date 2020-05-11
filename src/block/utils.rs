use bigint::U256;

lazy_static! {
    // max target int for calc difficulty
    static ref MAX: U256 = U256::from([
        255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ].as_ref());
}

/// calculate target from bits
pub fn bits_to_target(bits: u32) -> Result<U256, String> {
    let exponent = (bits >> 24) & 0xff;
    if exponent < 3 || 33 < exponent {
        return Err(format!("'3 <= exponent <= 33' but {}", exponent));
    }
    let mantissa = U256::from(bits & 0x7fffff);
    let exponent = U256::from(256).pow(U256::from(exponent - 3));
    Ok(mantissa * exponent)
}

/// calculate bits from target
pub fn target_to_bits(target: &U256) -> u32 {
    let mut target = target.clone();
    let limit = U256::from(0x7fffff);
    let mut exponent: u32 = 3;
    let base = U256::from(256);
    while limit < target {
        target = target / base;
        exponent += 1;
    }
    (exponent << 24) | (target.0[0] as u32)
}

/// calculate difficulty from target
pub fn target_to_diff(target: U256) -> f64 {
    // base = 0x00000000ffff0000000000000000000000000000000000000000000000000000
    // max  = 0xffff000000000000000000000000000000000000000000000000000000000000
    // BASE = MAX / 0x100000000
    // difficulty = BASE / target = double(MAX / target) / 0x100000000
    ((*MAX / target).as_u64() as f64) / 4294967296f64
}

#[allow(unused_imports)]
#[cfg(test)]
mod test {
    use crate::block::*;
    use crate::utils::*;
    use bigint::U256;

    #[test]
    fn decode_encode() {
        // https://btc.com/000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf
        let bits: u32 = 0x1a05db8b;
        let target = bits_to_target(bits).unwrap();
        assert_eq!(bits, target_to_bits(&target));

        let work_hash =
            hex::decode("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf").unwrap();
        let work = U256::from(work_hash.as_slice());
        assert!(target > work);
    }

    #[test]
    fn range() {
        let target = "ffff000000000000000000000000000000000000000000000000000000000000";
        let bits = target_to_bits(&string_to_u256(target));
        assert_eq!(bits, 0x2100ffff);
        let _target = bits_to_target(bits).unwrap();
        assert_eq!(target, &hex::encode(u256_to_bytes(&_target)));

        let target = "0000000000000000000000000000000000000000000000000000000000000000";
        let bits = target_to_bits(&string_to_u256(target));
        assert_eq!(bits, 0x03000000);
        let _target = bits_to_target(bits).unwrap();
        assert_eq!(target, &hex::encode(u256_to_bytes(&_target)));
    }
}
