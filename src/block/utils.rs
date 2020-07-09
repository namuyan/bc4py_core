use crate::block::{BlockFlag, BlockHeader};
use crate::tx::{TxBody, TxOutput};
use crate::utils::u256_to_bytes;
use bc4py_hash::{get_poc_hash, get_x11_hash, get_x16s_hash, get_yespower_hash};
use bigint::U256;
use sha2::{Digest, Sha256};

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

/// get proof of stake work hash
pub fn get_pos_hash(coinbase: &TxBody, amount: u64, previous_hash: &U256) -> U256 {
    assert!(1_0000_0000 <= amount);
    // fix after
    let mut input = [0u8; 64];
    input[0..32].clone_from_slice(&coinbase.hash());
    previous_hash.to_big_endian(&mut input[32..64]);
    let mut work_hash = Sha256::digest(&input);
    work_hash.reverse();
    let work = U256::from(work_hash.as_slice());
    let div = U256::from((amount / 1_0000_0000) as u32);
    let pos_hash: U256 = work / div;
    pos_hash.to_little_endian(&mut input[0..32]);
    U256::from(&input[0..32])
}

/// get Block's workHash
pub fn get_work_hash(
    flag: &BlockFlag,
    header: &BlockHeader,
    coinbase: Option<&TxBody>,
    input_cache: Option<&TxOutput>,
) -> Result<U256, String> {
    // note: PoS type require coinbase & input_cache
    match flag {
        BlockFlag::Genesis => Ok(U256::zero()),
        BlockFlag::CoinPos => {
            if input_cache.is_none() {
                return Err("input_cache is none but required for params".to_owned());
            }
            let input = input_cache.unwrap();
            if input.1 != 0 {
                return Err("try to get coinbase but coinId isn't 0".to_owned());
            }
            if coinbase.is_none() {
                return Err("coinbase is none but required".to_owned());
            }
            let coinbase = coinbase.unwrap();
            Ok(get_pos_hash(coinbase, input.2, &header.previous_hash))
        },
        BlockFlag::CapPos => {
            if input_cache.is_none() {
                return Err("input_cache is none but required to derive addr".to_owned());
            }
            let addr = input_cache.unwrap().0.clone();
            let previous_hash = u256_to_bytes(&header.previous_hash);
            let output = get_poc_hash(&addr, header.nonce, header.time, &previous_hash);
            let work = U256::from(output.as_slice());
            Ok(work)
        },
        BlockFlag::FlkPos => Err("not implemented yet".to_owned()),
        BlockFlag::YesPow => {
            let input = header.to_bytes().to_vec();
            let work = U256::from(get_yespower_hash(input).as_slice());
            Ok(work)
        },
        BlockFlag::X11Pow => {
            let input = header.to_bytes().to_vec();
            let work = U256::from(get_x11_hash(input).as_slice());
            Ok(work)
        },
        BlockFlag::X16sPow => {
            let input = header.to_bytes().to_vec();
            let work = U256::from(get_x16s_hash(input).as_slice());
            Ok(work)
        },
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod test {
    use crate::block::*;
    use crate::tx::TxBody;
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

    #[test]
    fn pos_hash() {
        let bytes = hex::decode("00000000020000003d3dfa016d67fa010000000000000000000000000000000000010100000000527c5bce9af709995d8b36ca18c517b33623d740d1b8374418176f045c115b6a0000de6e40c12db0920348ed0ebb136e3a926bad4a3a000000008a80355500000000").unwrap();
        let coinbase = TxBody::from_bytes(bytes.as_slice()).unwrap();
        let previous_hash = U256::from(
            hex::decode("65af729cdeb47c8607276d8f3786d734beaab7423b059807ed9a3df41357c77e")
                .unwrap()
                .as_slice(),
        );
        let amount = 7_1234_1764;
        let work = "200905f19eb1445c80a011d7651c1b5906b0322a431762531dc72d0405000000";
        let calc = get_pos_hash(&coinbase, amount, &previous_hash);
        assert_eq!(u256_to_hex(&calc), work);
    }
}
