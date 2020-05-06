use crate::utils::*;
use bigint::U256;

#[derive(Clone, PartialEq)]
pub struct BlockHeader {
    pub version: u32,        // 4bytes int
    pub previous_hash: U256, // 32bytes bin
    pub merkleroot: U256,    // 32bytes bin
    pub time: u32,           // 4bytes int
    pub bits: u32,           // 4bytes int
    pub nonce: u32,          // 4bytes int
}

impl BlockHeader {
    /// get block header from bytes
    pub fn from_bytes(bytes: &[u8]) -> BlockHeader {
        assert_eq!(bytes.len(), 80);
        let version = bytes_to_u32(&bytes[0..4]);
        let previous_hash = U256::from(&bytes[4..4 + 32]);
        let merkleroot = U256::from(&bytes[36..36 + 32]);
        let time = bytes_to_u32(&bytes[68..68 + 4]);
        let bits = bytes_to_u32(&bytes[72..72 + 4]);
        let nonce = bytes_to_u32(&bytes[76..76 + 4]);
        BlockHeader {
            version,
            previous_hash,
            merkleroot,
            time,
            bits,
            nonce,
        }
    }

    /// to bytes
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut data = [0u8; 80];
        write_slice(&mut data[0..4], &u32_to_bytes(self.version));
        self.previous_hash.to_big_endian(&mut data[4..4 + 32]);
        self.merkleroot.to_big_endian(&mut data[36..36 + 32]);
        write_slice(&mut data[68..68 + 4], &u32_to_bytes(self.time));
        write_slice(&mut data[72..72 + 4], &u32_to_bytes(self.bits));
        write_slice(&mut data[76..76 + 4], &u32_to_bytes(self.nonce));
        data
    }

    /// get sha256d hash
    pub fn hash(&self) -> U256 {
        U256::from(sha256double(&self.to_bytes()).as_slice())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum BlockFlag {
    Genesis, // genesis tx
    CoinPos, // coin stake
    CapPos,  // capacity stake
    FlkPos,  // found lock stake (unimplemented)
    YesPow,  // yespower work
    X11Pow,  // X11 work
    X16sPow, // X16S work
}

impl BlockFlag {
    pub fn from_int(int: u8) -> Result<Self, String> {
        match int {
            0 => Ok(BlockFlag::Genesis),
            1 => Ok(BlockFlag::CoinPos),
            2 => Ok(BlockFlag::CapPos),
            3 => Ok(BlockFlag::FlkPos),
            5 => Ok(BlockFlag::YesPow),
            6 => Ok(BlockFlag::X11Pow),
            9 => Ok(BlockFlag::X16sPow),
            int => Err(format!("unknown block type {}", int)),
        }
    }
    pub fn to_int(&self) -> u8 {
        match self {
            BlockFlag::Genesis => 0,
            BlockFlag::CoinPos => 1,
            BlockFlag::CapPos => 2,
            BlockFlag::FlkPos => 3,
            BlockFlag::YesPow => 5,
            BlockFlag::X11Pow => 6,
            BlockFlag::X16sPow => 9,
        }
    }
}

#[derive(PartialEq)]
pub struct Block {
    // meta
    pub work_hash: U256,
    pub height: u32,
    pub flag: BlockFlag,
    pub bias: f32,

    // header
    pub header: BlockHeader,

    // block body
    pub txs_hash: Vec<U256>,
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = hex::encode(sha256double(&self.header.to_bytes()));
        f.debug_tuple("Block").field(&hash).finish()
    }
}

// for target (BASE = MAX / 0x100000000)
// base = 0x00000000ffff0000000000000000000000000000000000000000000000000000
// bax  = 0xffff000000000000000000000000000000000000000000000000000000000000
static MAX_TARGET: [u8; 32] = [
    255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

impl Block {
    pub fn new(
        work_hash: U256,
        height: u32,
        flag: BlockFlag,
        bias: f32,
        header: BlockHeader,
        txs_hash: Vec<U256>,
    ) -> Self {
        Block {
            work_hash,
            height,
            flag,
            bias,
            header,
            txs_hash,
        }
    }

    pub fn check_proof_of_work(&self) -> Result<bool, String> {
        let target = bits_to_target(self.header.bits)?;
        Ok(target > self.work_hash)
    }

    pub fn calc_score(&self) -> f64 {
        // difficulty = BASE / target
        // score = difficulty / bias
        let target = bits_to_target(self.header.bits).unwrap();
        let max = U256::from(MAX_TARGET.as_ref());
        let difficulty = ((max / target).as_u64() as f64) / 4294967296f64;
        difficulty / (self.bias as f64)
    }
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

#[allow(unused_imports)]
#[cfg(test)]
mod target_bits {
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
