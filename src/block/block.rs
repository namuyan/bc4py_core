use crate::block::*;
use crate::utils::*;
use bigint::U256;
use std::fmt;

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

    pub fn hash(&self) -> U256 {
        U256::from(sha256double(&self.to_bytes()).as_slice())
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
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

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"hash", &u256_to_hex(&self.header.hash()))
            .entry(&"work", &u256_to_hex(&self.work_hash))
            .entry(&"height", &self.height)
            .entry(&"flag", &self.flag)
            .entry(&"bias", &self.bias)
            .entry(
                &"txs",
                &self.txs_hash.iter().map(u256_to_hex).collect::<Vec<String>>(),
            )
            .finish()
    }
}

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
        let target = bits_to_target(self.header.bits).unwrap();
        let difficulty = target_to_diff(target);
        // score = difficulty / bias
        difficulty / (self.bias as f64)
    }
}
