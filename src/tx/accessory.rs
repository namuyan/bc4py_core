use crate::tx::{TxBody, TxRecoded, TxVerifiable};
use crate::utils::*;
use bigint::U256;
use streaming_iterator::StreamingIterator;

type Address = [u8; 21];

#[derive(Clone, PartialEq)]
pub struct TxInput(pub U256, pub u8); // (txhash, txindex)

impl std::fmt::Debug for TxInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // input(txhash, txindex)
        let hash = hex::encode(u256_to_bytes(&self.0).as_ref());
        f.debug_tuple("input").field(&hash).field(&self.1).finish()
    }
}

impl TxInput {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 33 {
            Err("cannot decode tx input".to_owned())
        } else {
            Ok(TxInput(U256::from(&bytes[0..32]), bytes[32]))
        }
    }
    #[inline]
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut slice = [0u8; 33];
        self.0.to_big_endian(&mut slice[0..32]);
        slice[32] = self.1;
        slice
    }
}

/// (address<ver+ripemd160>, coinId, amount)
#[derive(Clone, PartialEq, Debug)]
pub struct TxOutput(pub Address, pub u32, pub u64);

impl TxOutput {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 33 {
            Err("cannot decode tx output".to_owned())
        } else {
            let mut address = [0u8; 21];
            address.clone_from_slice(&bytes[0..21]);
            let coin_id = bytes_to_u32(&bytes[21..21 + 4]);
            let amount = bytes_to_u64(&bytes[25..25 + 8]);
            Ok(TxOutput(address, coin_id, amount))
        }
    }
    #[inline]
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut slice = [0u8; 33];
        write_slice(&mut slice[0..21], &self.0);
        write_slice(&mut slice[21..21 + 4], &u32_to_bytes(self.1));
        write_slice(&mut slice[25..25 + 8], &u64_to_bytes(self.2));
        slice
    }
}

/// transaction type
/// https://github.com/kumacoinproject/bc4py/blob/develop/bc4py/config.py#L43
#[derive(Clone, PartialEq, Debug)]
pub enum TxType {
    Genesis,
    PoW,
    PoS,
    Transfer,
    Mint,
    // Inner,
}

impl TxType {
    pub fn from_int(int: u32) -> Result<TxType, String> {
        match int {
            0 => Ok(TxType::Genesis),
            1 => Ok(TxType::PoW),
            2 => Ok(TxType::PoS),
            3 => Ok(TxType::Transfer),
            4 => Ok(TxType::Mint),
            // 255 => Ok(TxType::Inner),
            i => Err(format!("not found txtype {}", i)),
        }
    }
    pub fn to_int(&self) -> u32 {
        match self {
            TxType::Genesis => 0,
            TxType::PoW => 1,
            TxType::PoS => 2,
            TxType::Transfer => 3,
            TxType::Mint => 4,
            // TxType::Inner => 255,
        }
    }
}

/// transaction message format
/// https://github.com/kumacoinproject/bc4py/blob/develop/bc4py/config.py#L59
#[derive(Clone, PartialEq, Debug)]
pub enum TxMessage {
    Nothing,
    Plain(String),
    Byte(Vec<u8>),
    // MsgPack(Vec<u8>),
    // HashLocked(Vec<u8>),
}

impl TxMessage {
    pub fn new(message_type: u8, message: Vec<u8>) -> Result<Self, String> {
        if 0xffff < message.len() {
            return Err(format!("tx message is too long len={}", message.len()));
        }
        match message_type {
            0 => Ok(TxMessage::Nothing),
            1 => Ok(TxMessage::Plain(
                String::from_utf8(message).map_err(|_| "is not UTF8".clone())?,
            )),
            2 => Ok(TxMessage::Byte(message)),
            i => Err(format!("not found message type {}", i)),
        }
    }
    /// get message type int
    pub fn to_int(&self) -> u8 {
        match self {
            TxMessage::Nothing => 0,
            TxMessage::Plain(_) => 1,
            TxMessage::Byte(_) => 2,
            // TxMessage::MsgPack(_) => 3,
            // TxMessage:HashLocked(_) => 4,
        }
    }
    pub fn to_type(&self) -> &'static str {
        // for debug
        match self {
            TxMessage::Nothing => "None",
            TxMessage::Plain(_) => "Plain",
            TxMessage::Byte(_) => "Byte",
        }
    }
    pub fn to_bytes(&'a self) -> &'a [u8] {
        match self {
            TxMessage::Nothing => &[],
            TxMessage::Plain(s) => s.as_bytes(),
            TxMessage::Byte(b) => b.as_slice(),
            // TxMessage::MsgPack(_) => ?,
            // TxMessage:HashLocked(_) => ?,
        }
    }
    pub fn to_string(&self) -> String {
        // for debug
        match self {
            TxMessage::Nothing => "".to_owned(),
            TxMessage::Plain(p) => p.clone(),
            TxMessage::Byte(b) => hex::encode(b), // hex
        }
    }
    pub fn length(&self) -> usize {
        match self {
            TxMessage::Nothing => 0,
            TxMessage::Plain(s) => s.as_bytes().len(),
            TxMessage::Byte(b) => b.len(),
            // TxMessage::MsgPack(_) => ?,
            // TxMessage:HashLocked(_) => ?,
        }
    }
}

/// Block's static transactions `(coinbase, txs, iter_index)`
#[derive(Clone, PartialEq, Debug)]
pub struct BlockTxs(pub TxVerifiable, pub Vec<TxRecoded>);

impl BlockTxs {
    pub fn new(coinbase: TxVerifiable, txs: Vec<TxRecoded>) -> Self {
        BlockTxs(coinbase, txs)
    }

    pub fn len(&self) -> usize {
        1 + self.1.len()
    }

    pub fn position(&self, hash: &U256) -> Option<usize> {
        if hash == &self.0.hash {
            Some(0)
        } else {
            match self.1.iter().position(|tx| tx.hash == *hash) {
                Some(index) => Some(index + 1),
                None => None,
            }
        }
    }

    pub fn body_ref(&self, hash: &U256) -> Option<&TxBody> {
        if hash == &self.0.hash {
            Some(&self.0.body)
        } else {
            match self.1.iter().find(|tx| tx.hash == *hash) {
                Some(tx) => Some(&tx.body),
                None => None,
            }
        }
    }

    pub fn iter(&self) -> TxBodyIter {
        TxBodyIter(&self.0.body, &self.1, 0)
    }

    pub fn into_iter(self) -> TxIntoIter {
        TxIntoIter(Some(self.0), self.1.into_iter().map(|tx| Some(tx)).collect())
    }
}

/// TxRecoded moved iterator
pub struct TxIntoIter(Option<TxVerifiable>, Vec<Option<TxRecoded>>);

impl Iterator for TxIntoIter {
    type Item = TxRecoded;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_some() {
            // start
            self.0.take().map(|tx| tx.convert_recoded_tx())
        } else {
            match self.1.iter_mut().find(|tx| tx.is_some()) {
                Some(tx) => tx.take(),
                None => None,
            }
        }
    }
}

/// TxBody ref iterator
pub struct TxBodyIter<'a>(&'a TxBody, &'a Vec<TxRecoded>, usize);

impl StreamingIterator for TxBodyIter<'_> {
    type Item = TxBody;

    fn advance(&mut self) {
        self.2 += 1;
    }

    fn get(&self) -> Option<&Self::Item> {
        match self.2 {
            0 => Some(self.0),
            i => match self.1.get(i - 1) {
                Some(tx) => Some(&tx.body),
                None => None,
            },
        }
    }
}
