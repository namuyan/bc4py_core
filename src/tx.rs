use crate::signature::*;
use crate::utils::*;
use bigint::U256;

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

#[derive(Clone, PartialEq, Debug)]
pub struct TxOutput(pub Address, pub u32, pub u64); // (address<ver+ripemd160>, coinId, amount)

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
    pub fn to_bytes(&'a self) -> &'a [u8] {
        match self {
            TxMessage::Nothing => &[],
            TxMessage::Plain(s) => s.as_bytes(),
            TxMessage::Byte(b) => b.as_slice(),
            // TxMessage::MsgPack(_) => ?,
            // TxMessage:HashLocked(_) => ?,
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

/// Tx structure
///
/// bytes static: [version u32][type u32][time u32][deadline u32][gas_price u32][gas_amount i64][msg_type u8][input_len u8][output_len u8][msg_len u32]
/// bytes dynamic: [inputs ?*33b][outputs ?*33b][msg ?b]
#[derive(PartialEq)]
pub struct Tx {
    // TX body
    pub version: u32,   // 4bytes int
    pub txtype: TxType, // 4bytes int
    pub time: u32,      // 4bytes int
    pub deadline: u32,  // 4bytes int
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub gas_price: u64,     // fee
    pub gas_amount: i64,    // fee
    pub message: TxMessage, // length type is 2bytes but real length limit to 65536

    // for verify
    pub signature: Option<Vec<Signature>>,
    pub inputs_cache: Option<Vec<TxOutput>>,
}

impl std::fmt::Debug for Tx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = hex::encode(sha256double(&self.to_bytes()));
        f.debug_tuple("tx").field(&hash).finish()
    }
}

impl Tx {
    pub fn new(
        version: u32,
        txtype: TxType,
        time: u32,
        deadline: u32,
        gas_price: u64,
        gas_amount: i64,
        message: TxMessage,
    ) -> Self {
        assert!(message.length() <= 0xffff);
        Tx {
            version,
            txtype,
            time,
            deadline,
            inputs: vec![],
            outputs: vec![],
            gas_price,
            gas_amount,
            message,
            signature: None,
            inputs_cache: None,
        }
    }

    pub fn hash(&self) -> U256 {
        U256::from(sha256double(&self.to_bytes()).as_slice())
    }

    pub fn get_size(&self) -> usize {
        39 + self.inputs.len() * 33 + self.outputs.len() * 33 + self.message.length()
    }

    /// TX binary (without signature)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.get_size());

        // static 39bytes
        vec.extend_from_slice(&u32_to_bytes(self.version));
        vec.extend_from_slice(&u32_to_bytes(self.txtype.to_int()));
        vec.extend_from_slice(&u32_to_bytes(self.time));
        vec.extend_from_slice(&u32_to_bytes(self.deadline));
        vec.extend_from_slice(&u64_to_bytes(self.gas_price));
        vec.extend_from_slice(&i64_to_bytes(self.gas_amount));
        vec.push(self.message.to_int());
        assert!(self.inputs.len() < 256);
        vec.push(self.inputs.len() as u8);
        assert!(self.outputs.len() < 256);
        vec.push(self.outputs.len() as u8);
        assert!(self.message.length() < 256 * 256);
        vec.extend_from_slice(&u32_to_bytes(self.message.length() as u32));

        // inputs 33bytes
        for input in self.inputs.iter() {
            vec.extend_from_slice(&input.to_bytes());
        }

        // outputs 33bytes
        for output in self.outputs.iter() {
            vec.extend_from_slice(&output.to_bytes());
        }

        // message ?bytes
        vec.extend_from_slice(self.message.to_bytes());

        vec
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // cannot define bytes' correct size
        if bytes.len() < 39 {
            return Err(format!("too short input length to generate tx"));
        }

        // static 39bytes
        let version = bytes_to_u32(&bytes[0..4]);
        let txtype = TxType::from_int(bytes_to_u32(&bytes[4..8]))?;
        let time = bytes_to_u32(&bytes[8..12]);
        let deadline = bytes_to_u32(&bytes[12..16]);
        let gas_price = bytes_to_u64(&bytes[16..16 + 8]);
        let gas_amount = bytes_to_i64(&bytes[24..24 + 8]);
        let message_type = bytes[32];
        let input_len = bytes[33] as usize;
        let output_len = bytes[34] as usize;
        let msg_len = bytes_to_u32(&bytes[35..35 + 4]) as usize;

        let correct_size = 39 + input_len * 33 + output_len * 33 + msg_len;
        if bytes.len() != correct_size {
            return Err(format!(
                "wrong length to generate tx {}!={}",
                bytes.len(),
                correct_size
            ));
        }

        // input
        let mut position = 39;
        let mut inputs = Vec::with_capacity(input_len);
        for _ in 0..input_len {
            inputs.push(TxInput::from_bytes(&bytes[position..position + 33])?);
            position += 33;
        }

        // output
        let mut outputs = Vec::with_capacity(output_len);
        for _ in 0..output_len {
            outputs.push(TxOutput::from_bytes(&bytes[position..position + 33])?);
            position += 33;
        }

        // message
        let message_bytes = bytes[position..position + msg_len].to_vec();
        let message = TxMessage::new(message_type, message_bytes)?;

        Ok(Tx {
            version,
            txtype,
            time,
            deadline,
            inputs,
            outputs,
            gas_price,
            gas_amount,
            message,
            signature: None,
            inputs_cache: None,
        })
    }

    pub fn is_coinbase(&self) -> bool {
        self.txtype == TxType::PoW || self.txtype == TxType::PoS
    }

    pub fn get_signature_size(&self) -> Result<usize, String> {
        if self.signature.is_none() {
            return Err("signature is None".to_owned());
        }
        let mut size = 0;
        for signature in self.signature.as_ref().unwrap().iter() {
            size += get_signature_size(signature);
        }
        Ok(size)
    }

    pub fn get_signature_bytes(&self) -> Result<Vec<u8>, String> {
        if self.signature.is_none() {
            return Err("signature is not inserted but try to get binary".to_owned());
        }
        let signature = self.signature.as_ref().unwrap();
        let mut vec = Vec::with_capacity(signature.len() * (33 + 32 + 32));
        for signature in signature.iter() {
            signature_to_bytes(signature, &mut vec);
        }
        Ok(vec)
    }

    pub fn restore_signature_from_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.signature.is_some() {
            let len = self.signature.as_ref().unwrap().len();
            return Err(format!("signature is already inserted len={}", len));
        }
        let mut signature_vec = Vec::with_capacity(bytes.len() / (33 + 32 + 32) + 1);
        let mut position = 0;
        while position < bytes.len() {
            let signature = bytes_to_signature(&bytes[position..])?;
            position += get_signature_size(&signature);
            signature_vec.push(signature);
        }
        if bytes.len() != position {
            return Err(format!("signature decode failed {}!={}", bytes.len(), position));
        }
        self.signature = Some(signature_vec);
        Ok(())
    }

    pub fn get_depends_of_inputs(&self) -> Vec<U256> {
        self.inputs
            .iter()
            .map(|input| input.0.clone())
            .collect::<Vec<U256>>()
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod tx {
    use crate::signature::Signature;
    use crate::tx::*;
    use crate::utils::*;
    use bech32::{convert_bits, Bech32};
    use bigint::U256;
    use std::str::FromStr;

    /// return (hrp, version, identifier)
    fn addr2params(addr: &str) -> Result<(String, u8, Vec<u8>), bech32::Error> {
        let bech = Bech32::from_str(addr)?;
        let ver = match bech.data().get(0) {
            Some(ver) => ver.to_owned().to_u8(),
            None => return Err(bech32::Error::InvalidLength),
        };
        let identifier = convert_bits(&bech.data()[1..], 5, 8, false)?;
        Ok((bech.hrp().to_string(), ver, identifier))
    }

    #[test]
    fn body_encode_decode() {
        let binary = hex::decode("0000000002000000e1feaa011129ab0100000000000000000000000000000000000101000000001d8b62ab6307ac224374b6eda408f8d7048457bcc536b26ac7e5ec542df3581800005bafa406ba6f53f4573a4d5a8f17615e61d71ab20000000036b8071403000000").unwrap();
        let hash = hex::decode("602e270e18879f99bdb2e2ff19e6dfd0df127ef7a2eb40ceec3e92f477f92353").unwrap();
        let genesis_time = 1557883103;
        let inputs = vec![TxInput(
            string_to_u256("1d8b62ab6307ac224374b6eda408f8d7048457bcc536b26ac7e5ec542df35818"),
            0,
        )];

        let (_hrp, ver, data) = addr2params("test1qtwh6gp46daflg4e6f4dg79mptesawx4j4gy0dl").unwrap();
        let mut address = [0u8; 21];
        address[0] = ver;
        write_slice(&mut address[1..21], data.as_slice());
        let outputs = vec![TxOutput(address, 0, 13220952118)];
        let message = TxMessage::Nothing;

        // decode
        let tx = Tx::from_bytes(&binary).unwrap();

        assert_eq!(tx.version, 0);
        assert_eq!(tx.txtype, TxType::PoS);
        assert_eq!(tx.time, 1585866688 - genesis_time);
        assert_eq!(tx.deadline, 1585877488 - genesis_time);
        assert_eq!(tx.inputs, inputs);
        assert_eq!(tx.outputs, outputs);
        assert_eq!(tx.message, message);

        // encode
        assert_eq!(
            hex::encode(tx.to_bytes().as_slice()),
            hex::encode(binary.as_slice())
        );
        assert_eq!(tx.hash(), U256::from(hash.as_slice()));
    }

    #[test]
    fn sign_encode_decode() {
        let pk = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let r = hex::decode("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6").unwrap(); // r
        let s = hex::decode("7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05").unwrap(); // s
        let sig0 = Signature::new_single_sig(&pk, &r, &s).unwrap();

        let pk = hex::decode("0226d77f91bcfe366a4f9390c38a7c03d025e541940a881cca98ac4237a0352537").unwrap();
        let r = hex::decode("69039691323f6d26a1ab2903730496cf3247f258b438abdbd350e3cf2814e368").unwrap();
        let s = hex::decode("3c179ac0a44fa7f25c3f734ff9e29a85f9be1ea541a92ceb542882ab95e8aa2a").unwrap();
        let sig1 = Signature::new_aggregate_sig(&pk, &r, &s).unwrap();

        // dummy
        let mut tx = Tx::new(0, TxType::Transfer, 0, 0, 0, 0, TxMessage::Nothing);
        tx.signature = Some(vec![sig0, sig1]);

        // decode
        let binary = tx.get_signature_bytes().unwrap();

        let raw_hex = "\
        0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
        787a848e71043d280c50470e8e1532b2dd5d20ee912a45dbdd2bd1dfbf187ef6\
        7031a98831859dc34dffeedda86831842ccd0079e1f92af177f7f22cc1dced05\
        0526d77f91bcfe366a4f9390c38a7c03d025e541940a881cca98ac4237a0352537\
        69039691323f6d26a1ab2903730496cf3247f258b438abdbd350e3cf2814e368\
        3c179ac0a44fa7f25c3f734ff9e29a85f9be1ea541a92ceb542882ab95e8aa2a";
        assert_eq!(&hex::encode(binary.as_slice()), raw_hex);

        // clear
        let signature: Vec<Signature> = tx.signature.unwrap().drain(..).collect();
        tx.signature = None;

        // encode
        tx.restore_signature_from_bytes(hex::decode(raw_hex).unwrap().as_slice())
            .unwrap();

        assert_eq!(tx.signature, Some(signature));
    }
}
