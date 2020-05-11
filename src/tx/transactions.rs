use crate::signature::*;
use crate::tx::*;
use crate::utils::*;
use bigint::U256;
use std::fmt;

/// transaction body
#[derive(Clone, PartialEq)]
pub struct TxBody {
    pub version: u32,
    pub txtype: TxType,
    pub time: u32,
    pub deadline: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    // fee
    pub gas_price: u64,
    pub gas_amount: i64,
    // length type is 2bytes but real length limit to 65536
    pub message: TxMessage,
}

impl fmt::Debug for TxBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("body")
            .field(&self.version)
            .field(&self.txtype)
            .field(&self.time)
            .field(&self.inputs)
            .field(&self.outputs)
            .field(&self.gas_price)
            .field(&self.gas_amount)
            .field(&self.message)
            .finish()
    }
}

impl TxBody {
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
        TxBody {
            version,
            txtype,
            time,
            deadline,
            inputs: vec![],
            outputs: vec![],
            gas_price,
            gas_amount,
            message,
        }
    }

    pub fn hash(&self) -> Vec<u8> {
        sha256double(&self.to_bytes())
    }

    pub fn get_size(&self) -> usize {
        39 + self.inputs.len() * 33 + self.outputs.len() * 33 + self.message.length()
    }

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

        Ok(TxBody {
            version,
            txtype,
            time,
            deadline,
            inputs,
            outputs,
            gas_price,
            gas_amount,
            message,
        })
    }

    pub fn is_coinbase(&self) -> bool {
        self.txtype == TxType::PoW || self.txtype == TxType::PoS
    }

    pub fn get_depends_of_inputs(&self) -> Vec<U256> {
        self.inputs
            .iter()
            .map(|input| input.0.clone())
            .collect::<Vec<U256>>()
    }
}

/// from tables **read-only**
#[derive(Clone, PartialEq)]
pub struct TxRecoded {
    pub hash: U256,
    pub body: TxBody,
    pub signature: Vec<Signature>,
}

impl fmt::Debug for TxRecoded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"type", &"recoded")
            .entry(&"hash", &u256_to_hex(&self.hash))
            .entry(&"body", &self.body)
            .entry(&"sign", &self.signature)
            .finish()
    }
}

impl TxRecoded {
    pub fn restore(body: TxBody, sign: &[u8]) -> Self {
        let mut signature = Vec::with_capacity(sign.len() / (33 + 32 + 32) + 1);
        let mut pos = 0;
        while pos < sign.len() {
            let sign = bytes_to_signature(&sign[pos..]).unwrap();
            pos += get_signature_size(&sign);
            signature.push(sign);
        }
        assert_eq!(sign.len(), pos, "signature deserialize failed by mismatch");
        TxRecoded {
            hash: U256::from(body.hash().as_slice()),
            body,
            signature,
        }
    }

    pub fn get_signature_size(&self) -> usize {
        let mut size = 0;
        for signature in self.signature.iter() {
            size += get_signature_size(signature);
        }
        size
    }

    pub fn get_signature_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.signature.len() * (33 + 32 + 32));
        for signature in self.signature.iter() {
            signature_to_bytes(signature, &mut vec);
        }
        vec
    }
}

/// **read-only**
/// form tables (coinbase) and from txcache (normal)
#[derive(Clone, PartialEq)]
pub struct TxVerifiable {
    pub hash: U256,
    pub body: TxBody,
    pub signature: Vec<Signature>,
    pub inputs_cache: Vec<TxOutput>,
}

impl fmt::Debug for TxVerifiable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"type", &"verifiable")
            .entry(&"hash", &u256_to_hex(&self.hash))
            .entry(&"body", &self.body)
            .entry(&"sign", &self.signature)
            .entry(&"inputs_cache", &self.inputs_cache)
            .finish()
    }
}

impl TxVerifiable {
    pub fn get_signature_size(&self) -> usize {
        let mut size = 0;
        for signature in self.signature.iter() {
            size += get_signature_size(signature);
        }
        size
    }

    pub fn get_signature_bytes(&self) -> Vec<u8> {
        let mut vec = Vec::with_capacity(self.signature.len() * (33 + 32 + 32));
        for signature in self.signature.iter() {
            signature_to_bytes(signature, &mut vec);
        }
        vec
    }

    pub fn convert_recoded_tx(self) -> TxRecoded {
        TxRecoded {
            hash: self.hash,
            body: self.body,
            signature: self.signature,
        }
    }
}

/// manually generated to convert to `TxVerifiable`
#[derive(Clone, PartialEq)]
pub struct TxManual {
    pub body: TxBody,
    pub signature: Option<Vec<Signature>>,
    pub inputs_cache: Option<Vec<TxOutput>>,
}

impl fmt::Debug for TxManual {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entry(&"type", &"manual")
            .entry(&"hash", &hex::encode(&self.body.hash()))
            .entry(&"body", &self.body)
            .entry(&"sign", &self.signature)
            .entry(&"inputs_cache", &self.inputs_cache)
            .finish()
    }
}

impl TxManual {
    pub fn new(body: TxBody) -> Self {
        TxManual {
            body,
            signature: None,
            inputs_cache: None,
        }
    }

    pub fn hash(&self) -> U256 {
        U256::from(self.body.hash().as_slice())
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
        let mut sign_vec = Vec::with_capacity(bytes.len() / (33 + 32 + 32) + 1);
        let mut pos = 0;
        while pos < bytes.len() {
            let signature = bytes_to_signature(&bytes[pos..])?;
            pos += get_signature_size(&signature);
            sign_vec.push(signature);
        }
        if bytes.len() != pos {
            return Err(format!("signature decode failed {}!={}", bytes.len(), pos));
        }
        self.signature = Some(sign_vec);
        Ok(())
    }

    pub fn convert_verifiable(self) -> Result<TxVerifiable, String> {
        Ok(TxVerifiable {
            hash: self.hash(),
            body: self.body,
            signature: self
                .signature
                .ok_or("cannot convert to verifiable because signature is none".to_owned())?,
            inputs_cache: self
                .inputs_cache
                .ok_or("cannot convert to verifiable because input_cache is none".to_owned())?,
        })
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

    #[test]
    fn body_encode_decode() {
        let binary = hex::decode("0000000002000000e1feaa011129ab0100000000000000000000000000000000000101000000001d8b62ab6307ac224374b6eda408f8d7048457bcc536b26ac7e5ec542df3581800005bafa406ba6f53f4573a4d5a8f17615e61d71ab20000000036b8071403000000").unwrap();
        let hash = hex::decode("602e270e18879f99bdb2e2ff19e6dfd0df127ef7a2eb40ceec3e92f477f92353").unwrap();
        let genesis_time = 1557883103;
        let inputs = vec![TxInput(
            string_to_u256("1d8b62ab6307ac224374b6eda408f8d7048457bcc536b26ac7e5ec542df35818"),
            0,
        )];

        // debug use `test` prefix
        set_global_hrp("test");

        let address = string2addr("test1qtwh6gp46daflg4e6f4dg79mptesawx4j4gy0dl").unwrap();
        let outputs = vec![TxOutput(address, 0, 13220952118)];
        let message = TxMessage::Nothing;

        // decode
        let body = TxBody::from_bytes(&binary).unwrap();

        assert_eq!(body.version, 0);
        assert_eq!(body.txtype, TxType::PoS);
        assert_eq!(body.time, 1585866688 - genesis_time);
        assert_eq!(body.deadline, 1585877488 - genesis_time);
        assert_eq!(body.inputs, inputs);
        assert_eq!(body.outputs, outputs);
        assert_eq!(body.message, message);

        // encode
        assert_eq!(
            hex::encode(body.to_bytes().as_slice()),
            hex::encode(binary.as_slice())
        );
        assert_eq!(body.hash(), hash);
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
        let body = TxBody::new(0, TxType::Transfer, 0, 0, 0, 0, TxMessage::Nothing);
        let mut tx = TxManual::new(body);
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
