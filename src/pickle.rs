use crate::block::*;
use crate::tx::{BlockTxs, TxBody, TxOutput, TxRecoded, TxVerifiable};
use crate::utils::*;
use bigint::U256;

/// full block pickle
/// static: [height u32][work 32b][header 80b][flag u8][bias f32][tx_len u32][input_cache_len u32]
/// dynamic: [tx0]..[txN] [input cache0]..[input cacheM]

pub fn pickle_full_block(block: &Block, txs: &Vec<TxVerifiable>) -> Result<Vec<u8>, String> {
    assert_eq!(block.txs_hash.len(), txs.len());
    assert!(0 < txs.len());
    let input_cache = &txs.get(0).unwrap().inputs_cache;
    let mut value = Vec::with_capacity(4 + 32 + 80 + 1 + 4 + 4 + 4);

    // static
    value.extend_from_slice(&u32_to_bytes(block.height));
    value.extend_from_slice(&u256_to_bytes(&block.work_hash));
    value.extend_from_slice(&block.header.to_bytes());
    value.push(block.flag.to_int());
    value.extend_from_slice(&f32_to_bytes(block.bias));
    value.extend_from_slice(&u32_to_bytes(txs.len() as u32));
    value.extend_from_slice(&u32_to_bytes(input_cache.len() as u32));

    // malloc
    let size = txs.len() * 4 * 2
        + txs
            .iter()
            .map(|tx| tx.body.get_size() + tx.get_signature_size())
            .sum::<usize>()
        + input_cache.len() * 33;
    value.reserve(size);

    // tx
    for tx in txs.iter() {
        // [tx size u32][tx sig size u32][tx_b Xb][tx_sig Xb]
        value.extend_from_slice(&u32_to_bytes(tx.body.get_size() as u32));
        value.extend_from_slice(&u32_to_bytes(tx.get_signature_size() as u32));
        value.extend_from_slice(&tx.body.to_bytes());
        value.extend_from_slice(&tx.get_signature_bytes());
    }

    // coinbase tx's input_cache
    for output in input_cache {
        value.extend_from_slice(output.to_bytes().as_ref());
    }

    Ok(value)
}

pub fn unpickle_full_block(bytes: &[u8]) -> (Block, BlockTxs, Vec<usize>) {
    let height = bytes_to_u32(&bytes[0..4]);
    let work_hash = U256::from(&bytes[4..4 + 32]);
    let header = BlockHeader::from_bytes(&bytes[36..36 + 80]);
    let flag = BlockFlag::from_int(bytes[116]).unwrap();
    let bias = bytes_to_f32(&bytes[117..117 + 4]);
    let tx_len = bytes_to_u32(&bytes[121..121 + 4]) as usize;
    let input_cache_len = bytes_to_u32(&bytes[125..125 + 4]) as usize;

    // tx
    let mut pos = 129;
    let mut txs = Vec::with_capacity(tx_len);
    let mut txs_hash = Vec::with_capacity(tx_len);
    let mut tx_offset = Vec::with_capacity(tx_len);
    for _ in 0..tx_len {
        tx_offset.push(pos);
        let tx_size = bytes_to_u32(&bytes[pos..pos + 4]) as usize;
        pos += 4;
        let sig_size = bytes_to_u32(&bytes[pos..pos + 4]) as usize;
        pos += 4;
        let body = TxBody::from_bytes(&bytes[pos..pos + tx_size]).unwrap();
        pos += tx_size;
        let tx = TxRecoded::restore(body, &bytes[pos..pos + sig_size]);
        pos += sig_size;
        txs_hash.push(tx.hash.clone());
        txs.push(tx);
    }

    // coinbase tx's input_cache
    let coinbase = txs.remove(0);
    let mut input_cache = Vec::with_capacity(input_cache_len);
    for _ in 0..input_cache_len {
        input_cache.push(TxOutput::from_bytes(&bytes[pos..pos + 33]).unwrap());
        pos += 33;
    }
    let coinbase = TxVerifiable {
        hash: coinbase.hash,
        body: coinbase.body,
        signature: coinbase.signature,
        inputs_cache: input_cache,
    };

    // check
    assert_eq!(bytes.len(), pos, "block restore failed by size mismatch");
    // success
    let block = Block {
        work_hash,
        height,
        flag,
        bias,
        header,
        txs_hash,
    };
    (block, BlockTxs::new(coinbase, txs), tx_offset)
}

pub fn unpickle_block(bytes: &[u8]) -> Block {
    // static
    let height = bytes_to_u32(&bytes[0..4]);
    let work_hash = U256::from(&bytes[4..4 + 32]);
    let header = BlockHeader::from_bytes(&bytes[36..36 + 80]);
    let flag = BlockFlag::from_int(bytes[116]).unwrap();
    let bias = bytes_to_f32(&bytes[117..117 + 4]);
    let tx_len = bytes_to_u32(&bytes[121..121 + 4]) as usize;
    let input_cache_len = bytes_to_u32(&bytes[125..125 + 4]) as usize;

    // dynamic
    let mut pos = 129;
    let mut txs_hash = Vec::with_capacity(tx_len);
    for _ in 0..tx_len {
        let tx_size = bytes_to_u32(&bytes[pos..pos + 4]) as usize;
        pos += 4;
        let sig_size = bytes_to_u32(&bytes[pos..pos + 4]) as usize;
        pos += 4;
        let hash = sha256double(&bytes[pos..pos + tx_size]);
        pos += tx_size;
        pos += sig_size;
        txs_hash.push(U256::from(hash.as_slice()));
    }

    // coinbase input_cache
    pos += input_cache_len * 33;

    // check
    assert_eq!(bytes.len(), pos, "block restore failed by size mismatch");
    // success
    Block {
        work_hash,
        height,
        flag,
        bias,
        header,
        txs_hash,
    }
}

pub fn pickle_txcache(tx: &TxVerifiable) -> Vec<u8> {
    // [tx size u32][sig size u32][input size u32][tx_b Xb][tx_sig Xb][input cache 33b]..
    let inputs_cache = &tx.inputs_cache;
    let size = 12 + tx.body.get_size() + tx.get_signature_size() + inputs_cache.len() * 33;
    let mut vec = Vec::with_capacity(size);
    vec.extend_from_slice(&u32_to_bytes(tx.body.get_size() as u32));
    vec.extend_from_slice(&u32_to_bytes(tx.get_signature_size() as u32));
    vec.extend_from_slice(&u32_to_bytes(inputs_cache.len() as u32));
    vec.extend_from_slice(&tx.body.to_bytes());
    vec.extend_from_slice(&tx.get_signature_bytes());
    for output in inputs_cache {
        vec.extend_from_slice(output.to_bytes().as_ref());
    }
    vec
}

pub fn unpickle_txcache(bytes: &[u8]) -> TxVerifiable {
    // [tx size u32][sig size u32][input size u32][tx_b Xb][tx_sig Xb][input cache 33b]..
    let tx_size = bytes_to_u32(&bytes[0..4]) as usize;
    let sig_size = bytes_to_u32(&bytes[4..4 + 4]) as usize;
    let input_size = bytes_to_u32(&bytes[8..8 + 4]) as usize;
    let body = TxBody::from_bytes(&bytes[12..12 + tx_size]).unwrap();
    let tx = TxRecoded::restore(body, &bytes[12 + tx_size..12 + tx_size + sig_size]);

    let mut pos = 12 + tx_size + sig_size;
    let mut inputs_cache = Vec::with_capacity(input_size);
    for _ in 0..input_size {
        inputs_cache.push(TxOutput::from_bytes(&bytes[pos..pos + 33]).unwrap());
        pos += 33;
    }
    let tx = TxVerifiable {
        hash: tx.hash,
        body: tx.body,
        signature: tx.signature,
        inputs_cache,
    };
    // check
    assert_eq!(pos, bytes.len());
    // success
    tx
}

#[allow(unused_imports)]
#[cfg(test)]
mod test {
    use crate::block::*;
    use crate::pickle::*;
    use crate::signature::*;
    use crate::tx::{TxBody, TxManual, TxMessage, TxOutput, TxType, TxVerifiable};
    use crate::utils::*;
    use bigint::U256;
    use streaming_iterator::StreamingIterator;

    fn get_dummy_block() -> (Block, Vec<TxVerifiable>) {
        let body = TxBody::new(
            2,
            TxType::PoW,
            100,
            200,
            300,
            0,
            TxMessage::Plain("hello python".to_owned()),
        );
        let coinbase = TxVerifiable {
            hash: U256::from(body.hash().as_slice()),
            body,
            signature: vec![],
            inputs_cache: vec![TxOutput(*b"222444422133331112332", 100, 200)],
        };

        // dummy tx
        let body = TxBody::new(2, TxType::Transfer, 100, 200, 300, 100, TxMessage::Nothing);
        let pk = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let r = hex::decode("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6").unwrap(); // r
        let s = hex::decode("7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05").unwrap(); // s
        let sig = Signature::new_single_sig(&pk, &r, &s).unwrap();
        let mut tx = TxVerifiable {
            hash: U256::from(body.hash().as_slice()),
            body,
            signature: vec![sig],
            inputs_cache: vec![],
        };

        let txs = vec![coinbase, tx];
        let tx_hash: Vec<U256> = txs
            .iter()
            .map(|_tx| U256::from(_tx.body.hash().as_slice()))
            .collect();

        // dummy block
        let header = BlockHeader {
            version: 1,
            time: 2,
            bits: 0x1effffff,
            nonce: 3,
            previous_hash: string_to_u256("171fadce3703d6f7624c49a22ca7984a2b8a31bb1dd532e1dd47f754458ea845"),
            merkleroot: string_to_u256("016056c4b0a8f0a773934916f08a9cf6819ea56d8148d12ee6615e87b29b523c"),
        };
        let work_hash = string_to_u256("1281ff15ded46eecf06c4c65f2c63736680ec798e8fb4d1e1be005a100000000");
        let block = Block::new(work_hash, 1000, BlockFlag::Genesis, 1.2, header, tx_hash);

        (block, txs)
    }

    #[test]
    fn full_block() {
        let (block, txs) = self::get_dummy_block();

        // encode
        let bytes = pickle_full_block(&block, &txs).unwrap();

        // decode
        let (new_block, new_txs, _) = unpickle_full_block(&bytes);
        assert_eq!(new_block, block);
        assert_eq!(new_txs.len(), txs.len());
        for (new_tx, tx) in new_txs.into_iter().zip(txs.into_iter()) {
            let tx = tx.convert_recoded_tx();
            assert_eq!(new_tx, tx);
        }
    }

    #[test]
    fn block() {
        let (block, txs) = self::get_dummy_block();

        // encode
        let bytes = pickle_full_block(&block, &txs).unwrap();

        // decode
        let new_block = unpickle_block(&bytes);

        assert_eq!(new_block, block);
    }

    #[test]
    fn txcache() {
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
        let tx = TxVerifiable {
            hash: U256::from(body.hash().as_slice()),
            body,
            signature: vec![sig0, sig1],
            inputs_cache: vec![
                TxOutput(*b"000000000000000000000", 0, 10000),
                TxOutput(*b"111111111111111111111", 2, 20000),
            ],
        };

        // decode
        let binary = pickle_txcache(&tx);

        // encode
        let new_tx = unpickle_txcache(&binary);

        assert_eq!(new_tx, tx);
    }
}
