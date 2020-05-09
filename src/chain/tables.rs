use crate::balance::BalanceMovement;
use crate::block::*;
use crate::chain::{iters::*, utils::*};
use crate::pickle::*;
use crate::tx::{BlockTxs, TxBody, TxInput, TxOutput, TxRecoded, TxVerifiable};
use crate::utils::*;
use bigint::U256;
use rocksdb::{DBIterator, Direction, IteratorMode, Options, WriteBatch, WriteOptions, DB};
use serde::{Deserialize, Serialize};
use serde_json::{from_reader, to_writer_pretty};
use std::fs::{create_dir_all, remove_dir_all, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

static TABLE_VERSION: &str = "0.1.0";
static KVS_NAME: &str = "rocksdb";
type Address = [u8; 21];

#[derive(Serialize, Deserialize, Debug)]
pub struct TableOptions {
    pub version: String,
    pub kvs_name: String,
    pub tx_index: bool,
    pub addr_index: bool,
    pub timeout: Option<f32>,
    pub sync: bool,
}

impl PartialEq for TableOptions {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.kvs_name == other.kvs_name
            && self.tx_index == other.tx_index
            && self.addr_index == other.addr_index
    }
}

impl TableOptions {
    pub fn new() -> Self {
        Self {
            version: TABLE_VERSION.to_owned(),
            kvs_name: KVS_NAME.to_owned(),
            tx_index: false,
            addr_index: false,
            timeout: None,
            sync: false,
        }
    }

    pub fn check_config_and_create(&self, dir: &Path) -> Result<bool, String> {
        let path = dir.join("config.json");
        if !dir.is_dir() {
            // not found database dir? need to create at first
            Ok(false)
        } else if path.exists() {
            // find config file and check same
            let fs = File::open(&path).map_err(|err| err.to_string())?;
            let read: TableOptions = from_reader(&fs).map_err(|err| err.to_string())?;
            Ok(&read == self)
        } else {
            // not found config and create first
            let fs = File::create(&path).map_err(|err| err.to_string())?;
            to_writer_pretty(&fs, &self).map_err(|err| err.to_string())?;
            Ok(true)
        }
    }

    pub fn check_status_and_create(&self, dir: &Path) -> Result<bool, String> {
        // check graceful exit
        // status flag (working or release)
        fn _inner(dir: &Path) -> std::io::Result<bool> {
            let path = dir.join("status.txt");
            let mut buf = vec![];
            if !dir.is_dir() {
                Ok(false)
            } else if path.exists() {
                // already exist and check status
                {
                    let mut fs = File::open(&path)?;
                    fs.read_to_end(&mut buf)?;
                }
                if buf.starts_with(b"released") {
                    let mut fs = File::create(&path)?;
                    fs.seek(SeekFrom::Start(0))?;
                    fs.write(b"working")?;
                    Ok(true)
                } else {
                    // need recreate
                    Ok(false)
                }
            } else {
                // write working flag
                let mut fs = File::create(&path)?;
                fs.write(b"working")?;
                Ok(true)
            }
        }
        // to escape error type
        _inner(dir).map_err(|err| format!("error on check status flag: {:?}", err))
    }

    pub fn release_status_flag(&self, dir: &Path) -> Result<(), String> {
        // note: call before table close
        fn _inner(dir: &Path) -> std::io::Result<()> {
            let path = dir.join("status.txt");
            let mut fs = File::create(&path)?;
            // write release flag
            fs.seek(SeekFrom::Start(0))?;
            fs.write(b"released")?;
            Ok(())
        }
        // to escape error type
        _inner(dir).map_err(|err| format!("error on release status flag: {:?}", err))
    }
}

pub struct Tables {
    // info
    pub dir: PathBuf,
    pub table_opts: TableOptions,
    pub initialized: bool, // create tables at first
    pub is_closed: bool,   // close flag (cannot write but can read)

    // chain
    block: DB,
    block_index: DB,
    utxo_index: DB,
    tx_index: DB,
    addr_index: DB,
    mint: DB,

    // tx cache
    txcache: DB,

    // account
    account: DB,
    movement: DB,
}

impl Tables {
    pub fn new(dir: &Path, table_opts: TableOptions) -> Result<Self, String> {
        // note: need initialize database
        let mut initialized = false;

        // create database folder if not exist
        if !dir.exists() {
            create_dir_all(dir).unwrap();
            initialized = true;
        }

        // require same table option & status
        if !table_opts.check_config_and_create(dir)? || !table_opts.check_status_and_create(dir)? {
            // remove
            remove_dir_all(dir).unwrap();
            // sleep 200ms to escape permission deny on windows
            std::thread::sleep(std::time::Duration::from_millis(200));
            // recreate
            create_dir_all(dir).unwrap();
            // check
            assert!(table_opts.check_config_and_create(dir)?);
            assert!(table_opts.check_status_and_create(dir)?);
            // success
            initialized = true;
        }

        // setup database options
        let mut rocks_opts = Options::default();
        rocks_opts.create_if_missing(initialized);

        // setup database objects
        let block = DB::open(&rocks_opts, dir.join("block")).unwrap();
        let block_index = DB::open(&rocks_opts, dir.join("block_index")).unwrap();
        let utxo_index = DB::open(&rocks_opts, dir.join("utxo_index")).unwrap();
        let tx_index = DB::open(&rocks_opts, dir.join("tx_index")).unwrap();
        let addr_index = DB::open(&rocks_opts, dir.join("addr_index")).unwrap();
        let mint = DB::open(&rocks_opts, dir.join("mint")).unwrap();
        let account = DB::open(&rocks_opts, dir.join("account")).unwrap();
        let movement = DB::open(&rocks_opts, dir.join("movement")).unwrap();
        let txcache = DB::open(&rocks_opts, dir.join("txcache")).unwrap();

        Ok(Tables {
            dir: dir.to_path_buf(),
            table_opts,
            initialized,
            is_closed: false,
            block,
            block_index,
            utxo_index,
            tx_index,
            addr_index,
            mint,
            account,
            movement,
            txcache,
        })
    }

    /// warning: destroy myself
    pub fn close_and_destroy(self) {
        let dir = self.dir.clone();
        std::mem::drop(self);
        remove_dir_all(&dir).unwrap();
    }

    pub fn close(&mut self) {
        self.is_closed = true;
        self.table_opts
            .release_status_flag(self.dir.as_ref())
            .expect("unexpected write status exception?");
    }

    /// start table transaction
    pub fn transaction(&mut self) -> TableCursor {
        assert!(!self.is_closed, "already closed!");
        TableCursor {
            tables: self,
            transaction_time: Instant::now(),
            block: WriteBatch::default(),
            block_index: WriteBatch::default(),
            utxo_index: WriteBatch::default(),
            tx_index: WriteBatch::default(),
            addr_index: WriteBatch::default(),
            mint: WriteBatch::default(),
            account: WriteBatch::default(),
            movement: WriteBatch::default(),
            txcache: WriteBatch::default(),
        }
    }

    pub fn read_block(&self, hash: &U256) -> Result<Option<Block>, String> {
        // [blockhash 32b] -> [block bin Xb]
        match self.block.get(&u256_to_bytes(hash)) {
            Ok(value) => match value {
                Some(value) => {
                    let block = unpickle_block(value.as_slice());
                    Ok(Some(block))
                },
                None => Ok(None),
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn read_full_block(&self, hash: &U256) -> Result<Option<(Block, BlockTxs)>, String> {
        // [blockhash 32b] -> [block bin Xb]
        match self.block.get(&u256_to_bytes(hash)) {
            Ok(value) => match value {
                Some(value) => {
                    let (block, txs, _) = unpickle_full_block(&value);
                    Ok(Some((block, txs)))
                },
                None => Ok(None),
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn read_block_index(&self, height: u32) -> Result<Option<U256>, String> {
        // [height u32] -> [blockhash U256]
        let key = big_endian_from_u32(height);
        match self.block_index.get(&key) {
            Ok(value) => match value {
                Some(value) => Ok(Some(U256::from(value.as_slice()))),
                None => Ok(None),
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn read_block_index_iter(&self, start_height: u32) -> DBIterator {
        // [height u32] -> [blockhash U256]
        let key = big_endian_from_u32(start_height);
        // include_start = true
        self.block_index
            .iterator(IteratorMode::From(&key, Direction::Forward))
    }

    pub fn read_tx(&self, hash: &U256) -> Result<Option<TxRecoded>, String> {
        // tx_index: [txhash 32b] -> [height u32][offset u32]
        let txhash = u256_to_bytes(hash);
        match self.tx_index.get(&txhash) {
            Ok(value) => match value {
                Some(value) => {
                    let height = bytes_to_u32(&value[0..4]);
                    let mut offset = bytes_to_u32(&value[4..4 + 4]) as usize;

                    // get binary
                    let blockhash = self.read_block_index(height)?.expect("get blockhash but none");
                    let blockhash = u256_to_bytes(&blockhash);
                    let bytes = self
                        .block
                        .get(&blockhash)
                        .map_err(|err| err.to_string())?
                        .expect("get block but none");

                    // decode
                    let tx_size = bytes_to_u32(&bytes[offset..offset + 4]) as usize;
                    offset += 4;
                    let sig_size = bytes_to_u32(&bytes[offset..offset + 4]) as usize;
                    offset += 4;
                    let body = TxBody::from_bytes(&bytes[offset..offset + tx_size])?;
                    offset += tx_size;
                    let tx = TxRecoded::restore(body, &bytes[offset..offset + sig_size]);
                    // offset += sig_size;

                    // success
                    Ok(Some(tx))
                },
                None => {
                    if self.table_opts.tx_index {
                        Ok(None)
                    } else {
                        Err("tx indexed but".to_owned())
                    }
                },
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn have_the_tx(&self, hash: &U256) -> Result<bool, String> {
        // tx_index: [txhash] -> [height][offset]
        let txhash = u256_to_bytes(hash);
        match self.tx_index.get(&txhash) {
            Ok(value) => Ok(value.is_some()),
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn read_utxo_index(&self, input: &TxInput) -> Result<Option<TxOutput>, String> {
        // [txhash 32b][output_index u8] -> [address 21b][coin_id u32][amount u64]
        let key = input.to_bytes();
        match self.utxo_index.get(key.as_ref()) {
            Ok(value) => match value {
                Some(value) => Ok(Some(TxOutput::from_bytes(&value).unwrap())),
                // `None` means used or no exist output.
                None => Ok(None),
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn read_addr_iter(&self, addr: &Address) -> AddrIter {
        // [address 21b][txhash 32b][output_index u8] -> [coin_id u32][amount u64]
        let mut key = [0u8; 21 + 32 + 1];
        write_slice(&mut key[0..21], addr);
        let mode = IteratorMode::From(&key, Direction::Forward);
        AddrIter {
            addr: addr.clone(),
            iter: self.addr_index.iterator(mode),
        }
    }

    pub fn read_mint_iter(&self, coin_id: u32) -> DBIterator {
        // [coin_id u32][height u32][index u32] -> [txhash 32b][params ?][setting ?]
        let mut key = [0u8; 4 + 4 + 4];
        write_slice(&mut key[0..4], &u32_to_bytes(coin_id));
        self.mint.iterator(IteratorMode::From(&key, Direction::Forward));
        unimplemented!("read mint")
    }

    pub fn read_account_iter(&self) -> DBIterator {
        // [account_id u32] -> [account bytes xb]
        self.account.iterator(IteratorMode::Start)
    }

    pub fn read_movement_iter(&self) -> DBIterator {
        // 32 bytes key: [txhash 32b] -> [movement bytes xb]
        // or
        // 8 bytes key: [height u32][position u32] -> [movement bytes xb]
        // stream from 8 bytes to 32 bytes, you need to check 8 length
        let mode = IteratorMode::From(b"\xff\xff\xff\xff\xff\xff\xff\xff", Direction::Reverse);
        // note: iterate from new to old
        self.movement.iterator(mode)
    }

    pub fn read_temporary_movement(&self, hash: &U256) -> Result<Option<BalanceMovement>, String> {
        // 32 bytes key: [txhash 32b] -> [movement bytes xb]
        // or
        // 8 bytes key: [height u32][tx index u32] -> [movement bytes xb]
        // note: temporary means 32bytes hash key
        let key = u256_to_bytes(hash);
        match self.movement.get(key.as_ref()) {
            Ok(value) => match value {
                Some(value) => Ok(Some(BalanceMovement::from_bytes(&value))),
                None => Ok(None),
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn read_txcache(&self, hash: &U256) -> Result<Option<TxVerifiable>, String> {
        // [txhash 32b] -> [txcache bytes Xb]
        // note: don't include coinbase tx
        let key = u256_to_bytes(hash);
        match self.txcache.get(key.as_ref()) {
            Ok(value) => match value {
                Some(value) => Ok(Some(unpickle_txcache(&value))),
                None => Ok(None),
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn read_txcache_iter(&self) -> DBIterator {
        // [txhash 32b] -> [txcache bytes Xb]
        self.txcache.iterator(IteratorMode::Start)
    }
}

pub struct TableCursor<'a> {
    // tables is locked by mutable borrow
    pub tables: &'a mut Tables,
    transaction_time: Instant,
    block: WriteBatch,
    block_index: WriteBatch,
    utxo_index: WriteBatch,
    tx_index: WriteBatch,
    addr_index: WriteBatch,
    mint: WriteBatch,
    account: WriteBatch,
    movement: WriteBatch,
    txcache: WriteBatch,
}

impl TableCursor<'_> {
    /// commit a transaction & return elapsed secs
    pub fn commit(self) -> Result<f32, rocksdb::Error> {
        assert!(!self.tables.is_closed, "already closed!");
        let mut writeopts = WriteOptions::default();
        writeopts.set_sync(self.tables.table_opts.sync);

        // write
        self.tables.block.write_opt(self.block, &writeopts)?;
        self.tables.block_index.write_opt(self.block_index, &writeopts)?;
        self.tables.utxo_index.write_opt(self.utxo_index, &writeopts)?;
        self.tables.tx_index.write_opt(self.tx_index, &writeopts)?;
        self.tables.addr_index.write_opt(self.addr_index, &writeopts)?;
        self.tables.mint.write_opt(self.mint, &writeopts)?;
        self.tables.account.write_opt(self.account, &writeopts)?;
        self.tables.movement.write_opt(self.movement, &writeopts)?;
        self.tables.txcache.write_opt(self.txcache, &writeopts)?;

        // return transaction duration
        Ok(self.transaction_time.elapsed().as_secs_f32())
    }

    pub fn write_block(&mut self, block: &Block, txs: &Vec<TxVerifiable>) -> Result<(), String> {
        // [blockhash 32b] -> [height u32][time u32][work 32b][header 80b][flag u8][bias f32][tx_len u32] [tx0]..[txN]

        let key = sha256double(&block.header.to_bytes());
        let value = pickle_full_block(block, txs)?;

        self.block.put(&key, &value).map_err(|err| err.to_string())
    }

    pub fn write_block_index(&mut self, height: u32, header: &BlockHeader) -> Result<(), String> {
        // [height u32] -> [blockhash U256]

        let key = big_endian_from_u32(height);
        let value = sha256double(&header.to_bytes());

        self.block_index.put(&key, &value).map_err(|err| err.to_string())
    }

    pub fn write_utxo_index(&mut self, body: &TxBody) -> Result<(), String> {
        // [txhash 32b][output_index u8] -> [address 21b][coin_id u32][amount u64]

        // remove used UTXO
        for input in body.inputs.iter() {
            self.utxo_index
                .delete(input.to_bytes().as_ref())
                .map_err(|err| err.to_string())?;
        }

        // add unused UTXO
        let mut key = [0u8; 32 + 1];
        let txhash = sha256double(body.to_bytes().as_slice());
        write_slice(&mut key[0..32], &txhash);
        for (index, output) in body.outputs.iter().enumerate() {
            key[32] = index as u8;
            self.utxo_index
                .put(key.as_ref(), output.to_bytes().as_ref())
                .map_err(|err| err.to_string())?;
        }
        Ok(())
    }

    pub fn write_tx_index(&mut self, blockhash: &U256, indexed_txs: &Vec<U256>) -> Result<(), String> {
        // [txhash 32b] -> [height u32][offset u32]
        // note: block is already recoded
        // note: recode only specific txs
        match self.tables.block.get(&u256_to_bytes(blockhash)) {
            Ok(value) => match value {
                Some(value) => {
                    let (block, txs, tx_offset) = unpickle_full_block(&value);
                    let mut value = [0u8; 4 + 4];
                    write_slice(&mut value[0..4], &u32_to_bytes(block.height));
                    // check for each txhash include
                    for txhash in indexed_txs {
                        match txs.position(txhash) {
                            Some(index) => {
                                let offset = *tx_offset.get(index).unwrap() as u32;
                                write_slice(&mut value[4..4 + 4], &u32_to_bytes(offset));
                                self.tx_index
                                    .put(&u256_to_bytes(txhash), &value)
                                    .map_err(|err| err.to_string())?;
                            },
                            None => return Err("not found txhash on unbuckled data".to_owned()),
                        }
                    }
                    Ok(())
                },
                None => Err("not found blockhash".to_owned()),
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    #[allow(dead_code)]
    pub fn write_tx_full_index(&mut self, blockhash: &U256) -> Result<(), String> {
        // [txhash 32b] -> [height u32][offset u32]
        // note: block is already recoded
        match self.tables.block.get(&u256_to_bytes(blockhash)) {
            Ok(value) => match value {
                Some(value) => {
                    let (block, txs, tx_offset) = unpickle_full_block(&value);
                    let mut value = [0u8; 4 + 4];
                    write_slice(&mut value[0..4], &u32_to_bytes(block.height));
                    assert_eq!(txs.len(), tx_offset.len());
                    for (txhash, offset) in block.txs_hash.iter().zip(tx_offset) {
                        write_slice(&mut value[4..4 + 4], &u32_to_bytes(offset as u32));
                        self.tx_index
                            .put(&u256_to_bytes(txhash), &value)
                            .map_err(|err| err.to_string())?;
                    }
                    Ok(())
                },
                None => Err("not found blockhash".to_owned()),
            },
            Err(err) => Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn write_addr_index(
        &mut self,
        output: &TxOutput,
        txhash: &U256,
        output_index: u8,
    ) -> Result<(), String> {
        // [address 21b][txhash 32b][output_index u8] -> [coin_id u32][amount u64]
        let mut key = [0u8; 21 + 32 + 1];
        write_slice(&mut key[0..21], &output.0);
        write_slice(&mut key[21..21 + 32], &u256_to_bytes(txhash));
        key[53] = output_index;

        let mut value = [0u8; 4 + 8];
        write_slice(&mut value[0..4], &u32_to_bytes(output.1));
        write_slice(&mut value[4..4 + 8], &u64_to_bytes(output.2));

        self.addr_index
            .put(key.as_ref(), value.as_ref())
            .map_err(|err| err.to_string())
    }

    pub fn remove_addr_index(&mut self, addr: &Address, input: &TxInput) -> Result<(), String> {
        // [address 21b][txhash 32b][output_index u8] -> [coin_id u32][amount u64]
        let mut key = [0u8; 21 + 32 + 1];
        write_slice(&mut key[0..21], addr.as_ref());
        write_slice(&mut key[21..21 + 32 + 1], &input.to_bytes());
        self.addr_index
            .delete(key.as_ref())
            .map_err(|err| err.to_string())
    }

    pub fn write_mint(&mut self) -> Result<(), String> {
        // [coin_id u32][height u32][index u32] -> [txhash 32b][params ?][setting ?]
        unimplemented!("write mint")
    }

    pub fn write_account_state(&mut self, account_id: u32, bytes: &[u8]) -> Result<(), String> {
        // [account_id u32] -> [account bytes xb]
        let key = u32_to_bytes(account_id);
        self.account
            .put(key.as_ref(), bytes)
            .map_err(|err| err.to_string())
    }

    pub fn write_temporary_movement(&mut self, movement: &BalanceMovement) -> Result<(), String> {
        // [txhash 32b] -> [movement bytes xb]
        let key = u256_to_bytes(&movement.hash);
        let value = movement.to_bytes();
        self.movement
            .put(key.as_ref(), &value)
            .map_err(|err| err.to_string())
    }

    pub fn update_movement_status(&mut self, hash: &U256, height: u32, position: u32) -> Result<(), String> {
        // change key [txhash 32b] to [height u32][position u32]
        let old_key = u256_to_bytes(hash).to_vec();
        match self.tables.movement.get(&old_key) {
            Ok(value) => match value {
                Some(value) => {
                    // delete old
                    self.movement.delete(&old_key).map_err(|err| err.to_string())?;
                    // insert new
                    let mut new_key = Vec::with_capacity(4 + 4);
                    new_key.extend_from_slice(&u32_to_bytes(height));
                    new_key.extend_from_slice(&u32_to_bytes(position));
                    self.movement
                        .put(&new_key, &value)
                        .map_err(|err| err.to_string())?;
                    Ok(())
                },
                None => return Err(format!("not found movement {:?}", hash)),
            },
            Err(err) => return Err(format!("database exception: {}", err.to_string())),
        }
    }

    pub fn write_txcache(&mut self, tx: &TxVerifiable) -> Result<(), String> {
        // [txhash 32b] -> [txcache bytes Xb]
        if tx.body.is_coinbase() {
            return Err(format!("coinbase tx is not recode to txcache {:?}", tx));
        }
        // non-coinbase tx
        let key = tx.body.hash();
        let value = pickle_txcache(tx);
        self.txcache.put(&key, &value).map_err(|err| err.to_string())
    }

    pub fn remove_from_txcache(&mut self, hash: &U256) -> Result<(), String> {
        // [txhash 32b] -> [txcache bytes Xb]
        let key = u256_to_bytes(hash);
        // note: don't remove from txcache until include by block and the block is finalized
        // note: this means all `not include by any blocks` and `expired` txs remain forever
        // note: refresh when recreate database
        self.txcache.delete(key.as_ref()).map_err(|err| err.to_string())
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod table_test {
    use crate::block::BlockHeader;
    use crate::chain::tables::*;
    use crate::chain::utils::*;
    use crate::tx::{TxInput, TxOutput};
    use crate::utils::*;
    use bigint::U256;
    use tempfile::tempdir;

    #[test]
    fn block_index_iter() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("database");
        let table_opts = TableOptions::new();
        let mut tables = Tables::new(dir.as_path(), table_opts).unwrap();

        // dummy block headers
        let block1 = BlockHeader::from_bytes(
            &hex::decode(
                "010000007028f78cc0\
        06db063b8762dbee3d695015497cf5b6ce9af7e903aada13f60c3600a6fdc95c96649506803bd3af8375bb86cdc1\
        78f1a0cd964bdba6c3286ad1f1472a38009ab0001f00003301",
            )
            .unwrap(),
        );
        let block2 = BlockHeader::from_bytes(
            &hex::decode(
                "01000000b70dbe984b\
        a424aac9f64d7237a82df15e7e9213f8787f1a66b517dc3bac6de4082f299b89b4a5db91556601bf90b8aa0edd3d\
        6d8ff7d291dbd8bcf44b5309dd742a3800629e021d054c5b13",
            )
            .unwrap(),
        );
        let block3 = BlockHeader::from_bytes(
            &hex::decode(
                "01000000c296100f2b\
        d2ff4b3fecdef8556a9bccb8604dafa0388abe1ea9cf4b5edc551453566ab06d84f5601a47a084457b31944c3b62\
        d1924092b852189ff6127935488a2a38002d85021d02b85171",
            )
            .unwrap(),
        );
        let block4 = BlockHeader::from_bytes(
            &hex::decode(
                "010000001f29ac47fd\
        c51cdf2e26b92384c6ec3a264e93fe827dfba9105b28086d7ba29247633af93b97d06be5059ef70011ede3c2ec79\
        c99c5021df98d71bbc9935430f962a3800f886041d9479d901",
            )
            .unwrap(),
        );

        // start transaction
        let mut cur = tables.transaction();

        // write
        assert_eq!(cur.write_block_index(1, &block1), Ok(()));
        assert_eq!(cur.write_block_index(2, &block2), Ok(()));
        assert_eq!(cur.write_block_index(3, &block3), Ok(()));
        assert_eq!(cur.write_block_index(4, &block4), Ok(()));

        // commit
        assert!(cur.commit().is_ok());

        {
            // read
            let mut iter = tables.read_block_index_iter(2);
            // skip height=1 because start_height is 2
            let (height2, blockhash2) = iter.next().unwrap();
            let (height3, blockhash3) = iter.next().unwrap();
            let (height4, blockhash4) = iter.next().unwrap();
            assert_eq!(iter.next(), None);

            // check
            assert_eq!(big_endian_to_u32(&height2), 2);
            assert_eq!(big_endian_to_u32(&height3), 3);
            assert_eq!(big_endian_to_u32(&height4), 4);
            assert_eq!(
                hex::encode(&blockhash2),
                hex::encode(u256_to_bytes(&block2.hash()))
            );
            assert_eq!(
                hex::encode(&blockhash3),
                hex::encode(u256_to_bytes(&block3.hash()))
            );
            assert_eq!(
                hex::encode(&blockhash4),
                hex::encode(u256_to_bytes(&block4.hash()))
            );
        }

        // remove dusts
        tables.close_and_destroy();
    }

    #[test]
    fn address_iter() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("database");
        let table_opts = TableOptions::new();
        let mut tables = Tables::new(dir.as_path(), table_opts).unwrap();

        let mut cur = tables.transaction();

        // write
        let pre_addr = &[2u8; 21];
        let output0 = TxOutput(pre_addr.clone(), 1121, 55);
        let txhash0 = string_to_u256("cd8bebe511aab4b85e2ab6a8b8629d8804d4c0ee30f234a653487f545f073fe9");
        let output_index0 = 3;
        cur.write_addr_index(&output0, &txhash0, output_index0).unwrap();

        let addr = &[3u8; 21];
        let output1 = TxOutput(addr.clone(), 4445, 3543);
        let txhash1 = string_to_u256("ff8d87eaa33aec3d901b9761f4f3b9c83cf395f55e233739a894b2174430e82c");
        let output_index1 = 2;
        cur.write_addr_index(&output1, &txhash1, output_index1).unwrap();

        let post_addr = &[4u8; 21];
        let output2 = TxOutput(post_addr.clone(), 45, 5008);
        let txhash2 = string_to_u256("3a7d5c3a627f6f9eab9360373d6e40487e6a09c89d45e997c1748c08f47baf52");
        let output_index2 = 0;
        cur.write_addr_index(&output2, &txhash2, output_index2).unwrap();

        cur.commit().unwrap();

        // read
        {
            let mut iter = tables.read_addr_iter(addr);
            let input = TxInput(txhash1, output_index1);
            assert_eq!(iter.next(), Some((input, output1)));
            assert_eq!(iter.next(), None);
        }

        // destroy
        tables.close_and_destroy();
    }
}
