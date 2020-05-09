pub mod account;
pub mod confirmed;
pub mod iters;
pub mod tables;
pub mod unconfirmed;
pub mod utils;

use crate::balance::Balances;
use crate::block::Block;
use crate::chain::confirmed::BlockHashVec;
use crate::chain::{
    account::AccountBuilder,
    confirmed::ConfirmedBuilder,
    iters::*,
    tables::*,
    unconfirmed::UnconfirmedBuilder,
};
use crate::tx::{TxInput, TxOutput, TxRecoded, TxVerifiable};
use bigint::U256;
use std::path::Path;

/// unconfirmed -> confirmed -> tables

/// genesis block's previous_hash is "ffff..ffff"
const GENESIS_PREVIOUS_HASH: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];
type Address = [u8; 21];

pub struct Chain {
    pub tables: Tables,
    pub confirmed: ConfirmedBuilder,
    pub unconfirmed: UnconfirmedBuilder,
    pub account: AccountBuilder,

    // update when new block accepted
    pub best_chain: BlockHashVec,
}

/// control chain
impl Chain {
    pub fn new(
        dir: &Path,
        sk: &Option<Vec<u8>>,
        deadline: u32,
        tx_index: bool,
        addr_index: bool,
    ) -> Result<Self, String> {
        // tables
        let mut table_opts = TableOptions::new();
        table_opts.tx_index = tx_index;
        table_opts.addr_index = addr_index;
        let mut tables = Tables::new(dir, table_opts)?;

        // confirmed
        let confirmed = if tables.initialized {
            let root_hash = U256::from(GENESIS_PREVIOUS_HASH.as_ref());
            ConfirmedBuilder::new(dir, &root_hash)
        } else {
            ConfirmedBuilder::restore_from_file(&tables)?
        };
        let best_chain = confirmed.get_best_chain();

        // unconfirmed
        let unconfirmed = if tables.initialized {
            UnconfirmedBuilder::new()
        } else {
            let mut unconfirmed: _ = UnconfirmedBuilder::restore_from_mempool(&tables, &best_chain)?;
            let mut cur = tables.transaction();
            unconfirmed.remove_expired_txs(deadline, &mut cur);
            cur.commit().unwrap();
            unconfirmed
        };

        // account
        let account = if tables.initialized {
            let sk = sk.as_ref().ok_or("account init require sk".to_owned())?;
            let mut cur = tables.transaction();
            let account = AccountBuilder::new(sk, &mut cur);
            cur.commit().unwrap();
            account
        } else {
            AccountBuilder::restore_from_tables(&tables, sk)
        }
        .map_err(|err| format!("account gene error: {:?}", err))?;

        Ok(Chain {
            tables,
            confirmed,
            unconfirmed,
            account,
            best_chain,
        })
    }

    pub fn push_new_block(&mut self, block: Block, txs: &Vec<TxVerifiable>) -> Result<(), String> {
        // note: block check is already finished
        // note: data is broken! if return error..

        // start transaction
        let mut cur = self.tables.transaction();

        // write block to tables (even if orphans)
        cur.write_block(&block, txs)?;

        // add block to confirmed and return fork info
        // best_chain is ordered `new to old`
        let (best_chain_before, best_chain_after): (_, _) =
            self.confirmed.push_new_block(block, &cur.tables)?;

        // revert fork (tx: confirmed -> unconfirmed)
        for blockhash in best_chain_before.iter() {
            let fork = self.confirmed.get_block_ref(blockhash).unwrap();
            // note: do not revert coinbase tx
            for txhash in fork.txs_hash.iter().skip(1).rev() {
                let tx = cur
                    .tables
                    .read_mempool(txhash)?
                    .expect("revert tx included by fork block");
                self.unconfirmed.push_new_tx(&tx)?;
            }
        }

        // construct main (tx: unconfirmed -> confirmed)
        for blockhash in best_chain_after.iter().rev() {
            let main = self.confirmed.get_block_ref(blockhash).unwrap();
            // note: do not revert coinbase tx
            let hashs = main
                .txs_hash
                .iter()
                .skip(1)
                .map(|hash| hash.clone())
                .collect::<Vec<U256>>();
            self.unconfirmed.remove_many(&hashs);
        }

        // finalize (move some blocks from `confirmed` to `tables`)
        match self.confirmed.truncate_old_blocks(1, 50) {
            // finalize if over size cache
            Some(finalized) => {
                // move to tables (ordered old to new)
                for (block, coinbase) in finalized.into_iter() {
                    cur.write_block_index(block.height, &block.header)?;
                    let blockhash = block.header.hash();

                    // tx
                    let mut indexed_txs: _ = Vec::with_capacity(block.txs_hash.len());
                    for txhash in block.txs_hash.iter() {
                        // block's tx is coinbase tx and non-coinbase txs
                        let _tx = cur.tables.read_mempool(txhash)?;
                        let tx = if txhash == &coinbase.hash {
                            &coinbase
                        } else if _tx.is_some() {
                            _tx.as_ref().unwrap()
                        } else {
                            return Err("not found mempool & not coinbase tx".to_owned());
                        };

                        // utxo
                        cur.write_utxo_index(&tx.body)?;

                        // addr index
                        let mut is_account_tx = false;
                        let full_index = cur.tables.table_opts.addr_index;
                        for (input, output) in tx.body.inputs.iter().zip(tx.inputs_cache.iter()) {
                            if full_index || self.account.is_account_address(&output.0) {
                                is_account_tx = true;
                                cur.remove_addr_index(&output.0, input)?;
                            }
                        }
                        for (index, output) in tx.body.outputs.iter().enumerate() {
                            if full_index || self.account.is_account_address(&output.0) {
                                is_account_tx = true;
                                cur.write_addr_index(output, txhash, index as u8)?;
                            }
                        }

                        // mint FIXME: unimplemented

                        // remove tx
                        cur.remove_from_mempool(txhash)?;

                        // tx index
                        if cur.tables.table_opts.tx_index || is_account_tx {
                            indexed_txs.push(txhash.clone());
                        }
                    }

                    // write tx index
                    cur.write_tx_index(&blockhash, &indexed_txs)?;

                    // account
                    self.account.finalize_block(&block, &mut cur)?;
                }
            },
            None => (), // do nothing
        }
        self.confirmed.update_temporary_file()?;
        self.best_chain = self.confirmed.get_best_chain();

        // OK
        cur.commit().unwrap();
        Ok(())
    }

    pub fn push_unconfirmed(&mut self, tx: &TxVerifiable) -> Result<(), String> {
        assert!(!tx.body.is_coinbase());
        // start transaction
        let mut cur = self.tables.transaction();

        // check already is unconfirmed
        if self.unconfirmed.have_the_tx(&tx.hash) {
            return Err(format!("tx is already unconfirmed {:?}", tx));
        }

        // insert
        self.unconfirmed.push_new_tx(&tx)?;
        cur.write_mempool(&tx)?;

        // check account transaction
        self.account
            .update_by_tx(tx, &mut cur)
            .map_err(|err| format!("account update failed: {:?}", err))?;

        // commit
        cur.commit().unwrap();

        Ok(())
    }

    pub fn get_block(&self, hash: &U256) -> Result<Option<Block>, String> {
        Ok(self.tables.read_block(hash)?)
    }

    pub fn get_tx(&self, hash: &U256) -> Result<Option<TxRecoded>, String> {
        // from tables (tx_indexed or account tx)
        let tx = self.tables.read_tx(hash)?;
        if tx.is_some() {
            return Ok(Some(tx.unwrap()));
        }

        // from mempool (confirmed or unconfirmed)
        let tx = self.tables.read_mempool(hash)?;
        if tx.is_some() {
            return Ok(Some(tx.unwrap().convert_recoded_tx()));
        }

        // not found
        Ok(None)
    }

    pub fn get_output_of_input(&self, input: &TxInput, ignore: bool) -> Result<Option<TxOutput>, String> {
        // find output of unused input (to fill input_cache)
        // note: return none if already used or not exist
        // note: `ignore` flag let me return output even if it is already used

        //  from tables
        let mut output: Option<TxOutput> = self.tables.read_utxo_index(input)?;

        // from confirmed
        self.confirmed
            .find_output_of_input(&self.best_chain, input, &mut output, ignore, &self.tables)?;

        // from unconfirmed
        self.unconfirmed
            .find_output_of_input(input, &mut output, ignore, &self.tables)?;

        Ok(output)
    }
}

// get account info
// `best_chain` is specified to `self.best_chain`
impl Chain {
    /// iterate unspent from old to new
    pub fn get_unspent_iter_by(&self, addr: &Address) -> Result<UnspentIter, String> {
        // 特定のアドレスに関連したunspentを返す
        if !self.tables.table_opts.addr_index {
            return Err("is not unspent indexed because addr_index is false".to_owned());
        }
        let best_chain_rev: BlockHashVec = self.best_chain.iter().rev().map(|hash| hash.clone()).collect();
        let addr = addr.clone();
        Ok(UnspentIter {
            table_iter: self.tables.read_addr_iter(&addr),
            confirmed_iter: best_chain_rev.into_iter(),
            unconfirmed_iter: self.unconfirmed.filtered_unconfirmed_iter(Some(addr)),
            addr,
            chain: self,
        })
    }

    pub fn get_account_unspent_iter(&self) -> AccountUnspentIter {
        AccountUnspentIter {
            addr_iter: self.account.get_account_addr_iter(),
            unspent_iter: None,
            chain: self,
        }
    }

    /// return (confirmed, unconfirmed) balance
    pub fn get_account_balance(&self, account_id: u32, confirm: u32) -> Result<(Balances, Balances), String> {
        // note: incoming is confirmed when `confirm` height passed
        // note: outgoing is instantly reflected from unconfirmed status

        // from tables
        let account = self.account.get_account_ref(account_id)?;
        let mut confirmed = account.balance.clone();
        let mut unconfirmed = Balances(vec![]);

        // from confirmed
        let best_hash = self.best_chain.first().ok_or("cannot get best_hash".to_owned())?;
        let best_block = self.confirmed.get_block_ref(best_hash).unwrap();
        for blockhash in self.best_chain.iter().rev() {
            let block = self.confirmed.get_block_ref(blockhash).unwrap();
            let f_enough_old = block.height <= best_block.height - confirm;
            for txhash in block.txs_hash.iter() {
                match self.tables.read_temporary_movement(txhash)? {
                    Some(movement) => {
                        for (_account_id, _balances) in movement.get_account_movement() {
                            if account_id != _account_id {
                                continue;
                            }
                            // skip non-account movement
                            if f_enough_old {
                                for balance in _balances.0.iter() {
                                    confirmed.add_balance(balance);
                                }
                            } else {
                                for balance in _balances.0.iter() {
                                    if 0 <= balance.amount {
                                        unconfirmed.add_balance(balance);
                                    } else {
                                        confirmed.add_balance(balance);
                                    }
                                }
                            }
                        }
                    },
                    None => (), // skip no account tx
                }
            }
        }

        // from unconfirmed
        for txhash in self.unconfirmed.filtered_unconfirmed_iter(None) {
            match self.tables.read_temporary_movement(&txhash)? {
                Some(movement) => {
                    for (_account_id, _balances) in movement.get_account_movement() {
                        if account_id != _account_id {
                            continue;
                        }
                        // skip non-account movement
                        for balance in _balances.0.iter() {
                            if 0 <= balance.amount {
                                unconfirmed.add_balance(balance);
                            } else {
                                confirmed.add_balance(balance);
                            }
                        }
                    }
                },
                None => (), // skip no account tx
            }
        }

        confirmed.compaction();
        unconfirmed.compaction();
        Ok((confirmed, unconfirmed))
    }

    pub fn get_movement_iter(&self) -> Result<MovementIter, String> {
        // from tables
        let tables_iter = self.tables.read_movement_iter();

        // from confirmed
        let confirmed_iter = self.best_chain.iter();

        // from unconfirmed
        let unconfirmed_iter: _ = self.unconfirmed.filtered_unconfirmed_iter(None);

        Ok(MovementIter {
            tables_iter,
            confirmed_iter,
            unconfirmed_iter,
            chain: self,
        })
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod chain {
    use crate::block::*;
    use crate::chain::*;
    use crate::tx::*;
    use bigint::U256;
    use tempfile::tempdir;

    #[test]
    fn no_index() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join("database");
        let sk = Some(b"1qwq53lmi8rapvcciqmuiorxdie5irwmw1dccbegkze9vjdpy7mz6nsd6j991a6b".to_vec());
        let deadline = 100;
        let (tx_index, addr_index) = (false, false);

        let mut chain = Chain::new(dir.as_ref(), &sk, deadline, tx_index, addr_index).unwrap();

        // TODO: 後で書く
        // block 0 (genesis)
        // block 1
        // block 2
        // block 3
        // block 4
        // block 5
        chain.tables.close_and_destroy();
    }

    #[test]
    fn tx_index() {}

    #[test]
    fn addr_index() {}

    #[test]
    fn full_index() {}
}
