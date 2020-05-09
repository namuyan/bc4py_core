use crate::balance::BalanceMovement;
use crate::chain::{account::AccountAddrIter, confirmed::BlockHashVec, unconfirmed::UnconfirmedIter, Chain};
use crate::tx::{TxInput, TxOutput};
use crate::utils::*;
use bigint::U256;
use rocksdb::DBIterator;
use std::slice::Iter;
use std::vec::IntoIter;

type Address = [u8; 21];

/// iterate tables unspent: (txhash, txindex, coinId, amount)
pub struct AddrIter<'a> {
    pub addr: Address,
    pub iter: DBIterator<'a>,
}

impl Iterator for AddrIter<'_> {
    type Item = (TxInput, TxOutput);

    fn next(&mut self) -> Option<Self::Item> {
        // [addr 21b][txhash 32b][output_index u8] -> [coin_id u32][amount u64]
        // note: You should think the iter run out if once return `None`
        match self.iter.next() {
            Some((key, value)) => {
                if key.starts_with(&self.addr) {
                    let input = TxInput(U256::from(&key[21..21 + 32]), key[53]);
                    let output = TxOutput(
                        self.addr.clone(),
                        bytes_to_u32(&value[0..4]),
                        bytes_to_u64(&value[4..4 + 8]),
                    );
                    Some((input, output))
                } else {
                    None
                }
            },
            None => None,
        }
    }
}

/// return address specified unspent
/// note: confirmed_iter is ordered **old to new**
pub struct UnspentIter<'a> {
    pub table_iter: AddrIter<'a>,
    pub confirmed_iter: IntoIter<U256>,
    pub unconfirmed_iter: UnconfirmedIter<'a>,
    pub addr: Address,
    pub chain: &'a Chain,
}

impl Iterator for UnspentIter<'_> {
    type Item = (TxInput, TxOutput);

    fn next(&mut self) -> Option<Self::Item> {
        // 1. from tables
        match self.table_iter.next() {
            Some((input, output)) => {
                // check already used on confirmed
                if self
                    .chain
                    .confirmed
                    .input_already_used(&self.chain.best_chain, &input)
                {
                    return self.next(); // already used, go next unspent!
                }
                // check already used on unconfirmed
                if self
                    .chain
                    .unconfirmed
                    .input_already_used(&input, &self.chain.tables)
                    .unwrap()
                {
                    return self.next(); // already used, go next unspent!
                }
                // success: not used unspent
                return Some((input, output));
            },
            None => (), // no unspent, go next unspent!
        }

        // 2. from confirmed
        match self.confirmed_iter.next() {
            Some(blockhash) => {
                let (_block, txs) = self
                    .chain
                    .tables
                    .read_full_block(&blockhash)
                    .expect("database exception rare case?")
                    .expect("not found block on tables?");
                for tx in txs.into_iter() {
                    let txhash = tx.hash.clone();
                    for (txindex, output) in tx.body.outputs.into_iter().enumerate() {
                        // find unspent
                        if output.0 == self.addr {
                            // check used on confirmed
                            let input = TxInput(txhash, txindex as u8);
                            if self
                                .chain
                                .confirmed
                                .input_already_used(&self.chain.best_chain, &input)
                            {
                                return self.next(); // already used, go next unspent!
                            }
                            // check used on unconfirmed
                            if self
                                .chain
                                .unconfirmed
                                .input_already_used(&input, &self.chain.tables)
                                .unwrap()
                            {
                                return self.next(); // already used, go next unspent!
                            }
                            // success get unspent
                            return Some((input, output));
                        }
                    }
                    // not found unspent..
                    // go next unconfirmed section
                }
            },
            None => (), // no unspent, go next unspent!
        }

        // 3. from unconfirmed
        match self.unconfirmed_iter.next() {
            // note: this unconfirmed_iter is filtered by address
            Some(txhash) => {
                let tx = self
                    .chain
                    .tables
                    .read_txcache(&txhash)
                    .expect("table read exception?")
                    .expect("not found tx on txcache?");
                for (txindex, output) in tx.body.outputs.into_iter().enumerate() {
                    // find unspent
                    if output.0 == self.addr {
                        // check used on unconfirmed
                        let input = TxInput(txhash, txindex as u8);
                        if self
                            .chain
                            .unconfirmed
                            .input_already_used(&input, &self.chain.tables)
                            .unwrap()
                        {
                            return self.next(); // already used, go next unspent!
                        }
                        // success get unspent
                        return Some((input, output));
                    }
                }
            },
            None => (), // no unspent..
        }

        // 4. end of iterator!
        None
    }
}

/// iterate all account related unspent
pub struct AccountUnspentIter<'a> {
    pub addr_iter: AccountAddrIter<'a>,
    pub unspent_iter: Option<UnspentIter<'a>>,
    pub chain: &'a Chain,
}

impl Iterator for AccountUnspentIter<'_> {
    type Item = (TxInput, TxOutput);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.unspent_iter.is_some() {
                match self.unspent_iter.as_mut().unwrap().next() {
                    Some(unspent) => return Some(unspent),
                    None => self.unspent_iter = None,
                }
            } else {
                match self.addr_iter.next() {
                    Some(addr) => {
                        let best_chain_rev: BlockHashVec = self
                            .chain
                            .best_chain
                            .iter()
                            .rev()
                            .map(|hash| hash.clone())
                            .collect();
                        self.unspent_iter = Some(UnspentIter {
                            table_iter: self.chain.tables.read_addr_iter(&addr),
                            confirmed_iter: best_chain_rev.into_iter(),
                            unconfirmed_iter: self.chain.unconfirmed.filtered_unconfirmed_iter(Some(addr)),
                            addr,
                            chain: self.chain,
                        });
                    },
                    None => return None,
                }
            }
        }
    }
}

/// all account movement from new to old.
/// return **(height u32, position u32, movement)**
pub struct MovementIter<'a> {
    pub tables_iter: DBIterator<'a>,
    pub confirmed_iter: Iter<'a, U256>,
    pub unconfirmed_iter: UnconfirmedIter<'a>,
    pub chain: &'a Chain,
}

impl Iterator for MovementIter<'_> {
    type Item = (Option<u32>, Option<u32>, BalanceMovement);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // from unconfirmed
            match self.unconfirmed_iter.next() {
                Some(hash) => match self.chain.tables.read_temporary_movement(&hash).unwrap() {
                    Some(movement) => return Some((None, None, movement)),
                    None => continue,
                },
                None => (), // go next iterator
            }

            // from confirmed
            match self.confirmed_iter.next() {
                Some(blockhash) => {
                    let block = self.chain.confirmed.get_block_ref(blockhash).unwrap();
                    for (position, txhash) in block.txs_hash.iter().enumerate() {
                        match self.chain.tables.read_temporary_movement(&txhash).unwrap() {
                            Some(movement) => {
                                return Some((Some(block.height), Some(position as u32), movement));
                            },
                            None => continue,
                        }
                    }
                },
                None => (), // go next iterator
            }

            // from tables
            match self.tables_iter.next() {
                Some((key, value)) => {
                    if key.len() != 8 {
                        continue; // not finalized movement
                    }
                    let height = Some(bytes_to_u32(&key[0..4]));
                    let position = Some(bytes_to_u32(&key[4..4 + 4]));
                    let movement = BalanceMovement::from_bytes(&value);
                    return Some((height, position, movement));
                },
                None => return None, // end of iterator
            }
        }
    }
}
