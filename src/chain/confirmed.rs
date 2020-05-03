use crate::block::*;
use crate::chain::tables::Tables;
use crate::tx::*;
use crate::utils::*;
use bigint::U256;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// [block(n), block(n-1),.. ,block(n-m)]
pub type BlockHashVec = Vec<U256>;

struct Confirmed {
    hash: U256, // block header hash
    block: Block,
    score: f64,
    coinbase: Tx,

    // summarize txs
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
}

impl Confirmed {
    fn new(tables: &Tables, hash: U256) -> Result<Self, String> {
        let (block, txs) = tables
            .read_full_block(&hash)?
            .expect("already write to table but not found block");
        let score = block.calc_score();
        let input_size = txs.iter().map(|_tx| _tx.inputs.len()).sum();
        let output_size = txs.iter().map(|_tx| _tx.outputs.len()).sum();
        let mut inputs = Vec::with_capacity(input_size);
        let mut outputs = Vec::with_capacity(output_size);
        let mut coinbase = None;
        for (index, tx) in txs.into_iter().enumerate() {
            if index == 0 {
                // clone coinbase tx
                inputs.extend(tx.inputs.iter().map(|_input| _input.clone()));
                outputs.extend(tx.outputs.iter().map(|_output| _output.clone()));
                coinbase = Some(tx);
            } else {
                inputs.extend(tx.inputs.into_iter());
                outputs.extend(tx.outputs.into_iter());
            }
        }
        let coinbase = coinbase.unwrap();
        assert!(coinbase.inputs_cache.is_some());
        Ok(Confirmed {
            hash,
            block,
            score,
            coinbase,
            inputs,
            outputs,
        })
    }
}

pub struct ConfirmedBuilder {
    dat_path: PathBuf,
    pub root_hash: U256, // top block hash of tables
    tree: HashMap<U256, Confirmed>,
}

impl ConfirmedBuilder {
    pub fn new(dir: &Path, root_hash: &U256) -> Self {
        // used when table initialized
        let confirmed = ConfirmedBuilder {
            dat_path: dir.join("confirmed.dat"),
            root_hash: root_hash.clone(),
            tree: HashMap::new(),
        };
        // write `confirmed.dat` file
        confirmed.update_temporary_file().unwrap();
        confirmed
    }

    pub fn restore_from_file(tables: &Tables) -> Result<Self, String> {
        assert_eq!(tables.initialized, false);
        let dat_path = tables.dir.join("confirmed.dat");
        if !dat_path.exists() {
            return Err(format!("not found {:?}", dat_path));
        }
        let mut fp = File::open(&dat_path).map_err(|err| err.to_string())?;

        // root hash
        let mut buf = [0u8; 32];
        if fp.read(&mut buf).ok() != Some(32) {
            return Err("cannot restore from file by root hash is wrong size".to_owned());
        }
        let root_hash = U256::from(buf.as_ref());

        // find length
        if fp.read(&mut buf[0..4]).ok() != Some(4) {
            return Err("cannot restore from file by length is wrong size".to_owned());
        }
        let length = bytes_to_u32(&buf[0..4]);

        // chain
        let mut chain: _ = HashMap::with_capacity(length as usize);
        loop {
            match fp.read(&mut buf) {
                Ok(32) => {
                    let hash = U256::from(buf.as_ref());
                    let confirmed = Confirmed::new(tables, hash)?;
                    chain.insert(hash, confirmed);
                },
                Ok(0) => break,
                _ => return Err("cannot restore from file on construct chain".to_owned()),
            }
        }
        Ok(ConfirmedBuilder {
            dat_path,
            root_hash,
            tree: chain,
        })
    }

    pub fn get_block_ref(&self, hash: &U256) -> Option<&Block> {
        self.tree.get(hash).map(|confirmed| &confirmed.block)
    }

    pub fn have_the_block(&self, hash: &U256) -> bool {
        self.tree.contains_key(hash)
    }

    pub fn get_best_chain(&self) -> BlockHashVec {
        let mut best_chain: Vec<&U256> = vec![];
        let mut best_score = 0.0;
        let mut tmp_chain: Vec<&U256> = Vec::with_capacity(self.tree.len());

        // struct best_chain
        for (hash, confirm) in self.tree.iter() {
            if best_chain.contains(&hash) {
                continue;
            }

            // init vec, no effect on the allocated capacity
            tmp_chain.clear();
            tmp_chain.push(hash);
            let mut tmp_score = confirm.score;
            let mut tmp_previous = &confirm.block.header.previous_hash;
            loop {
                match self.tree.get(tmp_previous) {
                    Some(previous) => {
                        tmp_chain.push(&previous.hash);
                        tmp_score += previous.score;
                        tmp_previous = &previous.block.header.previous_hash;
                    },
                    None => break,
                }
            }

            // update best chain
            if &self.root_hash == tmp_previous && best_score < tmp_score {
                best_chain = tmp_chain.clone();
                best_score = tmp_score;
            }
        }

        best_chain.into_iter().map(|hash| hash.clone()).collect()
    }

    pub fn get_best_chain_by(&self, best_hash: &U256) -> Result<BlockHashVec, String> {
        let best_block = self
            .tree
            .get(best_hash)
            .ok_or("not found the best_hash".to_owned())?;

        // struct best_chain
        let mut best_chain = Vec::with_capacity(self.tree.len());
        best_chain.push(best_block.hash);
        let mut previous_hash = best_block.block.header.previous_hash;
        loop {
            match self.tree.get(&previous_hash) {
                Some(previous) => {
                    best_chain.push(previous.hash);
                    previous_hash = previous.block.header.previous_hash;
                },
                None => break,
            }
        }

        // check previous_hash is root
        if self.root_hash == previous_hash {
            Ok(best_chain) // [block(n), block(n-1),.. ,block(n-m)]
        } else {
            Err("the best_hash is already purged".to_owned())
        }
    }

    pub fn input_already_used(&self, best_chain: &BlockHashVec, input: &TxInput) -> bool {
        for hash in best_chain {
            match self.tree.get(hash) {
                Some(confirmed) => {
                    if confirmed.inputs.contains(input) {
                        return true;
                    }
                },
                // note: return `used` is more safe then return `unused`
                None => return true,
                // removed: None => Err("not found block on check input".to_owned())
            }
        }
        false
    }

    pub fn find_output_of_input(
        &self,
        best_chain: &BlockHashVec,
        input: &TxInput,
        output: &mut Option<TxOutput>,
        ignore: bool,
        tables: &Tables,
    ) -> Result<(), String> {
        for blockhash in best_chain.iter().rev() {
            // ignore output is used or not
            if ignore && output.is_some() {
                return Ok(());
            }

            let confirmed = self.tree.get(blockhash).unwrap();

            // input already used & set output None
            if confirmed.inputs.contains(input) {
                output.take(); // <= None
            }

            // find output of input
            if confirmed.hash == input.0 {
                let tx = tables.read_mempool(&confirmed.hash)?.unwrap();
                let inner = tx
                    .outputs
                    .get(input.1 as usize)
                    .ok_or("txindex is out of range on confirmed".to_owned())?
                    .clone();
                output.replace(inner); // <= Some
            }
        }
        Ok(())
    }

    pub fn push_new_block(
        &mut self,
        block: Block,
        tables: &Tables,
    ) -> Result<(BlockHashVec, BlockHashVec), String> {
        // get best_chain before to compare after
        let mut best_chain_before = self.get_best_chain();

        // insert new block
        let hash = block.header.hash();
        let confirmed = Confirmed::new(tables, hash)?;
        self.tree.insert(hash, confirmed);

        // get best_chain after
        let mut best_chain_after = self.get_best_chain();

        // remove duplicate commons
        while 0 < best_chain_before.len() && 0 < best_chain_after.len() {
            if best_chain_before.last() == best_chain_after.last() {
                best_chain_before.pop();
                best_chain_after.pop();
            } else {
                break;
            }
        }

        // return fork info
        // rollback `best_chain_before` and apply `best_chain_after`
        Ok((best_chain_before, best_chain_after))
    }

    pub fn truncate_old_blocks(&mut self, chunk: usize, limit: usize) -> Option<Vec<(Block, Tx)>> {
        // remove `chunk` size when best_chain is over `limit` size
        assert!(0 < chunk && chunk < limit);

        let mut best_chain = self.get_best_chain();
        best_chain.reverse(); // reversed (old to new)

        // limit best_chain size
        if best_chain.len() < limit {
            return None;
        }

        // next root
        let root_hash = best_chain.get(chunk - 1).unwrap();
        let root_height = self.tree.get(root_hash).unwrap().block.height;

        // find all remove block (moved & orphans)
        let removed = self
            .tree
            .values()
            .filter(|confirmed| confirmed.block.height <= root_height)
            .map(|confirmed| confirmed.hash)
            .collect::<BlockHashVec>();

        // truncate
        let mut moved = removed
            .iter()
            .filter(|hash| best_chain.contains(hash))
            .map(|hash| self.tree.remove(hash).unwrap())
            .collect::<Vec<Confirmed>>();

        // drop orphans
        removed
            .iter()
            .filter_map(|hash| self.tree.remove(hash))
            .for_each(drop);

        // update root
        self.root_hash = root_hash.clone();

        // reorder (old to new)
        moved.sort_unstable_by_key(|_confirmed| _confirmed.block.height);
        Some(
            moved
                .into_iter()
                .map(|_confirmed| (_confirmed.block, _confirmed.coinbase))
                .collect::<Vec<(Block, Tx)>>(),
        )
    }

    pub fn update_temporary_file(&self) -> Result<(), String> {
        // need after `push_new_block()` or `truncate_old_blocks()`

        // generate tmp file
        let mut data = Vec::with_capacity(4 + 32 * (1 + self.tree.len()));
        data.extend_from_slice(&u256_to_bytes(&self.root_hash));
        data.extend_from_slice(&u32_to_bytes(self.tree.len() as u32));
        self.tree
            .keys()
            .for_each(|hash| data.extend_from_slice(&u256_to_bytes(hash)));

        // write
        match File::create(&self.dat_path) {
            Ok(mut fp) => fp.write_all(&data).expect("write tmp file"),
            Err(err) => return Err(format!("confirmed block update failed: {:?}", err)),
        }
        Ok(())
    }
}

#[cfg(test)]
mod confirmed {
    #[test]
    fn vector() {}
}
