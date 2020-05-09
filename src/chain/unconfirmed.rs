use crate::chain::confirmed::BlockHashVec;
use crate::chain::tables::*;
use crate::pickle::*;
use crate::tx::{TxInput, TxOutput, TxVerifiable};
use crate::utils::*;
use bigint::U256;
use bloomfilter::Bloom;

type Address = [u8; 21];
const FP_P: f64 = 0.01; // false-positive rate

// meta data used for find priority
struct Unconfirmed {
    hash: U256,                   // txhash
    depend_hashs: Box<[U256]>,    // input txhash
    depend_addrs: Bloom<Address>, // input & output addr
    price: u64,
    time: u32,
    deadline: u32,
    size: u32,
}

impl std::fmt::Debug for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("unconfirmed")
            .field(&hex::encode(u256_to_bytes(&self.hash)))
            .finish()
    }
}

#[derive(Debug)]
pub struct UnconfirmedBuilder {
    // unconfirmed is sorted by priority high to low
    unconfirmed: Vec<Unconfirmed>,
}

impl UnconfirmedBuilder {
    pub fn new() -> Self {
        UnconfirmedBuilder {
            unconfirmed: Vec::with_capacity(100),
        }
    }

    pub fn restore_from_txcache(tables: &Tables, best_chain: &BlockHashVec) -> Result<Self, String> {
        // unconfirmed = txcache - best_chain's txs
        let mut include_txs = vec![];
        for blockhash in best_chain {
            let block = tables.read_block(blockhash)?.expect("not found block?");
            include_txs.extend_from_slice(&block.txs_hash);
        }

        let mut unconfirmed = UnconfirmedBuilder::new();
        for (hash, bytes) in tables.read_txcache_iter() {
            let hash = U256::from(hash.as_ref());
            if include_txs.contains(&hash) {
                continue;
            }
            let tx = unpickle_txcache(bytes.as_ref());
            unconfirmed.push_new_tx(&tx)?;
        }
        Ok(unconfirmed)
    }

    pub fn have_the_tx(&self, hash: &U256) -> bool {
        self.unconfirmed.iter().position(|tx| &tx.hash == hash).is_some()
    }

    pub fn get_priority(&self, hash: &U256) -> Option<usize> {
        self.unconfirmed.iter().position(|tx| &tx.hash == hash)
    }

    pub fn get_size(&self) -> u32 {
        self.unconfirmed.iter().map(|tx| tx.size).sum()
    }

    pub fn input_already_used(&self, input: &TxInput, tables: &Tables) -> Result<bool, String> {
        let hash = &input.0;
        for unconfirmed in self.unconfirmed.iter() {
            if unconfirmed.depend_hashs.contains(hash) {
                let tx = tables
                    .read_txcache(&unconfirmed.hash)?
                    .expect("try to get unconfirmed from txcache?");
                if tx.body.inputs.contains(input) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub fn push_new_tx(&mut self, tx: &TxVerifiable) -> Result<usize, String> {
        // push new unconfirmed tx, return inserted index
        let hash = tx.hash.clone();

        // get raw dependency of input hash
        let mut depend_hashs = tx.body.inputs.iter().map(|input| input.0).collect::<Vec<U256>>();

        // remove duplicate depend_hashs
        depend_hashs.sort_unstable();
        depend_hashs.dedup();

        // drop any excess capacity
        let depend_hashs = depend_hashs.into_boxed_slice();

        // get bloom filter of input & output address
        // note: 1% false-positive rate (by 614 bytes filter & 100 items)
        // note: maximum bitmap_size is 400bytes
        let items_count = std::cmp::max(4, tx.inputs_cache.len() + tx.body.outputs.len());
        let bitmap_size = Bloom::<Address>::compute_bitmap_size(items_count, FP_P);
        let mut depend_addrs: _ = Bloom::<Address>::new(bitmap_size, items_count);
        tx.inputs_cache
            .iter()
            .map(|output| &output.0)
            .chain(tx.body.outputs.iter().map(|output| &output.0))
            .for_each(|addr| depend_addrs.set(addr));

        let unconfirmed = Unconfirmed {
            hash,
            depend_hashs,
            depend_addrs,
            price: tx.body.gas_price,
            time: tx.body.time,
            deadline: tx.body.deadline,
            size: tx.body.get_size() as u32,
        };

        // push
        self.push_unconfirmed(unconfirmed)
    }

    #[allow(dead_code)]
    fn remove_tx(&mut self, hash: &U256) {
        // note: not allow any error (assert)
        // require reorder after remove the hash
        let mut deleted = Vec::with_capacity(1);

        // remove all related txs
        self.remove_with_depend_myself(&hash, &mut deleted);
        assert!(0 < deleted.len());

        // remove root tx from deleted list
        assert_eq!(hash, &deleted.remove(0).hash);

        // insert all except root tx
        for tx in deleted {
            assert!(self.push_unconfirmed(tx).is_ok())
        }
    }

    pub fn remove_many(&mut self, hashs: &Vec<U256>) {
        // note: no error even if no delete tx

        //require reorder after remove the hash
        let mut deleted = Vec::with_capacity(hashs.len());

        // remove all related txs
        for hash in hashs.iter() {
            self.remove_with_depend_myself(hash, &mut deleted);
        }

        // remove root txs
        deleted
            .drain_filter(|_tx| hashs.contains(&_tx.hash))
            .for_each(drop);

        // insert all
        for tx in deleted {
            assert!(self.push_unconfirmed(tx).is_ok())
        }
    }

    #[allow(dead_code)]
    fn remove_with_depends(&mut self, hash: &U256) -> usize {
        // remove unconfirmed tx with depend and return delete count
        let mut deleted: Vec<Unconfirmed> = Vec::new();
        self.remove_with_depend_myself(hash, &mut deleted);
        deleted.len()
    }

    pub fn get_size_limit_list(&self, maxsize: u32, deadline: u32) -> Vec<U256> {
        // size limit unconfirmed tx's tuple for mining interface
        let mut size = 0;
        self.unconfirmed
            .iter()
            .filter(|tx| deadline < tx.deadline)
            .filter(|tx| {
                size += tx.size;
                size < maxsize
            })
            .map(|tx| tx.hash)
            .collect::<Vec<U256>>()
    }

    pub fn filtered_unconfirmed_iter(&self, filter: Option<Address>) -> UnconfirmedIter {
        // note: filter by address but optional
        UnconfirmedIter {
            unconfirmed: self,
            filter,
            index: 0,
        }
    }

    pub fn remove_expired_txs(&mut self, deadline: u32, cur: &mut TableCursor) -> Vec<U256> {
        // remove expired unconfirmed txs
        // note: remove from this and tables
        let mut deleted: Vec<Unconfirmed> = Vec::new();

        // remove from unconfirmed
        loop {
            let mut want_delete = None;
            for tx in self.unconfirmed.iter() {
                if tx.deadline < deadline {
                    want_delete = Some(tx.hash.clone());
                    break;
                }
            }
            match want_delete {
                Some(hash) => self.remove_with_depend_myself(&hash, &mut deleted),
                None => break,
            };
        }

        // remove from tables
        for tx in deleted.iter() {
            cur.remove_from_txcache(&tx.hash).unwrap();
        }

        // return expired tx's hashs
        deleted.into_iter().map(|tx| tx.hash).collect::<Vec<U256>>()
    }

    pub fn find_output_of_input(
        &self,
        input: &TxInput,
        output: &mut Option<TxOutput>,
        ignore: bool,
        tables: &Tables,
    ) -> Result<(), String> {
        for unconfirmed in self.unconfirmed.iter() {
            if ignore && output.is_some() {
                return Ok(());
            }

            // input already used & set output None
            if unconfirmed.depend_hashs.contains(&input.0) {
                match tables.read_txcache(&unconfirmed.hash)? {
                    Some(tx) => {
                        if tx.body.inputs.contains(input) {
                            output.take(); // <= None
                        }
                    },
                    None => return Err("input's hash isn't found in txcache".to_owned()),
                }
            }

            // find output of input
            if unconfirmed.hash == input.0 {
                let tx = tables.read_txcache(&unconfirmed.hash)?.unwrap();
                let inner = tx
                    .body
                    .outputs
                    .get(input.1 as usize)
                    .ok_or("txindex is out of range on unconfirmed".to_owned())?
                    .clone();
                output.replace(inner); // <= Some
            }
        }
        Ok(())
    }

    /// remove unconfirmed tx with depend it
    fn remove_with_depend_myself(&mut self, hash: &U256, deleted: &mut Vec<Unconfirmed>) {
        // find position
        let delete_index = match self.unconfirmed.iter().position(|tx| hash == &tx.hash) {
            Some(index) => index,
            None => return,
        };

        // delete tx
        deleted.push(self.unconfirmed.remove(delete_index));

        // check depend_hashs
        loop {
            let mut delete_hash = None;
            for tx in self.unconfirmed.iter() {
                if tx.depend_hashs.contains(hash) {
                    delete_hash = Some(tx.hash.clone());
                    break;
                }
            }
            match delete_hash {
                Some(hash) => self.remove_with_depend_myself(&hash, deleted),
                None => break,
            }
        }
    }

    /// push unconfirmed tx with dependency check
    /// return inserted tx's index
    fn push_unconfirmed(&mut self, unconfirmed: Unconfirmed) -> Result<usize, String> {
        // most high position depend index
        let mut depend_index: Option<usize> = None;
        for (index, tx) in self.unconfirmed.iter().enumerate() {
            if unconfirmed.depend_hashs.contains(&tx.hash) {
                depend_index = Some(index);
            }
            if unconfirmed.hash == tx.hash {
                return Err("already inserted tx".to_owned());
            }
        }

        // most low position required index
        let mut required_index = None;
        let mut disturbs = Vec::new();
        for (index, tx) in self.unconfirmed.iter().enumerate().rev() {
            if tx.depend_hashs.contains(&unconfirmed.hash) {
                required_index = Some(index);
                // check absolute condition: depend_index < required_index
                if depend_index.is_some() && depend_index.unwrap() >= index {
                    disturbs.push(tx.hash.clone());
                }
            }
        }

        // exception: with disturbs
        if 0 < disturbs.len() {
            // 1. remove disturbs
            let mut deleted: Vec<Unconfirmed> = Vec::new();
            for disturb in disturbs {
                self.remove_with_depend_myself(&disturb, &mut deleted);
            }

            // 2. push original (not disturbed)
            let hash = unconfirmed.hash.clone();
            assert!(self.push_unconfirmed(unconfirmed).is_ok());

            // 3. push deleted disturbs
            for tx in deleted {
                assert!(self.push_unconfirmed(tx).is_ok());
            }

            // 4. find original position
            let position = self.unconfirmed.iter().position(|tx| hash == tx.hash);
            return Ok(position.unwrap());
        }

        // normal: without disturbs
        // find best relative condition
        let mut best_index: Option<usize> = None;
        for (index, tx) in self.unconfirmed.iter().enumerate() {
            // absolute conditions
            // ex
            //        0 1 2 3 4 5
            // vec = [a,b,c,d,e,f]
            //
            // You can insert positions(2,3,4) when you depend on b(1) and required by e(4)
            if depend_index.is_some() && index <= depend_index.unwrap() {
                continue;
            }
            if required_index.is_some() && index > required_index.unwrap() {
                continue;
            }

            // relative conditions
            if unconfirmed.price < tx.price {
                continue;
            } else if unconfirmed.price == tx.price {
                if unconfirmed.time >= tx.time {
                    continue;
                }
            }
            // find
            if best_index.is_none() {
                best_index = Some(index);
                break;
            }
        }

        // minimum index is required_index (or None)
        if best_index.is_none() {
            best_index = required_index.clone();
        }

        // insert
        match best_index {
            Some(best_index) => {
                // println!("best {} {:?} {:?}", best_index, depend_index, required_index);
                self.unconfirmed.insert(best_index, unconfirmed);
                Ok(best_index)
            },
            None => {
                // println!("last {:?} {:?}", depend_index, required_index);
                self.unconfirmed.push(unconfirmed);
                Ok(self.unconfirmed.len())
            },
        }
    }
}

/// iterate unconfirmed txhash from priority high to low
pub struct UnconfirmedIter<'a> {
    unconfirmed: &'a UnconfirmedBuilder,
    filter: Option<Address>,
    index: usize,
}

impl Iterator for UnconfirmedIter<'_> {
    type Item = U256;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.unconfirmed.unconfirmed.get(self.index) {
                Some(unconfirmed) => {
                    self.index += 1;
                    if self.filter.is_some() {
                        if unconfirmed.depend_addrs.check(self.filter.as_ref().unwrap()) {
                            // maybe the unconfirmed is related..
                            return Some(unconfirmed.hash);
                        }
                    } else {
                        return Some(unconfirmed.hash);
                    }
                },
                None => return None,
            }
        }
    }
}
