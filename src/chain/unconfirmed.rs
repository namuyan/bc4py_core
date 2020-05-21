use crate::chain::confirmed::BlockHashVec;
use crate::chain::tables::*;
use crate::pickle::*;
use crate::tx::{TxInput, TxOutput, TxVerifiable};
use crate::utils::*;
use bigint::U256;
use bloomfilter::Bloom;
use std::fmt;
use streaming_iterator::{DoubleEndedStreamingIterator, StreamingIterator};

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

impl fmt::Debug for Unconfirmed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("unconfirmed")
            .field(&hex::encode(u256_to_bytes(&self.hash)))
            .finish()
    }
}

type TxsType = Vec<Option<Unconfirmed>>;

/// unconfirmed transaction's list
#[derive(Debug)]
struct Txs(TxsType);

/// unconfirmed txs iter
struct TxsIter<'a> {
    index: Option<usize>,
    vec: &'a TxsType,
}

impl StreamingIterator for TxsIter<'_> {
    type Item = Unconfirmed;

    fn advance(&mut self) {
        loop {
            // init
            if self.index.is_none() {
                self.index.replace(0);
            } else {
                *self.index.as_mut().unwrap() += 1;
            }
            // vec = [0,1,2,3,4]
            // false: index=5 < len=5
            let index = self.index.unwrap();
            if self.vec.get(index).is_some() {
                break; // find element
            } else if index < self.vec.len() {
                continue; // deleted element
            } else {
                self.index.take();
                break; // end of iter
            }
        }
    }

    fn get(&self) -> Option<&Self::Item> {
        match self.index {
            Some(index) => Some(self.vec.get(index).unwrap().as_ref().unwrap()),
            None => None,
        }
    }
}

impl DoubleEndedStreamingIterator for TxsIter<'_> {
    fn advance_back(&mut self) {
        loop {
            // init
            if self.index.is_none() {
                if 0 < self.vec.len() {
                    self.index.replace(self.vec.len() - 1);
                } else {
                    break; // empty vec
                }
            } else {
                *self.index.as_mut().unwrap() -= 1;
            }
            // vec = [0,1,2,3,4]
            // false: index=5 < len=5
            let index = self.index.unwrap();
            if self.vec.get(index).is_some() {
                break; // find element
            } else if index < self.vec.len() {
                continue; // deleted element
            } else {
                self.index.take();
                break; // end of iter
            }
        }
    }
}

/// unconfirmed is sorted by priority high to low
#[derive(Debug)]
pub struct UnconfirmedBuilder {
    txs: Txs,
}

impl Txs {
    /// check exist the hash
    fn exist(&self, hash: &U256) -> bool {
        self.0
            .iter()
            .find(|tx| tx.is_some() && &tx.as_ref().unwrap().hash == hash)
            .is_some()
    }

    /// get tx's position on unconfirmed
    fn position(&self, hash: &U256) -> Option<usize> {
        self.0
            .iter()
            .filter(|tx| tx.is_some())
            .position(|tx| &tx.as_ref().unwrap().hash == hash)
    }

    /// remove tx or panic!
    fn remove(&mut self, index: usize) -> Unconfirmed {
        self.0
            .iter_mut()
            .filter(|tx| tx.is_some())
            .nth(index)
            .take()
            .expect("index is out of bounds")
            .take()
            .expect("item is none but filtered?")
    }

    /// push an element to the back
    fn push(&mut self, value: Unconfirmed) {
        // note: rare case
        self.0.push(Some(value));
    }

    /// insert a item before the index specified
    fn insert(&mut self, index: usize, element: Unconfirmed) {
        // get raw_index on txs
        let raw_index = match self.0.iter().filter(|tx| tx.is_some()).nth(index) {
            // note: item is some type
            Some(item) => self.position(&item.as_ref().unwrap().hash).unwrap(),
            None => {
                if 0 < index {
                    panic!("index is out of bounds");
                } else {
                    // vec is empty
                    self.0.push(Some(element));
                    return;
                }
            },
        };

        // check index-1 is none and replace
        if 0 < raw_index {
            let item = self.0.get_mut(raw_index - 1).unwrap();
            if item.is_none() {
                item.replace(element);
                return;
            }
        }

        // check index-2 is none and replace
        if 1 < raw_index {
            let back_index = raw_index - 2;
            if self.0.get(back_index).unwrap().is_none() {
                self.0.get_mut(back_index).unwrap().replace(element);
                self.0.swap(back_index, raw_index - 1);
                return;
            }
        }

        // check index+1 is none and replace
        if raw_index + 1 < self.0.len() {
            let next_index = raw_index + 1;
            if self.0.get(next_index).unwrap().is_none() {
                self.0.get_mut(next_index).unwrap().replace(element);
                self.0.swap(raw_index, next_index);
                return;
            }
        }

        // not found empty item near and insert
        self.0.insert(raw_index, Some(element));
    }

    /// compact empty space of vec
    #[allow(dead_code)]
    fn compaction(&mut self) {
        // note: best empty space is same size of filled size
        let mut reserve_num = self.len() as i32;
        // note: beginning part should have empty space because of often edit and high cost to insert
        self.0
            .drain_filter(|tx| {
                // drop if return true
                if tx.is_none() {
                    reserve_num -= 1;
                    reserve_num < 0
                } else {
                    false
                }
            })
            .for_each(drop);
        // release memory
        self.0.shrink_to_fit();
    }

    /// total unconfirmed txs number
    fn len(&self) -> usize {
        self.0.iter().filter(|tx| tx.is_some()).count()
    }

    /// size hint (minimum, maximum)
    #[allow(dead_code)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.0.len()))
    }

    /// iterate unconfirmed txs
    fn streaming(&self) -> TxsIter {
        TxsIter {
            index: None,
            vec: &self.0,
        }
    }
}

impl UnconfirmedBuilder {
    pub fn new() -> Self {
        UnconfirmedBuilder {
            txs: Txs(Vec::with_capacity(100)),
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
        self.txs.exist(hash)
    }

    pub fn get_size(&self) -> u32 {
        let mut size = 0;
        while let Some(unconfirmed) = self.txs.streaming().next() {
            size += unconfirmed.size;
        }
        size
    }

    pub fn input_already_used(&self, input: &TxInput, tables: &Tables) -> Result<bool, String> {
        let hash = &input.0;
        while let Some(unconfirmed) = self.txs.streaming().next() {
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
        // note: don't remove from txcache

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

    pub fn remove_by_duplicate_inputs(
        &mut self,
        tables: &Tables,
        inputs: &Vec<TxInput>,
    ) -> Result<(), String> {
        // remove unconfirmed txs with same inputs
        // this method is used to force push new tx included in new block

        // find all same input use txs
        let mut hashs = Vec::new();
        for input in inputs.iter() {
            while let Some(unconfirmed) = self.txs.streaming().next() {
                if unconfirmed.depend_hashs.contains(&input.0) {
                    let tx = tables.read_txcache(&unconfirmed.hash)?.unwrap();
                    if tx.body.inputs.contains(input) {
                        hashs.push(tx.hash);
                    }
                }
            }
        }

        // remove many at once with depends
        self.remove_many(&hashs);

        Ok(())
    }

    pub fn get_size_limit_list(&self, maxsize: u32) -> Vec<U256> {
        // size limit unconfirmed tx's tuple for mining interface
        // note: drain by deadline before call this method
        let mut size = 0;
        let mut vec = Vec::with_capacity(3000);
        while let Some(unconfirmed) = self.txs.streaming().next() {
            size += unconfirmed.size;
            if size < maxsize {
                vec.push(unconfirmed.hash.clone());
            } else {
                break;
            }
        }
        vec.shrink_to_fit();
        vec
    }

    pub fn filtered_unconfirmed_iter(&self, filter: Option<Address>) -> UnconfirmedIter {
        // note: filter by address but optional
        UnconfirmedIter {
            txs_iter: self.txs.streaming(),
            filter,
        }
    }

    pub fn remove_expired_txs(&mut self, deadline: u32) -> Vec<U256> {
        // remove expired unconfirmed txs
        // note: remove from this but not remove from tables
        let mut deleted: Vec<Unconfirmed> = Vec::new();

        // remove from unconfirmed
        loop {
            let mut want_delete = None;
            while let Some(unconfirmed) = self.txs.streaming().next() {
                if unconfirmed.deadline < deadline {
                    want_delete = Some(unconfirmed.hash.clone());
                    break;
                }
            }
            match want_delete {
                Some(hash) => self.remove_with_depend_myself(&hash, &mut deleted),
                None => break,
            };
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
        while let Some(unconfirmed) = self.txs.streaming().next() {
            if ignore && output.is_some() {
                return Ok(());
            }

            // input already used & set output None
            if unconfirmed.depend_hashs.contains(&input.0) {
                let tx = tables.read_txcache(&unconfirmed.hash)?.unwrap();
                if tx.body.inputs.contains(input) {
                    output.take(); // <= None
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

    pub fn is_unused_input(&self, input: &TxInput, except_hash: &U256, is_unused: &mut bool) -> Option<bool> {
        // check the input is unused or not on unconfirmed section
        while let Some(unconfirmed) = self.txs.streaming().next() {
            if &unconfirmed.hash == except_hash {
                continue;
            }
            if unconfirmed.hash == input.0 {
                *is_unused = true;
            }
            // check the input is already used by unconfirmed tx
            if unconfirmed.depend_hashs.contains(&input.0) {
                return Some(false);
            }
        }
        // continue checking
        None
    }

    /// remove unconfirmed tx with depend it
    fn remove_with_depend_myself(&mut self, hash: &U256, deleted: &mut Vec<Unconfirmed>) {
        // find position
        let delete_index = match self.txs.position(hash) {
            Some(index) => index,
            None => return,
        };

        // delete tx
        deleted.push(self.txs.remove(delete_index));

        // check depend_hashs
        loop {
            let mut delete_hash = None;

            while let Some(tx) = self.txs.streaming().next() {
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
        while let Some(tx) = self.txs.streaming().next() {
            if unconfirmed.depend_hashs.contains(&tx.hash) {
                let index = self.txs.position(&tx.hash).unwrap();
                depend_index = Some(index);
            }
            if unconfirmed.hash == tx.hash {
                return Err("already inserted tx".to_owned());
            }
        }

        // most low position required index
        let mut required_index = None;
        let mut disturbs = Vec::new();
        while let Some(tx) = self.txs.streaming().rev().next() {
            if tx.depend_hashs.contains(&unconfirmed.hash) {
                let index = self.txs.position(&tx.hash).unwrap();
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
            let position = self.txs.position(&hash);
            return Ok(position.unwrap());
        }

        // normal: without disturbs
        // find best relative condition
        let mut best_index: Option<usize> = None;
        while let Some(tx) = self.txs.streaming().next() {
            let index = self.txs.position(&tx.hash).unwrap();
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
                self.txs.insert(best_index, unconfirmed);
                Ok(best_index)
            },
            None => {
                // println!("last {:?} {:?}", depend_index, required_index);
                self.txs.push(unconfirmed);
                Ok(self.txs.len() - 1)
            },
        }
    }
}

/// iterate unconfirmed txhash from priority high to low
pub struct UnconfirmedIter<'a> {
    txs_iter: TxsIter<'a>,
    filter: Option<Address>,
}

impl Iterator for UnconfirmedIter<'_> {
    type Item = U256;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.txs_iter.next() {
                Some(unconfirmed) => {
                    if self.filter.is_some() {
                        if unconfirmed.depend_addrs.check(self.filter.as_ref().unwrap()) {
                            // maybe the unconfirmed is related..
                            return Some(unconfirmed.hash);
                        } else {
                            // don't include the address
                            continue;
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
