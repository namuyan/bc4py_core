use crate::block::{bits_to_target, get_pos_hash, Block, BlockFlag, BlockHeader, DifficultyBuilder};
use crate::chain::unconfirmed::UnconfirmedTxs;
use crate::chain::Chain;
use crate::tx::{TxBody, TxMessage, TxOutput, TxType, TxVerifiable};
use crate::utils::*;
use bc4py_hash::plotfile::{PlotFile, PlotFlag};
use bc4py_hash::seekfile::seek_file;
use bc4py_hash::{get_x11_hash, get_x16s_hash, get_yespower_hash};
use bigint::U256;
use std::cmp::max;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::thread;
use std::time::Instant;

/// mining worker duck typing
type WorkerType = Box<dyn WorkerTrait + Send>;

/// input's mature height that PoS mining coinbase can use
const MATURE_HEIGHT: u32 = 20;

/// generation result of mining
pub enum WorkerResult {
    /// (work, coinbase, header)
    PoW((U256, TxBody, [u8; 80])),
    /// (work, Coinbase, header, amount)
    PoS((U256, TxBody, BlockHeader, u64)),
    /// (work, header, plotFile)
    PoC((U256, BlockHeader, PlotFile)),
    /// cannot find work met a target
    NotFoundWork,
}

/// general mining & staking trait
pub trait WorkerTrait {
    /// manually throw task and may return in one second
    fn generate(&mut self) -> WorkerResult;

    /// update mining info by new accepted block or reverted block
    fn update_by_new_block(
        &mut self,
        chain: &mut Chain,
        new_block: &Block,
        new_bits: u32,
        block_reward: u64,
        txs_reward: u64,
        txs: &UnconfirmedTxs,
    );

    /// update mining info of time & deadline.
    ///
    /// # panic
    /// ```
    /// assert!(txs.time <= time);
    /// assert!(deadline < txs.deadline);
    /// ```
    ///
    /// # note
    /// design execute this before `generate()`.
    fn update_time_and_deadline(&mut self, time: u32, deadline: u32, txs: &UnconfirmedTxs);

    /// hashrate X hash/sec
    fn get_hashrate(&self) -> Option<usize>;

    /// worker debug info
    fn get_info(&self) -> String;

    /// get block flag
    fn get_flag(&self) -> &BlockFlag;
}

/// proof of work
pub struct PowWorker {
    flag: BlockFlag,
    header: BlockHeader,
    coinbase: TxBody,
    /// pow hash function (input 80bytes slice and output 32bytes vec)
    hash_func: fn(&[u8]) -> Vec<u8>,
    /// CPU occupancy (power_limit / 255 * 100 %)
    power_limit: f64,
    /// store generation span to fix best count number
    span: VecDeque<(usize, f64)>, // (count, time)
}

impl PowWorker {
    pub fn new(flag: &BlockFlag, power_limit: u8, block_ver: u32, tx_ver: u32) -> WorkerType {
        assert!(0 < power_limit, "power_limit's range is 1~255");
        // note: need to init before mining
        let flag = flag.clone();
        let header = BlockHeader {
            version: block_ver,
            previous_hash: U256::zero(), // update after
            merkleroot: U256::zero(),    // update after
            time: 0,                     // update after
            bits: 0,                     // update after
            nonce: 0,
        };
        let coinbase = TxBody {
            version: tx_ver,
            txtype: TxType::PoW,
            time: 0,         // update after
            deadline: 0,     // update after
            inputs: vec![],  // update after
            outputs: vec![], // update after
            gas_price: 0,
            gas_amount: 0,
            message: TxMessage::Nothing,
        };
        let hash_func: fn(&[u8]) -> Vec<u8> = match flag {
            BlockFlag::YesPow => |x| get_yespower_hash(x),
            BlockFlag::X11Pow => |x| get_x11_hash(x),
            BlockFlag::X16sPow => |x| get_x16s_hash(x),
            _ => unreachable!(),
        };
        Box::new(PowWorker {
            flag,
            header,
            coinbase,
            hash_func,
            power_limit: power_limit as f64,
            span: VecDeque::new(),
        })
    }

    /// private update merkleroot
    fn update_merkleroot(&mut self, unconfirmed: &UnconfirmedTxs) {
        let mut hashs = Vec::with_capacity(1 + unconfirmed.txs.len());
        hashs.push(U256::from(self.coinbase.hash().as_slice()));
        hashs.extend_from_slice(&unconfirmed.txs);
        self.header.merkleroot = calc_merkleroot_hash(hashs);
    }
}

impl WorkerTrait for PowWorker {
    fn generate(&mut self) -> WorkerResult {
        let now = Instant::now();

        // find good count number
        let count = if 10 < self.span.len() {
            let mut fixed = 0.0;
            let mut real = 0.0;
            for (i, (count, time)) in self.span.iter().enumerate().skip(1) {
                let (_before_count, before_time) = &self.span[i - 1];
                assert!(before_time <= time);
                fixed += (count * i) as f64 * 1.0;
                real += (count * i) as f64 * (time - before_time);
            }
            let (last_count, _last_time) = self.span.iter().last().unwrap();
            // note: fixed is more and more bigger, count should more and more bigger
            let fixed_count = *last_count as f64 * real / fixed;
            // note: panic if you set count zero
            max(10, fixed_count as usize)
        } else {
            100 // default 1oo loop
        };

        // prepare initial params
        let mut bytes = self.header.to_bytes();
        let mut nonce = bytes_to_u32(&bytes[76..76 + 4]);
        let target = bits_to_target(self.header.bits).unwrap();

        // hash generation loop
        for _ in 0..count {
            let output = (self.hash_func)(bytes.as_ref());
            // check enough work and replace old
            let work = U256::from(output.as_slice());
            if work < target {
                return WorkerResult::PoW((work, self.coinbase.clone(), bytes));
            }
            // prepare next input
            nonce = nonce.checked_add(1).unwrap_or(0);
            bytes[76..76 + 4].clone_from_slice(&nonce.to_le_bytes());
        }

        // recode span info
        let real_span = now.elapsed().as_secs_f64();
        let virtual_span = real_span * 255.0 / self.power_limit;
        self.span.push_back((count, virtual_span));

        // limit span queue size
        if 100 < self.span.len() {
            self.span.pop_front();
        }

        // not found work
        WorkerResult::NotFoundWork
    }

    fn update_by_new_block(
        &mut self,
        chain: &mut Chain,
        new_block: &Block,
        new_bits: u32,
        block_reward: u64,
        txs_reward: u64,
        unconfirmed: &UnconfirmedTxs,
    ) {
        // new output addr
        let addr = chain
            .get_account_address(0, false)
            .expect("try to get addr from already created accountId 0?");

        // update header by new block
        self.header.previous_hash = new_block.header.hash();
        self.header.bits = new_bits;
        self.coinbase.outputs = vec![TxOutput(addr, 0, block_reward + txs_reward)];
        self.update_merkleroot(unconfirmed);
    }

    fn update_time_and_deadline(&mut self, time: u32, deadline: u32, unconfirmed: &UnconfirmedTxs) {
        assert!(unconfirmed.time <= time);
        assert!(deadline < unconfirmed.deadline);
        // update header & coinbase time
        self.header.time = time;
        self.coinbase.time = time;
        self.coinbase.deadline = deadline;
        self.update_merkleroot(unconfirmed);
    }

    fn get_hashrate(&self) -> Option<usize> {
        if 5 < self.span.len() {
            let mut sum = 0;
            let mut len = 0;
            for (count, _time) in self.span.iter() {
                sum += *count;
                len += 1;
            }
            let hashrate = sum as f64 / len as f64;
            Some(hashrate as usize)
        } else {
            None // unknown hashrate
        }
    }

    fn get_info(&self) -> String {
        let hashrate = self.get_hashrate();
        let power = self.power_limit / 255.0 * 100.0;
        if let Some(rate) = hashrate {
            format!("<PoW {:?} {}hash/s {:.2}%>", self.flag, rate, power)
        } else {
            format!("<PoW {:?} ... {:.2}%>", self.flag, power)
        }
    }

    fn get_flag(&self) -> &BlockFlag {
        &self.flag
    }
}

/// proof of stake
pub struct PosWorker {
    flag: BlockFlag,
    /// Vec<(coinbase, input amount)>
    coinbase: Vec<(TxBody, u64)>,
    previous_hash: U256,
    bits: u32,
    /// newest hashrate info (hash, sec)
    generate_info: Option<(usize, f64)>,
}

impl PosWorker {
    pub fn new() -> WorkerType {
        Box::new(PosWorker {
            flag: BlockFlag::CoinPos,
            coinbase: vec![],
            previous_hash: U256::zero(),
            bits: 0,
            generate_info: None,
        })
    }
}

impl WorkerTrait for PosWorker {
    fn generate(&mut self) -> WorkerResult {
        let now = Instant::now();
        let target = bits_to_target(self.bits).unwrap();
        let mut total = 0;

        for (index, (coinbase, amount)) in self.coinbase.iter().enumerate() {
            total += 1;
            let work = get_pos_hash(coinbase, *amount, &self.previous_hash);
            if work < target {
                let header = BlockHeader {
                    version: 0, // always zero
                    previous_hash: self.previous_hash,
                    merkleroot: U256::zero(), // update after
                    time: coinbase.time,
                    bits: self.bits,
                    nonce: 0, // always zero
                };
                return WorkerResult::PoS((work, coinbase.clone(), header, *amount));
            }
            // skip if over a second
            if index % 10 == 0 && 1.0 <= now.elapsed().as_secs_f32() {
                break;
            }
        }

        // update hashrate
        self.generate_info.replace((total, now.elapsed().as_secs_f64()));

        // not found work
        WorkerResult::NotFoundWork
    }

    fn update_by_new_block(
        &mut self,
        chain: &mut Chain,
        new_block: &Block,
        new_bits: u32,
        block_reward: u64,
        _txs_reward: u64,
        _txs: &UnconfirmedTxs,
    ) {
        // get list unspent for staking limited by some condition
        let mut limit = 5000usize;
        let mut unspent = Vec::with_capacity(limit);
        for (input, output) in chain.get_account_unspent_iter() {
            // check conditions
            if output.1 != 0 {
                continue; // skip: coinId is 0
            }
            if output.0[0] != 0 {
                continue; // skip: AddrVer is 0
            }
            if output.2 < 1_0000_0000 {
                continue; // skip: amount is more than 1.0
            }

            // check height
            match chain.get_tx_height(&input.0) {
                Ok(Some(height)) => {
                    if new_block.height + 1 <= height + MATURE_HEIGHT {
                        continue; // skip: not enough mature input
                    }
                },
                _ => continue, // skip: unconfirmed or not found tx
            }

            // find good unspent
            unspent.push((
                TxBody {
                    version: 0,
                    txtype: TxType::PoS,
                    time: 0,
                    deadline: 0,
                    inputs: vec![input],
                    // note: PoS reward don't include txs_reward because only time change hash.
                    outputs: vec![TxOutput(output.0, output.1, output.2 + block_reward)],
                    gas_price: 0,
                    gas_amount: 0,
                    message: TxMessage::Nothing,
                },
                output.2,
            ));

            // loop limit
            match limit.checked_sub(1) {
                Some(new_limit) => limit = new_limit,
                None => break,
            }
        }

        // replace old coinbase & previous
        unspent.shrink_to_fit();
        self.coinbase = unspent;
        self.previous_hash = new_block.header.hash();
        self.bits = new_bits;
    }

    fn update_time_and_deadline(&mut self, time: u32, deadline: u32, txs: &UnconfirmedTxs) {
        assert!(txs.time <= time);
        assert!(deadline < txs.deadline);
        for (tx, _) in self.coinbase.iter_mut() {
            tx.time = time;
            tx.deadline = deadline;
        }
    }

    fn get_hashrate(&self) -> Option<usize> {
        match self.generate_info {
            Some((hashrate, _)) => Some(hashrate),
            None => None,
        }
    }

    fn get_info(&self) -> String {
        match self.generate_info {
            Some((hashrate, span)) => format!(
                "<PoS {}unspent {}hash/s {:.2}%load>",
                self.coinbase.len(),
                hashrate,
                (span / 1.0 * 100.0) as f32
            ),
            None => format!("<PoS {}unspent ...>", self.coinbase.len()),
        }
    }

    fn get_flag(&self) -> &BlockFlag {
        &self.flag
    }
}

/// proof of capacity
pub struct PocWorker {
    flag: BlockFlag,
    /// optimized plot files list
    plots: Vec<PlotFile>,
    previous_hash: U256,
    bits: u32,
    block_reward: u64,
    time: u32,
    /// newest hashrate info (hash, sec)
    generate_info: Option<(usize, f64)>,
}

impl PocWorker {
    /// # panic
    /// if dirs is not directory or not exist
    pub fn new(dirs: Vec<&Path>) -> WorkerType {
        let plots = dirs
            .iter()
            // get all plots from directories
            .map(|dir| PlotFile::restore_from_dir(dir))
            .flatten()
            // remove non-optimized plots
            .filter(|plot| plot.flag == PlotFlag::Optimized)
            .collect::<Vec<PlotFile>>();

        Box::new(PocWorker {
            flag: BlockFlag::CapPos,
            plots,
            previous_hash: U256::zero(),
            bits: 0,
            block_reward: 0,
            time: 0,
            generate_info: None,
        })
    }
}

impl WorkerTrait for PocWorker {
    fn generate(&mut self) -> WorkerResult {
        let now = Instant::now();
        let mut count = 0;

        let previous_hash = u256_to_bytes(&self.previous_hash);
        let target = u256_to_bytes(&bits_to_target(self.bits).unwrap());
        for plot in self.plots.iter() {
            assert_eq!(plot.flag, PlotFlag::Optimized);
            match seek_file(
                &plot.path,
                plot.start,
                plot.end,
                previous_hash.as_ref(),
                target.as_ref(),
                self.time,
                true,
            ) {
                Ok((nonce, work)) => {
                    let work = U256::from(work.as_slice());
                    let header = BlockHeader {
                        version: 0, // always zero
                        previous_hash: self.previous_hash,
                        merkleroot: U256::zero(), // update after
                        time: self.time,
                        bits: self.bits,
                        nonce,
                    };
                    return WorkerResult::PoC((work, header, plot.clone()));
                },
                Err(_err) => {
                    count += plot.end - plot.start;
                    if 1.0 <= now.elapsed().as_secs_f64() {
                        break;
                    }
                },
            }
        }

        // update hashrate info
        self.generate_info.replace((count, now.elapsed().as_secs_f64()));

        // not found work
        WorkerResult::NotFoundWork
    }

    fn update_by_new_block(
        &mut self,
        _chain: &mut Chain,
        new_block: &Block,
        new_bits: u32,
        block_reward: u64,
        _txs_reward: u64,
        _txs: &UnconfirmedTxs,
    ) {
        self.previous_hash = new_block.header.hash();
        self.bits = new_bits;
        self.block_reward = block_reward;
    }

    fn update_time_and_deadline(&mut self, time: u32, _deadline: u32, _txs: &UnconfirmedTxs) {
        self.time = time;
    }

    fn get_hashrate(&self) -> Option<usize> {
        match self.generate_info {
            Some((hashrate, _)) => Some(hashrate),
            None => None,
        }
    }

    fn get_info(&self) -> String {
        match self.generate_info {
            Some((hashrate, span)) => format!(
                "<PoC {}files {}hash/s {:.2}%load>",
                self.plots.len(),
                hashrate,
                (span / 1.0 * 100.0) as f32
            ),
            None => format!("<PoC {}files ...", self.plots.len()),
        }
    }

    fn get_flag(&self) -> &BlockFlag {
        &self.flag
    }
}

/// future object of generating threads
pub struct GenerateFuture<R = (WorkerResult, WorkerType)> {
    threads: Option<Vec<thread::JoinHandle<R>>>,
    result: Option<Vec<R>>,
}

impl<R> GenerateFuture<R> {
    /// wait for threads work finish
    pub fn wait(&mut self) {
        if self.result.is_some() {
            return;
        }
        assert!(self.threads.is_some());
        let mut result = vec![];
        for thread in self.threads.take().unwrap().into_iter() {
            result.push(thread.join().unwrap());
        }
        self.result.replace(result);
    }

    /// get result of threads
    pub fn get(mut self) -> Vec<R> {
        if self.result.is_none() {
            self.wait();
        }
        self.result.unwrap()
    }
}

/// new block generator
pub struct GenerateBuilder {
    /// generating threads.
    threads: Vec<WorkerType>,
    /// workers before update by best_block
    reserve: Vec<WorkerType>,
    /// mining block height
    height: u32,
    /// block reward of the hight
    reward: u64,
    /// mining info to generate mined block
    new_block_info: HashMap<BlockFlag, (f32,)>,
    /// unconfirmed transaction's hash list
    unconfirmed: UnconfirmedTxs,
}

impl GenerateBuilder {
    pub fn new() -> Self {
        GenerateBuilder {
            threads: vec![],
            reserve: vec![],
            height: 0,
            reward: 0,
            new_block_info: HashMap::new(),
            unconfirmed: UnconfirmedTxs {
                txs: vec![],
                time: u32::MAX,
                deadline: 0,
                reward: 0,
            },
        }
    }

    /// get thread info
    pub fn get_worker_info(&self) -> Vec<String> {
        self.threads.iter().map(|thread| thread.get_info()).collect()
    }

    /// add new worker.
    /// return error if already pushed same block flag worker.
    pub fn push_worker(&mut self, worker: WorkerType) -> Result<(), String> {
        // note: not allow block flag duplicate
        for thread in self.reserve.iter().chain(self.threads.iter()) {
            if thread.get_flag() == worker.get_flag() {
                return Err(format!("already mining thread exist: {}", thread.get_info()));
            }
        }
        self.threads.push(worker);
        Ok(())
    }

    /// remove worker from threads
    pub fn remove_worker(&mut self, flag: &BlockFlag) {
        // note: cannot find removed or not
        self.reserve
            .drain_filter(|thread| thread.get_flag() == flag)
            .for_each(drop);
        self.threads
            .drain_filter(|thread| thread.get_flag() == flag)
            .for_each(drop);
    }

    /// update mining block's unconfirmed list
    pub fn update_unconfirmed_list(&mut self, unconfirmed: UnconfirmedTxs) {
        self.unconfirmed = unconfirmed;
    }

    /// update by new_block
    pub fn update_by_new_block(
        &mut self,
        chain: &mut Chain,
        new_block: &Block,
        new_block_reward: u64,
        diff: &mut DifficultyBuilder,
    ) -> Result<(), String> {
        // move prepared worker to working thread vec
        self.threads.extend(self.reserve.drain(..));

        // update by new block info
        // note: update unconfirmed list before
        let previous_hash = new_block.header.hash();
        for worker in self.threads.iter_mut() {
            let flag = worker.get_flag().clone();
            let new_bits = diff.calc_next_bits(&previous_hash, &flag, &chain.tables)?;
            let new_bias = diff.calc_next_bias(&previous_hash, &flag, &chain.tables)?;
            worker.update_by_new_block(
                chain,
                new_block,
                new_bits,
                new_block_reward,
                self.unconfirmed.reward,
                &self.unconfirmed,
            );
            self.new_block_info.insert(flag, (new_bias,));
        }

        // mining height
        self.height = new_block.height + 1;
        self.reward = new_block_reward;

        // success
        Ok(())
    }

    /// throw worker to other threads and return future
    pub fn throw_task(&mut self) -> GenerateFuture {
        let mut threads = vec![];
        while let Some(mut worker) = self.threads.pop() {
            threads.push(thread::spawn(move || (worker.generate(), worker)))
        }
        // note: get worker info in advance because thread is empty
        GenerateFuture {
            threads: Some(threads),
            result: None,
        }
    }

    /// get result from future and get new block
    pub fn future_result(
        &mut self,
        chain: &Chain,
        futures: GenerateFuture,
    ) -> Option<(Block, Vec<TxVerifiable>)> {
        // wait threads finish
        let mut mined = None;
        for (result, worker) in futures.get() {
            // note: ignore if already mined block found
            if mined.is_none() {
                let flag = worker.get_flag().clone();

                match result {
                    WorkerResult::PoW((work_hash, coinbase, bytes)) => {
                        // generate block
                        let (bias,) = self.new_block_info.get(&flag).cloned().unwrap();
                        let header = BlockHeader::from_bytes(bytes.as_ref());
                        let txs_len = self.unconfirmed.txs.len() + 1;
                        let mut txs_hash = Vec::with_capacity(txs_len);
                        let coinbase_hash = U256::from(coinbase.hash().as_slice());
                        txs_hash.push(coinbase_hash.clone());
                        txs_hash.extend_from_slice(&self.unconfirmed.txs);
                        assert_eq!(header.merkleroot, calc_merkleroot_hash(txs_hash.clone()));
                        let block = Block::new(work_hash, self.height, flag, bias, header, txs_hash);

                        // don't need to generate signature
                        // note: PoW coinbase don't have signature and input

                        // generate txs
                        let coinbase = TxVerifiable {
                            hash: coinbase_hash,
                            body: coinbase,
                            signature: vec![],
                            inputs_cache: vec![],
                        };
                        let txs = self.unconfirmed.get_mining_block_txs(coinbase, &chain.tables);

                        // success
                        mined = Some((block, txs));
                    },
                    WorkerResult::PoS((work_hash, coinbase, mut header, amount)) => {
                        // generate block
                        let (bias,) = self.new_block_info.get(&flag).cloned().unwrap();
                        let txs_len = self.unconfirmed.txs.len() + 1;
                        let mut txs_hash = Vec::with_capacity(txs_len);
                        let coinbase_hash = U256::from(coinbase.hash().as_slice());
                        txs_hash.push(coinbase_hash.clone());
                        txs_hash.extend_from_slice(&self.unconfirmed.txs);
                        header.merkleroot = calc_merkleroot_hash(txs_hash.clone());
                        let block = Block::new(work_hash, self.height, flag, bias, header, txs_hash);

                        // generate signature
                        // note: staking signature is header's not tx's
                        let mut output_of_input = coinbase.outputs[0].clone();
                        output_of_input.2 = amount;
                        let signature = chain
                            .account
                            .get_single_sign_by_addr(&output_of_input.0, block.header.to_bytes().as_ref())
                            .expect("generate signature for PoS mining");

                        // generate txs
                        let coinbase = TxVerifiable {
                            hash: coinbase_hash,
                            body: coinbase,
                            signature: vec![signature],
                            inputs_cache: vec![output_of_input],
                        };
                        let txs = self.unconfirmed.get_mining_block_txs(coinbase, &chain.tables);

                        // success
                        mined = Some((block, txs));
                    },
                    WorkerResult::PoC((work_hash, mut header, plot)) => {
                        // generate coinbase
                        let coinbase = TxBody {
                            version: 0,
                            txtype: TxType::PoS,
                            time: header.time,
                            deadline: header.time + 10800,
                            inputs: vec![],
                            outputs: vec![TxOutput(plot.addr, 0, self.reward)],
                            gas_price: 0,
                            gas_amount: 0,
                            message: TxMessage::Nothing,
                        };

                        // generate block
                        let (bias,) = self.new_block_info.get(&flag).cloned().unwrap();
                        let txs_len = self.unconfirmed.txs.len() + 1;
                        let mut txs_hash = Vec::with_capacity(txs_len);
                        let coinbase_hash = U256::from(coinbase.hash().as_slice());
                        txs_hash.push(coinbase_hash.clone());
                        txs_hash.extend_from_slice(&self.unconfirmed.txs);
                        header.merkleroot = calc_merkleroot_hash(txs_hash.clone());
                        let block = Block::new(work_hash, self.height, flag, bias, header, txs_hash);

                        // generate signature
                        // note: staking signature is header's not tx's
                        let signature = chain
                            .account
                            .get_single_sign_by_addr(&plot.addr, block.header.to_bytes().as_ref())
                            .expect("generate signature for PoC mining");

                        // generate txs
                        let coinbase = TxVerifiable {
                            hash: coinbase_hash,
                            body: coinbase,
                            signature: vec![signature],
                            inputs_cache: vec![],
                        };
                        let txs = self.unconfirmed.get_mining_block_txs(coinbase, &chain.tables);

                        // success
                        mined = Some((block, txs));
                    },
                    WorkerResult::NotFoundWork => (),
                }
            }

            // return worker
            self.threads.push(worker);
        }

        // success
        mined
    }
}
