use crate::block::{
    bits_to_target,
    target_to_bits,
    target_to_diff,
    BlockFlag,
    DifficultyBuilder,
    GenerateBuilder,
    PocWorker,
    PosWorker,
    PowWorker,
    RewardBuilder,
};
use crate::python::pyblock::{PyBlock, PyTxs};
use crate::python::pychain::{PyChain, SharedChain};
use crate::python::pytx::PyTxInputs;
use crate::utils::u256_to_bytes;
use bigint::U256;
use pyo3::exceptions::{AssertionError, ValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::Path;

/// Block & Tx validation methods
#[pyclass]
pub struct PyValidate {
    chain: SharedChain,
    /// block reward calculator
    reward: RewardBuilder,
    /// bits & bias calculator
    diff: DifficultyBuilder,
    /// mining block generator
    gene: GenerateBuilder,
    /// temporary workers info while generating
    tmp_info: Option<Vec<String>>,
}

#[pymethods]
impl PyValidate {
    #[new]
    fn new(chain: PyRef<PyChain>, total_supply: u64, params: &PyAny) -> PyResult<Self> {
        let vec: Vec<(u8, u32, u32, u32)> = params.extract()?;
        let mut params = Vec::with_capacity(vec.len());
        for p in vec {
            let flag = BlockFlag::from_int(p.0).map_err(|err| ValueError::py_err(err))?;
            params.push((flag, p.1, p.2, p.3));
        }
        Ok(PyValidate {
            chain: chain.clone_chain(),
            reward: RewardBuilder::new(total_supply),
            diff: DifficultyBuilder::new(params),
            gene: GenerateBuilder::new(),
            tmp_info: None,
        })
    }

    fn is_unconfirmed(&self, hash: &PyBytes) -> PyResult<bool> {
        // true -> unconfirmed
        // false -> confirmed or not exist
        let hash = hash.as_bytes();
        if hash.len() != 32 {
            Err(AssertionError::py_err("hash is 32 bytes"))
        } else {
            let chain = self.chain.lock().unwrap();
            Ok(chain.unconfirmed.have_the_tx(&U256::from(hash)))
        }
    }

    fn is_mature_input(&self, base_hash: &PyBytes, limit_height: u32) -> PyResult<bool> {
        // this method is designed for PoS coinbase tx's input check
        let base_hash = base_hash.as_bytes();
        if base_hash.len() != 32 {
            return Err(AssertionError::py_err("hash is 32 bytes"));
        }
        let base_hash = U256::from(base_hash);
        let chain = self.chain.lock().unwrap();

        // check unconfirmed: not allow unconfirmed input
        if chain.unconfirmed.have_the_tx(&base_hash) {
            return Ok(false);
        }

        // check confirmed
        for blockhash in chain.best_chain.iter() {
            let block = chain.confirmed.get_block_ref(blockhash).unwrap();
            if block.height < limit_height {
                return Ok(true);
            }
            for txhash in block.txs_hash.iter() {
                if *txhash == base_hash {
                    return Ok(false);
                }
            }
        }

        // check tables
        let mut height = chain
            .get_block(&chain.confirmed.root_hash)
            .unwrap()
            .expect("root_hash but not found block")
            .height;
        while limit_height <= height {
            let blockhash = chain.tables.read_block_index(height).unwrap().unwrap();
            let block = chain.tables.read_block(&blockhash).unwrap().unwrap();
            for txhash in block.txs_hash.iter() {
                if *txhash == base_hash {
                    return Ok(false);
                }
            }
            height -= 1;
        }

        // check passed
        Ok(true)
    }

    fn is_unused_inputs(
        &self,
        py: Python,
        inputs: PyRef<PyTxInputs>,
        except_hash: &PyBytes,
        best_block: Option<PyRef<PyBlock>>,
    ) -> PyResult<bool> {
        // return inputs status: unused(True) or not(False)
        let chain = self.chain.lock().unwrap();

        // except tx's hash
        // don't check the tx because it don't use its own input
        let except_hash = except_hash.as_bytes();
        if except_hash.len() != 32 {
            return Err(AssertionError::py_err("input_hash and except_hash is 32 bytes"));
        }
        let except_hash = U256::from(except_hash);

        // check: tables -> confirmed -> unconfirmed
        if best_block.is_some() {
            // block included tx check
            let best_block = best_block.as_ref().unwrap().clone_to_full_block(py)?;
            let best_chain = chain
                .confirmed
                .get_best_chain_by(&best_block.0.header.previous_hash)
                .map_err(|err| ValueError::py_err(err))?;
            let best_block = Some(best_block);

            for input in inputs.inputs.iter() {
                if chain
                    .is_unused_input(input, &except_hash, &best_block, &best_chain)
                    .map_err(|err| ValueError::py_err(err))?
                {
                    // success: unused
                    // do nothing
                } else {
                    // failed: already used
                    return Ok(false);
                }
            }
        } else {
            // unconfirmed tx check
            let best_block = None;
            let best_chain = &chain.best_chain;

            for input in inputs.inputs.iter() {
                if chain
                    .is_unused_input(input, &except_hash, &best_block, best_chain)
                    .map_err(|err| ValueError::py_err(err))?
                {
                    // success: unused
                    // do nothing
                } else {
                    // failed: already used
                    return Ok(false);
                }
            }
        }

        // check success
        Ok(true)
    }

    fn is_orphan_block(&self, block: PyRef<PyBlock>) -> bool {
        // check the block is confirmed or finalized
        let chain = self.chain.lock().unwrap();
        let hash = block.header.hash();

        // from confirmed
        if chain.best_chain.contains(&hash) {
            return false;
        }

        // from tables
        match chain.tables.read_block(&hash).unwrap() {
            Some(block) => match chain.tables.read_block_index(block.height).unwrap() {
                // block confirmed and check indexed hash is same or not
                // waring: **true** means **orphan**
                Some(indexed_hash) => block.header.hash() != indexed_hash,
                // block confirmed but not indexed (not in best_chain) is orphan
                None => true,
            },
            // not found in tables and confirmed
            None => true,
        }
    }

    fn clear_old_unconfirmed(&self, deadline: u32) -> usize {
        // remove expired unconfirmed txs & return removed txs count
        let mut chain = self.chain.lock().unwrap();
        chain.unconfirmed.remove_expired_txs(deadline).len()
    }

    fn get_best_unconfirmed(&self, maxsize: u32) -> PyTxs {
        // get size limited unconfirmed tx's list
        let chain = self.chain.lock().unwrap();
        let hashs = chain.unconfirmed.get_best_unconfirmed_list(maxsize);
        PyTxs::from_hash_vec(hashs.txs)
    }

    fn calc_next_bits(&mut self, previous_hash: &PyBytes, flag: u8) -> PyResult<u32> {
        let previous_hash = previous_hash.as_bytes();
        if previous_hash.len() != 32 {
            return Err(ValueError::py_err("previous_hash is 32 bytes"));
        }
        let previous_hash = U256::from(previous_hash);
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let chain = self.chain.lock().unwrap();
        // get next bits from previous info
        self.diff
            .calc_next_bits(&previous_hash, &flag, &chain.tables)
            .map_err(|err| ValueError::py_err(err))
    }

    fn calc_next_bias(&mut self, previous_hash: &PyBytes, flag: u8) -> PyResult<f32> {
        let previous_hash = previous_hash.as_bytes();
        if previous_hash.len() != 32 {
            return Err(ValueError::py_err("previous_hash is 32 bytes"));
        }
        let previous_hash = U256::from(previous_hash);
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let chain = self.chain.lock().unwrap();
        // get next bias from previous info
        self.diff
            .calc_next_bias(&previous_hash, &flag, &chain.tables)
            .map_err(|err| ValueError::py_err(err))
    }

    #[staticmethod]
    fn bits_to_target(py: Python, bits: u32) -> PyResult<PyObject> {
        match bits_to_target(bits) {
            Ok(target) => Ok(PyBytes::new(py, u256_to_bytes(&target).as_ref()).to_object(py)),
            Err(err) => Err(ValueError::py_err(format!("cannot bits to target by: {}", err))),
        }
    }

    #[staticmethod]
    fn target_to_bits(target: &PyBytes) -> PyResult<u32> {
        let target = target.as_bytes();
        if target.len() != 32 {
            return Err(ValueError::py_err("target is 32 bytes"));
        }
        let target = U256::from(target);
        Ok(target_to_bits(&target))
    }

    #[staticmethod]
    fn target_to_diff(target: &PyBytes) -> PyResult<f64> {
        let target = target.as_bytes();
        if target.len() != 32 {
            return Err(ValueError::py_err("target is 32 bytes"));
        }
        let target = U256::from(target);
        Ok(target_to_diff(target))
    }

    fn calc_block_reward(&self, height: u32) -> u64 {
        self.reward.calc_block_reward(height)
    }

    fn calc_total_supply(&self, height: u32) -> u64 {
        self.reward.calc_total_supply(height)
    }

    fn get_worker_info(&self) -> Vec<String> {
        match &self.tmp_info {
            None => self.gene.get_worker_info(),
            Some(info) => info.clone(),
        }
    }

    fn push_pow_worker(&mut self, flag: u8, power_limit: u8, block_ver: u32, tx_ver: u32) -> PyResult<()> {
        let flag = BlockFlag::from_int(flag).map_err(|err| AssertionError::py_err(err))?;
        let worker = PowWorker::new(&flag, power_limit, block_ver, tx_ver);
        self.gene
            .push_worker(worker)
            .map_err(|err| ValueError::py_err(err))?;
        Ok(())
    }

    fn push_pos_worker(&mut self) -> PyResult<()> {
        let worker = PosWorker::new();
        self.gene
            .push_worker(worker)
            .map_err(|err| ValueError::py_err(err))?;
        Ok(())
    }

    fn push_poc_worker(&mut self, dirs: Vec<String>) -> PyResult<()> {
        let dirs = dirs.iter().map(|path| Path::new(path)).collect();
        let worker = PocWorker::new(dirs);
        self.gene
            .push_worker(worker)
            .map_err(|err| ValueError::py_err(err))?;
        Ok(())
    }

    fn remove_worker(&mut self, flag: u8) -> PyResult<()> {
        let flag = BlockFlag::from_int(flag).map_err(|err| AssertionError::py_err(err))?;
        self.gene.remove_worker(&flag);
        Ok(())
    }

    fn generate_work(&mut self, py: Python) {
        self.tmp_info.replace(self.gene.get_worker_info());

        let mut future = self.gene.throw_task();

        // release python's GIL and wait for threads finish
        py.allow_threads(|| {
            future.wait();
        });

        let chain = self.chain.lock().unwrap();

        // get mined block
        let (_a, _b) = self.gene.future_result(&chain, future).unwrap();

        // TODO: return full block?
        unimplemented!()
    }
}
