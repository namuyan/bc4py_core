use crate::python::pyblock::{PyBlock, PyTxs};
use crate::python::pychain::{PyChain, SharedChain};
use crate::python::pytx::PyTxInputs;
use bigint::U256;
use pyo3::exceptions::{AssertionError, ValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Block & Tx validation methods
#[pyclass]
pub struct PyValidate {
    chain: SharedChain,
}

#[pymethods]
impl PyValidate {
    #[new]
    fn new(chain: PyRef<PyChain>) -> Self {
        PyValidate {
            chain: chain.clone_chain(),
        }
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
        let hashs = chain.unconfirmed.get_size_limit_list(maxsize);
        PyTxs::from_hash_vec(hashs)
    }
}
