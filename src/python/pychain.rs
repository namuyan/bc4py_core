use crate::block::Block;
use crate::chain::Chain;
use crate::python::{pyblock::PyBlock, pytx::PyTx};
use crate::tx::Tx;
use bigint::U256;
use pyo3::exceptions::{TypeError, ValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::Path;

#[pyclass]
pub struct PyChain {
    pub chain: Chain,
}

#[pymethods]
impl PyChain {
    #[new]
    fn new(
        root_dir: &str,
        sk: Option<&PyBytes>,
        deadline: u32,
        tx_index: bool,
        addr_index: bool,
    ) -> PyResult<Self> {
        let dir = Path::new(root_dir).join("database");
        // auto create `root_dir/database` directory.
        // check initialize by the folder's existence.

        let sk = sk.map(|bytes| bytes.as_bytes().to_vec());
        // sk is BIP32 root secret extended key => m/44'/CoinType'
        // account generation require secret key because harden derive => m/44'/CoinType'/account_id'
        // account address derive do NOT require sk => m/44'/CoinType'/account_id'/isInner/index

        match Chain::new(dir.as_ref(), &sk, deadline, tx_index, addr_index) {
            Ok(chain) => Ok(PyChain { chain }),
            Err(err) => Err(ValueError::py_err(err)),
        }
    }

    fn push_new_block(&mut self, block: PyRef<PyBlock>, txs: Vec<PyRef<PyTx>>) -> PyResult<()> {
        if self.chain.tables.is_closed {
            return Err(ValueError::py_err("already closed!"));
        }
        let block: Block = block
            .clone_to_block()
            .map_err(|_err| TypeError::py_err(_err))?;
        let txs = txs.iter().map(|_tx| _tx.clone_to_tx()).collect::<Vec<Tx>>();

        // note: push txs to unconfirmed before
        // warning: error means tables is broken, do not allow this error
        self.chain
            .push_new_block(block, &txs)
            .map_err(|_err| ValueError::py_err(format!("low-level block push failed: {}", _err)))
    }

    fn push_unconfirmed(&mut self, tx: PyRef<PyTx>) -> PyResult<()> {
        if self.chain.tables.is_closed {
            return Err(ValueError::py_err("already closed!"));
        }
        let tx = tx.clone_to_tx();
        if tx.is_coinbase() {
            return Err(ValueError::py_err(
                "you try to push coinbase as unconfirmed",
            ));
        }
        self.chain
            .push_unconfirmed(&tx)
            .map_err(|_err| ValueError::py_err(format!("push unconfirmed failed: {}", _err)))
    }

    fn get_block(&self, hash: &PyBytes) -> PyResult<Option<PyBlock>> {
        let hash = hash.as_bytes();
        if hash.len() != 32 {
            return Err(TypeError::py_err("hash is 32 bytes"));
        }
        match self
            .chain
            .get_block(&U256::from(hash))
            .map_err(|_err| ValueError::py_err(_err))?
        {
            Some(block) => Ok(Some(PyBlock::from_block(block)?)),
            None => Ok(None),
        }
    }

    fn get_tx(&self, hash: &PyBytes) -> PyResult<Option<PyTx>> {
        let hash = hash.as_bytes();
        if hash.len() != 32 {
            return Err(TypeError::py_err("hash is 32 bytes"));
        }
        match self
            .chain
            .get_tx(&U256::from(hash))
            .map_err(|_err| ValueError::py_err(_err))?
        {
            Some(tx) => Ok(Some(PyTx::from_tx(tx)?)),
            None => Ok(None),
        }
    }

    #[getter]
    fn get_is_closed(&self) -> bool {
        self.chain.tables.is_closed
    }

    fn close(&mut self) -> PyResult<()> {
        if self.chain.tables.is_closed {
            Err(ValueError::py_err(
                "already close and maybe database is broken",
            ))
        } else {
            self.chain.tables.close();
            Ok(())
        }
    }
}
