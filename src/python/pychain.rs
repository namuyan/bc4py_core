use crate::balance::*;
use crate::block::Block;
use crate::chain::Chain;
use crate::python::pyunspent::PyUnspent;
use crate::python::{pyaccount::*, pyaddr::PyAddress, pyblock::PyBlock, pytx::PyTx};
use crate::tx::{TxInput, TxOutput};
use bigint::U256;
use pyo3::exceptions::{TypeError, ValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::cmp::{Ordering, PartialOrd};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

type Address = [u8; 21];
pub type SharedChain = Arc<Mutex<Chain>>;

#[pyclass]
pub struct PyChain {
    chain: SharedChain,
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
            Ok(chain) => Ok(PyChain {
                chain: Arc::new(Mutex::new(chain)),
            }),
            Err(err) => Err(ValueError::py_err(err)),
        }
    }

    fn push_new_block(&self, py: Python, block: PyRef<PyBlock>, txs: Vec<PyRef<PyTx>>) -> PyResult<()> {
        let mut chain = self.lock();
        if chain.tables.is_closed {
            return Err(ValueError::py_err("already closed!"));
        }
        let block: Block = block.clone_to_block().map_err(|_err| TypeError::py_err(_err))?;
        let txs = {
            let mut _txs = Vec::with_capacity(block.txs_hash.len());
            for tx in txs.iter() {
                _txs.push(tx.clone_to_verifiable(py)?)
            }
            _txs
        };

        // note: push txs to unconfirmed before
        // warning: error means tables is broken, do not allow this error
        chain
            .push_new_block(block, &txs)
            .map_err(|_err| ValueError::py_err(format!("low-level block push failed: {}", _err)))
    }

    fn push_unconfirmed(&self, py: Python, tx: PyRef<PyTx>) -> PyResult<()> {
        let mut chain = self.lock();
        if chain.tables.is_closed {
            return Err(ValueError::py_err("already closed!"));
        }
        let tx = tx.clone_to_verifiable(py)?;
        if tx.body.is_coinbase() {
            return Err(ValueError::py_err("try to push unconfirmed but coinbase tx"));
        }
        chain
            .push_unconfirmed(&tx)
            .map_err(|_err| ValueError::py_err(format!("push unconfirmed failed: {}", _err)))
    }

    fn get_block(&self, hash: &PyBytes) -> PyResult<Option<PyBlock>> {
        let chain = self.lock();
        let hash = hash.as_bytes();
        if hash.len() != 32 {
            return Err(TypeError::py_err("hash is 32 bytes"));
        }
        match chain
            .get_block(&U256::from(hash))
            .map_err(|_err| ValueError::py_err(_err))?
        {
            Some(block) => Ok(Some(PyBlock::from_block(&self.chain, block)?)),
            None => Ok(None),
        }
    }

    fn get_tx(&self, py: Python, hash: &PyBytes) -> PyResult<Option<PyTx>> {
        let chain = self.lock();
        let hash = hash.as_bytes();
        if hash.len() != 32 {
            return Err(TypeError::py_err("hash is 32 bytes"));
        }
        match chain
            .get_tx(&U256::from(hash))
            .map_err(|_err| ValueError::py_err(_err))?
        {
            Some(tx) => Ok(Some(PyTx::from_recoded(py, tx)?)),
            None => Ok(None),
        }
    }

    fn get_account_balance(&self, account_id: u32, confirm: u32) -> PyResult<PyAccount> {
        let (confirmed, unconfirmed) = self
            .lock()
            .get_account_balance(account_id, confirm)
            .map_err(|_err| ValueError::py_err(format!("failed get account balance: {}", _err)))?;
        {
            let gil = Python::acquire_gil();
            let py = gil.python();
            let confirmed = PyCell::new(py, PyBalance {
                iter_index: None,
                balance: confirmed,
            })?;
            let unconfirmed = PyCell::new(py, PyBalance {
                iter_index: None,
                balance: unconfirmed,
            })?;
            Ok(PyAccount {
                account_id,
                confirmed: confirmed.into(),
                unconfirmed: unconfirmed.into(),
            })
        }
    }

    fn get_account_addr_path(&self, addr: PyRef<PyAddress>) -> Option<(u32, bool, u32)> {
        // find address derive path `m/44'/CoinType'/account'/is_inner/index`
        self.lock().account.get_path_from_addr(&addr.addr)
    }

    fn calc_unspent_by_amount(&self, balances: PyRef<PyBalance>) -> PyResult<Vec<PyUnspent>> {
        let chain = self.lock();
        let mut iter = chain.get_account_unspent_iter();
        let require = &balances.balance;

        // calculate best unspent list
        let mut unspent: Vec<(TxInput, TxOutput)> = Vec::with_capacity(256);
        let mut unspent_sum = Balances(Vec::with_capacity(require.0.len()));
        let mut backup: Vec<(TxInput, TxOutput)> = Vec::with_capacity(2000);
        let mut limit_percent = 0.9;

        loop {
            // check have enough unspent
            match require.partial_cmp(&unspent_sum) {
                Some(Ordering::Less) => break, // require < unspent_sum
                _ => (),                       // continue if require >= unspent_sum or None
            }

            // limit_percent is too low
            if limit_percent < 0.001 {
                return Err(ValueError::py_err(format!(
                    "limit_percent is too low, looks dust unspent only exists: {}",
                    limit_percent
                )));
            }

            // not have enough if not break
            loop {
                match iter.next() {
                    Some((input, output)) => {
                        // get 1 from iter and push unspent or backup
                        match require.get_amount_by(output.1) {
                            Some(amount) => {
                                assert!(0 < amount);
                                let limit = (amount as f64 * limit_percent) as u64;
                                if limit < output.2 {
                                    unspent_sum.add(output.1, output.2);
                                    unspent.push((input, output));
                                    break; // check enough unspent list
                                } else {
                                    // continue getting unspent
                                    backup.push((input, output));
                                }
                            },
                            None => continue, //skip unrelated unspent
                        }
                    },

                    // run out of iter just get from backup
                    None => {
                        // get 1 unspent from backup and push to unspent
                        let position = backup.iter().position(|(_input, output)| {
                            let unspent_amount = unspent_sum.get_amount_by(output.1).unwrap_or(0);
                            let require_amount = require.get_amount_by(output.1);
                            if require_amount.is_some() {
                                let require = require_amount.unwrap() as u64;
                                let limit = (require as f64 * limit_percent) as u64;
                                let amount = unspent_amount as u64;
                                // check already enough unspent or too few new input
                                if require < amount {
                                    false
                                } else {
                                    limit < output.2
                                }
                            } else {
                                // note: require has backup's coinId (unreachable)
                                false
                            }
                        });
                        // find position and insert new unspent
                        match position {
                            Some(index) => {
                                let (input, output) = backup.remove(index);
                                unspent_sum.add(output.1, output.2);
                                unspent.push((input, output));
                                break;
                            },
                            None => {
                                // not found good unspent in backup
                                // need low amount limitation
                                limit_percent *= 0.8;
                            },
                        }
                    },
                }
            }
        }
        // unspent length is limit to 255
        if 255 < unspent.len() {
            return Err(ValueError::py_err(format!(
                "unspent limit over 255: {}",
                unspent.len()
            )));
        } else {
            // success
            Ok(unspent
                .into_iter()
                .map(|(input, output)| PyUnspent { input, output })
                .collect())
        }
    }

    fn list_unspent_by_addr(
        &self,
        addrs: Vec<PyRef<PyAddress>>,
        page: usize,
        size: usize,
    ) -> PyResult<Vec<PyUnspent>> {
        // note: page default 0, size default 25
        let chain = self.lock();
        if !chain.tables.table_opts.addr_index {
            return Err(ValueError::py_err(
                "addr_index should be true when you get unspent by addr",
            ));
        }
        let start_pos = page * size;
        let end_pos = (page + 1) * size;
        let addrs = addrs
            .iter()
            .map(|_addr| _addr.addr.clone())
            .collect::<Vec<Address>>();
        let mut unspent = Vec::with_capacity(size);
        // find unspent
        for addr in addrs.iter() {
            for (index, (input, output)) in chain
                .get_unspent_iter_by(addr)
                .map_err(|_err| ValueError::py_err(format!("failed get unspent iter: {}", _err)))?
                .enumerate()
            {
                if index < start_pos {
                    continue;
                } else if index < end_pos {
                    // start_pos <= index < end_pos
                    unspent.push(PyUnspent { input, output });
                } else {
                    break;
                }
            }
        }
        // success
        Ok(unspent)
    }

    fn list_account_movement(&self, page: usize, size: usize) -> PyResult<Vec<PyMovement>> {
        let chain = self.lock();
        let start_pos = page * size;
        let end_pos = (page + 1) * size;
        let mut result = Vec::with_capacity(size);
        // find movement
        for (index, (height, position, movement)) in chain
            .get_movement_iter()
            .map_err(|_err| ValueError::py_err(format!("fai;ed get account movement: {}", _err)))?
            .enumerate()
        {
            if index < start_pos {
                continue;
            } else if index < end_pos {
                // start_pos <= index < end_pos
                result.push(PyMovement {
                    height,
                    position,
                    movement,
                });
            } else {
                break;
            }
        }
        // success
        Ok(result)
    }

    #[getter]
    fn get_is_closed(&self) -> bool {
        self.lock().tables.is_closed
    }

    fn close(&mut self) -> PyResult<()> {
        let mut chain = self.lock();
        if chain.tables.is_closed {
            Err(ValueError::py_err("already close and maybe database is broken"))
        } else {
            chain.tables.close();
            Ok(())
        }
    }
}

impl PyChain {
    /// shared lock on multi-threading
    pub fn lock(&self) -> MutexGuard<Chain> {
        self.chain
            .lock()
            .expect("chain lock failed by already locked with same thread maybe")
    }

    pub fn clone_chain(&self) -> SharedChain {
        self.chain.clone()
    }
}
