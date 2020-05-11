use crate::block::*;
use crate::python::pychain::{PyChain, SharedChain};
use crate::python::pytx::PyTx;
use crate::utils::*;
use bigint::U256;
use pyo3::basic::CompareOp;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyType};
use pyo3::PyObjectProtocol;
use std::fmt;

#[pyclass]
pub struct PyBlock {
    chain: SharedChain,

    // meta
    pub work_hash: Option<U256>,
    #[pyo3(get)]
    pub height: u32,
    pub flag: BlockFlag,
    #[pyo3(get)]
    pub bias: f32,

    // header (not static)
    pub header: BlockHeader,

    // body
    pub txs_hash: Vec<U256>,
}

#[pyproto]
impl PyObjectProtocol for PyBlock {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self))
    }

    fn __richcmp__(&self, other: PyRef<'p, Self>, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.header == other.header), // `__eq__`
            CompareOp::Ne => Ok(self.header != other.header), // `__ne__`
            _ => Err(ValueError::py_err("not implemented")),
        }
    }
}

#[pymethods]
impl PyBlock {
    #[new]
    fn new(
        chain: PyRef<PyChain>,
        height: u32,
        flag: u8,
        bias: f32,
        version: u32,
        previous_hash: &PyBytes,
        merkleroot: &PyBytes,
        time: u32,
        bits: u32,
        nonce: u32,
        txs_hash: &PyAny,
    ) -> PyResult<Self> {
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let previous_hash = previous_hash.as_bytes();
        let merkleroot = merkleroot.as_bytes();
        let txs_hash: Vec<Vec<u8>> = txs_hash.extract()?;
        let txs_check = txs_hash.iter().all(|_hash| _hash.len() == 32);
        // check
        if previous_hash.len() == 32 && merkleroot.len() == 32 && txs_check {
            let header = BlockHeader {
                version,
                previous_hash: U256::from(previous_hash),
                merkleroot: U256::from(merkleroot),
                time,
                bits,
                nonce,
            };
            Ok(PyBlock {
                chain: chain.clone_chain(),
                work_hash: None,
                height,
                flag,
                bias,
                header,
                txs_hash: txs_hash
                    .into_iter()
                    .map(|hash| U256::from(hash.as_slice()))
                    .collect(),
            })
        } else {
            Err(ValueError::py_err(
                "previous_hash, merkleroot and txs_hash is 32bytes hash",
            ))
        }
    }

    fn hash(&self, py: Python) -> PyObject {
        let hash = sha256double(&self.header.to_bytes());
        PyBytes::new(py, hash.as_ref()).to_object(py)
    }

    #[classmethod]
    fn from_binary(
        _cls: &PyType,
        chain: PyRef<PyChain>,
        height: u32,
        flag: u8,
        bias: f32,
        binary: &PyBytes,
        txs_hash: &PyAny,
    ) -> PyResult<Self> {
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let binary = binary.as_bytes();
        let txs_hash: Vec<Vec<u8>> = txs_hash.extract()?;
        let txs_check = txs_hash.iter().all(|_hash| _hash.len() == 32);
        // check
        if binary.len() == 80 && txs_check {
            let header = BlockHeader::from_bytes(binary);
            Ok(PyBlock {
                chain: chain.clone_chain(),
                work_hash: None,
                height,
                flag,
                bias,
                header,
                txs_hash: txs_hash
                    .into_iter()
                    .map(|hash| U256::from(hash.as_slice()))
                    .collect(),
            })
        } else {
            Err(ValueError::py_err(
                "binary is 80 bytes & txs_hash is 32bytes hash list",
            ))
        }
    }

    #[getter]
    fn get_work_hash(&self, py: Python) -> Option<PyObject> {
        match self.work_hash.as_ref() {
            Some(hash) => {
                let hash = u256_to_bytes(&hash);
                Some(PyBytes::new(py, hash.as_ref()).to_object(py))
            },
            None => None,
        }
    }

    #[setter]
    fn set_work_hash(&mut self, hash: &PyBytes) -> PyResult<()> {
        let hash = hash.as_bytes();
        if hash.len() == 32 {
            self.work_hash = Some(U256::from(hash));
            Ok(())
        } else {
            Err(ValueError::py_err("work_hash isn't 32 bytes"))
        }
    }

    #[getter]
    fn get_flag(&self) -> u8 {
        self.flag.to_int()
    }

    // about block header
    #[getter]
    fn get_version(&self) -> u32 {
        self.header.version
    }

    #[getter]
    fn get_previous_hash(&self, py: Python) -> PyObject {
        let hash = u256_to_bytes(&self.header.previous_hash);
        PyBytes::new(py, hash.as_ref()).to_object(py)
    }

    #[getter]
    fn get_merkleroot(&self, py: Python) -> PyObject {
        let hash = u256_to_bytes(&self.header.merkleroot);
        PyBytes::new(py, hash.as_ref()).to_object(py)
    }

    #[getter]
    fn get_time(&self) -> u32 {
        self.header.time
    }

    #[getter]
    fn get_bits(&self) -> u32 {
        self.header.bits
    }

    #[getter]
    fn get_nonce(&self) -> u32 {
        self.header.nonce
    }

    // about block body
    #[getter]
    fn get_txs_hash(&self, py: Python) -> PyObject {
        // return List[bytes] for edit
        let txs: _ = self
            .txs_hash
            .iter()
            .map(|_hash| PyBytes::new(py, u256_to_bytes(_hash).as_ref()).to_object(py))
            .collect::<Vec<PyObject>>();
        PyList::new(py, &txs).to_object(py)
    }

    #[setter]
    fn set_txs_hash(&mut self, hashs: &PyAny) -> PyResult<()> {
        let hashs: Vec<Vec<u8>> = hashs.extract()?;
        let mut txs_hash = Vec::with_capacity(hashs.len());
        for hash in hashs.iter() {
            if hash.len() == 32 {
                txs_hash.push(U256::from(hash.as_slice()));
            } else {
                return Err(ValueError::py_err("hash is 32 bytes"));
            }
        }
        self.txs_hash = txs_hash;
        Ok(())
    }

    fn two_difficulties(&self) -> PyResult<(f64, f64)> {
        if self.work_hash.is_none() {
            return Err(ValueError::py_err("cannot get diff because work_hash is none"));
        }
        let work_hash = self.work_hash.as_ref().unwrap();
        match bits_to_target(self.header.bits) {
            Ok(target) => {
                let required = target_to_diff(target);
                let work = target_to_diff(*work_hash);
                Ok((required, work))
            },
            Err(_err) => Err(ValueError::py_err(format!("cannot get diff: {}", _err))),
        }
    }

    fn update_merkleroot(&mut self) -> PyResult<()> {
        let hashs: _ = self
            .txs_hash
            .iter()
            .map(|_hash| sha256double(u256_to_bytes(_hash).as_ref()))
            .collect::<Vec<Vec<u8>>>();

        // calc merkleroot
        let hash = utils::calc_merkleroot_hash(hashs)
            .map_err(|_err| ValueError::py_err(format!("calc merkleroot hash is failed: {}", _err)))?;

        // success
        self.header.merkleroot = U256::from(hash.as_slice());
        Ok(())
    }

    fn check_proof_of_work(&self) -> PyResult<bool> {
        match bits_to_target(self.header.bits) {
            Ok(target) => match self.work_hash.as_ref() {
                Some(work) => Ok(work < &target),
                None => Err(ValueError::py_err("cannot check work because work_hash is none")),
            },
            Err(_err) => Err(ValueError::py_err(format!("cannot check work: {}", _err))),
        }
    }

    fn is_orphan(&self) -> bool {
        // note: get chain lock
        let chain = self.chain.lock().unwrap();
        let hash = self.header.hash();

        // from confirmed
        if chain.best_chain.contains(&hash) {
            return false;
        }

        // from tables
        if chain.tables.read_block(&hash).unwrap().is_some() {
            return false;
        }

        // not found in tables and confirmed
        true
    }

    fn update_time(&mut self, time: u32) {
        self.header.time = time;
    }

    fn update_nonce(&mut self, nonce: u32) {
        self.header.nonce = nonce;
    }

    fn increment_nonce(&mut self) {
        // cycle nonce
        let (new_nonce, _flag) = self.header.nonce.overflowing_add(1);
        self.header.nonce = new_nonce;
    }

    fn getinfo(&self, py: Python, tx_info: Option<bool>) -> PyResult<PyObject> {
        // for debug method just looked by humans
        let dict = PyDict::new(py);

        let hash = self.header.hash();
        dict.set_item("hash", u256_to_hex(&hash))?;
        if self.work_hash.is_some() {
            dict.set_item("work_hash", u256_to_hex(self.work_hash.as_ref().unwrap()))?;
        } else {
            dict.set_item("work_hash", py.None())?;
        }
        dict.set_item("previous_hash", u256_to_hex(&self.header.previous_hash))?;
        // dict.set_item("next_hash", )?; REMOVED
        dict.set_item("is_orphan", self.is_orphan())?; // note: get chain lock
                                                       // dict.set_item("recode_flag", )?; REMOVED
        dict.set_item("height", self.height)?;
        let (difficulty, _work) = self.two_difficulties()?;
        dict.set_item("difficulty", difficulty)?;
        dict.set_item("fixed_difficulty", difficulty / (self.bias as f64))?;
        dict.set_item("score", difficulty / (self.bias as f64))?;
        dict.set_item("flag", format!("{:?}", self.flag))?;
        dict.set_item("merkleroot", u256_to_hex(&self.header.merkleroot))?;
        dict.set_item("time", self.header.time)?;
        dict.set_item("bits", self.header.bits)?;
        dict.set_item("bias", self.header.bits)?;
        dict.set_item("nonce", self.header.nonce)?;
        if tx_info.is_some() && tx_info.unwrap() {
            // with tx info list
            let chain = self.chain.lock().unwrap();
            match chain.tables.read_full_block(&hash).unwrap() {
                Some((_block, txs)) => {
                    let mut tx_info = Vec::with_capacity(txs.len());
                    for tx in txs.into_iter() {
                        tx_info.push(PyTx::from_recoded(py, tx)?.getinfo(py)?);
                    }
                    dict.set_item("txs", tx_info)?;
                },
                None => dict.set_item("txs", py.None())?,
            }
        } else {
            // with tx hash list
            let txs = self
                .txs_hash
                .iter()
                .map(|_hash| u256_to_hex(_hash))
                .collect::<Vec<String>>();
            dict.set_item("txs", txs)?;
        }
        // dict.set_item("create_time", )?;  REMOVED
        // dict.set_item("size", )?;  REMOVED
        dict.set_item("hex", hex::encode(self.header.to_bytes().as_ref()))?;
        Ok(dict.to_object(py))
    }
}

impl fmt::Debug for PyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = hex::encode(&sha256double(&self.header.to_bytes()));
        f.debug_tuple("PyBlock")
            .field(&self.height)
            .field(&self.flag)
            .field(&hash)
            .finish()
    }
}

impl PyBlock {
    pub fn from_block(chain: &SharedChain, block: Block) -> PyResult<Self> {
        // moved
        Ok(PyBlock {
            work_hash: Some(block.work_hash),
            height: block.height,
            flag: block.flag,
            bias: block.bias,
            chain: chain.clone(),
            header: block.header,
            txs_hash: block.txs_hash,
        })
    }

    pub fn clone_to_block(&self) -> Result<Block, String> {
        // clone
        if self.work_hash.is_none() {
            return Err("cannot clone to block because work_hash is None".to_owned());
        }
        Ok(Block {
            work_hash: self.work_hash.unwrap(),
            height: self.height,
            flag: self.flag.clone(),
            bias: self.bias,
            header: self.header.clone(),
            txs_hash: self.txs_hash.clone(),
        })
    }
}

mod utils {
    use crate::utils::sha256double;

    pub fn calc_merkleroot_hash(mut hashs: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
        let mut buf = Vec::with_capacity(32 * hashs.len());
        while 1 < hashs.len() {
            if hashs.len() % 2 == 0 {
                let cycle = hashs.len() / 2;
                let mut new_hashs = Vec::with_capacity(cycle);
                for i in 0..cycle {
                    buf.clear();
                    buf.extend_from_slice(&hashs[i * 2]);
                    buf.extend_from_slice(&hashs[i * 2 + 1]);
                    new_hashs.push(sha256double(buf.as_slice()));
                }
                hashs = new_hashs;
            } else {
                let last = match hashs.last() {
                    Some(hash) => hash.clone(),
                    None => return Err("hashs length may be zero".to_owned()),
                };
                hashs.push(last);
            }
        }

        // check
        match hashs.pop() {
            Some(hash) => Ok(hash),
            None => Err("hashs length may be zero".to_owned()),
        }
    }

    #[test]
    fn test_merkleroot_hash() {
        // https://btc.com/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506
        // Bitcoin's block & tx hash is looks reversed because they want work hash starts with zeros
        let mut hashs = vec![
            hex::decode("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87").unwrap(),
            hex::decode("fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4").unwrap(),
            hex::decode("6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4").unwrap(),
            hex::decode("e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d").unwrap(),
        ];
        hashs.iter_mut().for_each(|_hash| _hash.reverse());
        let mut merkleroot =
            hex::decode("f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766").unwrap();
        merkleroot.reverse();
        assert_eq!(calc_merkleroot_hash(hashs), Ok(merkleroot));
    }
}
