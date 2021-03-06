use crate::block::*;
use crate::python::pychain::PyChain;
use crate::python::pytx::PyTx;
use crate::tx::{BlockTxs, TxBody, TxOutput, TxVerifiable};
use crate::utils::*;
use bigint::U256;
use pyo3::basic::CompareOp;
use pyo3::exceptions::{AssertionError, IndexError, ValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyType};
use pyo3::{PyIterProtocol, PyObjectProtocol};
use std::fmt;

enum PyTxsEnum {
    Hashs(Vec<U256>),       // only tx hash
    Objects(Vec<Py<PyTx>>), // full tx object
}

impl fmt::Debug for PyTxsEnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hashs: Vec<U256> = match &self {
            PyTxsEnum::Hashs(vec) => {
                f.write_str("Hashs")?;
                vec.clone()
            },
            PyTxsEnum::Objects(vec) => {
                f.write_str("Objects")?;
                let gil = Python::acquire_gil();
                let py = gil.python();
                vec.iter()
                    .map(|tx| {
                        let cell: &PyCell<PyTx> = tx.as_ref(py);
                        let tx_rc: PyRef<PyTx> = cell.borrow();
                        U256::from(tx_rc.clone_to_body(py).hash().as_slice())
                    })
                    .collect()
            },
        };
        f.write_str("[")?;
        for hash in hashs.iter() {
            f.write_str(&u256_to_hex(hash))?;
            f.write_str(", ")?;
        }
        f.write_str("]")?;
        Ok(())
    }
}

#[pyclass]
#[derive(Debug)]
pub struct PyTxs {
    iter_index: Option<usize>,
    txs: PyTxsEnum,
}

#[pyproto]
impl PyIterProtocol for PyTxs {
    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<PyObject> {
        let py = unsafe { Python::assume_gil_acquired() };
        slf.iter_index.replace(0);
        Ok(slf.into_py(py))
    }

    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        let py = unsafe { Python::assume_gil_acquired() };
        let index = slf.iter_index.unwrap();
        *slf.iter_index.as_mut().unwrap() += 1; // pre increment
        let result = slf.get(py, index);
        if result.is_err() {
            // error means index is out of bounds
            slf.iter_index.take();
            Ok(None)
        } else {
            Ok(Some(result.unwrap()))
        }
    }
}

#[pymethods]
impl PyTxs {
    #[getter(HASH)]
    fn get_hash(&self) -> &'static str {
        "hash"
    }

    #[getter(OBJECT)]
    fn get_object(&self) -> &'static str {
        "object"
    }

    #[new]
    fn new(typename: &str, txs: &PyAny) -> PyResult<Self> {
        match typename {
            "hash" => {
                let obj: Vec<Vec<u8>> = txs.extract()?;
                let mut hashs = Vec::with_capacity(obj.len());
                for hash in obj.into_iter() {
                    if hash.len() == 32 {
                        hashs.push(U256::from(hash.as_slice()));
                    } else {
                        return Err(ValueError::py_err(format!(
                            "PyTxs hash is 32 bytes but {}bytes",
                            hash.len()
                        )));
                    }
                }
                Ok(PyTxs {
                    iter_index: None,
                    txs: PyTxsEnum::Hashs(hashs),
                })
            },
            "object" => {
                let cell: Vec<&PyCell<PyTx>> = txs.extract()?;
                let objs = cell.iter().map(|tx| (*tx).into()).collect();
                Ok(PyTxs {
                    iter_index: None,
                    txs: PyTxsEnum::Objects(objs),
                })
            },
            name => Err(ValueError::py_err(format!("not found PyTxsType name: {}", name))),
        }
    }

    fn len(&self) -> usize {
        match &self.txs {
            PyTxsEnum::Hashs(vec) => vec.len(),
            PyTxsEnum::Objects(vec) => vec.len(),
        }
    }

    fn typename(&self) -> &'static str {
        match &self.txs {
            PyTxsEnum::Hashs(_) => "hash",
            PyTxsEnum::Objects(_) => "object",
        }
    }

    fn get(&self, py: Python, index: usize) -> PyResult<PyObject> {
        match &self.txs {
            PyTxsEnum::Hashs(vec) => match vec.get(index) {
                Some(hash) => Ok(PyBytes::new(py, u256_to_bytes(hash).as_ref()).to_object(py)),
                None => Err(IndexError::py_err(format!(
                    "try to get txhash but out of bounds index={} len={}",
                    index,
                    vec.len()
                ))),
            },
            PyTxsEnum::Objects(vec) => match vec.get(index) {
                Some(obj) => Ok(obj.to_object(py)),
                None => Err(IndexError::py_err(format!(
                    "try to get PyTx but out of bounds index={} len={}",
                    index,
                    vec.len()
                ))),
            },
        }
    }

    fn index(&self, py: Python, obj: &PyAny) -> PyResult<usize> {
        // Raises ValueError if the value is not present.
        let hash = self.obj_to_u256(py, obj)?;
        let result = match &self.txs {
            PyTxsEnum::Hashs(vec) => vec.iter().position(|txhash| txhash == &hash),
            PyTxsEnum::Objects(_) => {
                let vec = self.hash_list(py);
                vec.iter().position(|txhash| txhash == &hash)
            },
        };
        result.ok_or(ValueError::py_err(format!("not found obj {:?}", obj)))
    }

    fn contain(&self, py: Python, obj: &PyAny) -> PyResult<bool> {
        let hash = self.obj_to_u256(py, obj)?;
        match &self.txs {
            PyTxsEnum::Hashs(vec) => Ok(vec.contains(&hash)),
            PyTxsEnum::Objects(_) => Ok(self.hash_list(py).contains(&hash)),
        }
    }

    fn push(&mut self, obj: &PyAny) -> PyResult<()> {
        match &mut self.txs {
            PyTxsEnum::Hashs(vec) => {
                let hash: Vec<u8> = obj.extract()?;
                if hash.len() != 32 {
                    Err(ValueError::py_err(format!(
                        "hash length is 32 bytes but {}",
                        hash.len()
                    )))
                } else {
                    vec.push(U256::from(hash.as_slice()));
                    Ok(())
                }
            },
            PyTxsEnum::Objects(vec) => {
                let cell: &PyCell<PyTx> = obj.extract()?;
                vec.push(cell.into());
                Ok(())
            },
        }
    }

    fn insert(&mut self, index: usize, obj: &PyAny) -> PyResult<()> {
        match &mut self.txs {
            PyTxsEnum::Hashs(vec) => {
                let hash: Vec<u8> = obj.extract()?;
                if hash.len() != 32 {
                    Err(ValueError::py_err(format!(
                        "hash length is 32 bytes but {}",
                        hash.len()
                    )))
                } else if vec.len() <= index {
                    Err(IndexError::py_err(format!(
                        "index is out of bounds index={} len={}",
                        index,
                        vec.len()
                    )))
                } else {
                    vec.push(U256::from(hash.as_slice()));
                    Ok(())
                }
            },
            PyTxsEnum::Objects(vec) => {
                if vec.len() <= index {
                    Err(IndexError::py_err(format!(
                        "index is out of bounds index={} len={}",
                        index,
                        vec.len()
                    )))
                } else {
                    let cell: &PyCell<PyTx> = obj.extract()?;
                    vec.insert(index, cell.into());
                    Ok(())
                }
            },
        }
    }

    fn extend(&mut self, py: Python, txs: PyRef<PyTxs>) -> PyResult<()> {
        match (&mut self.txs, &txs.txs) {
            (PyTxsEnum::Objects(origin), PyTxsEnum::Objects(other)) => {
                origin.reserve(other.len());
                other.iter().for_each(|tx| origin.push(tx.clone_ref(py)));
                Ok(())
            },
            (PyTxsEnum::Hashs(origin), PyTxsEnum::Hashs(other)) => {
                origin.extend_from_slice(other.as_slice());
                Ok(())
            },
            _ => Err(ValueError::py_err(format!(
                "type mismatch, origin is {} but other is {}",
                self.typename(),
                txs.typename()
            ))),
        }
    }

    fn remove(&mut self, index: usize) -> PyResult<()> {
        let result = match &mut self.txs {
            PyTxsEnum::Hashs(vec) => {
                if index < vec.len() {
                    vec.remove(index);
                    Ok(())
                } else {
                    Err(vec.len())
                }
            },
            PyTxsEnum::Objects(vec) => {
                if index < vec.len() {
                    vec.remove(index);
                    Ok(())
                } else {
                    Err(vec.len())
                }
            },
        };
        result.map_err(|length| {
            IndexError::py_err(format!("index is out of bounds index={} len={}", index, length))
        })
    }

    fn pop(&mut self, py: Python) -> PyResult<PyObject> {
        // remove last item or raise IndexError
        let result = match &mut self.txs {
            PyTxsEnum::Hashs(vec) => vec.pop().map(|hash| u256_to_bytes(&hash).to_object(py)),
            PyTxsEnum::Objects(vec) => vec.pop().map(|obj| obj.to_object(py)),
        };
        match result {
            Some(obj) => Ok(obj),
            None => Err(IndexError::py_err(format!(
                "pop from empty {} list",
                self.typename()
            ))),
        }
    }

    fn get_hash_list(&self, py: Python) -> Vec<PyObject> {
        self.hash_list(py)
            .iter()
            .map(|hash| PyBytes::new(py, u256_to_bytes(hash).as_ref()).to_object(py))
            .collect()
    }

    fn convert_object_type(&mut self, py: Python, chain: PyRef<PyChain>) -> PyResult<()> {
        // hash type to object type
        let chain = chain.lock();
        let new = match &self.txs {
            PyTxsEnum::Hashs(vec) => {
                // note: hash must be unconfirmed only ( cannot read from txcache)
                let mut new = Vec::with_capacity(vec.len());
                for hash in vec.iter() {
                    match chain.tables.read_txcache(hash).unwrap() {
                        Some(tx) => {
                            new.push(Py::new(py, PyTx::from_verifiable(py, tx)?)?);
                        },
                        None => {
                            return Err(ValueError::py_err(format!(
                                "cannot convert hash to object because not found in txcache hash={}",
                                u256_to_hex(hash)
                            )))
                        },
                    }
                }
                // success
                new
            },
            // skip: already object type
            PyTxsEnum::Objects(_) => return Ok(()),
        };
        // over write
        self.txs = PyTxsEnum::Objects(new);
        Ok(())
    }
}

impl PyTxs {
    fn obj_to_u256(&self, py: Python, obj: &PyAny) -> PyResult<U256> {
        // both bytes or PyTx to U256
        match obj.extract::<Vec<u8>>() {
            Ok(hash) => {
                if hash.len() == 32 {
                    Ok(U256::from(hash.as_slice()))
                } else {
                    Err(ValueError::py_err("hash is 32 bytes"))
                }
            },
            Err(_) => {
                // may not bytes
                let tx: &PyCell<PyTx> = obj.extract()?;
                Ok(U256::from(tx.borrow().clone_to_body(py).hash().as_slice()))
            },
        }
    }

    fn hash_list(&self, py: Python) -> Vec<U256> {
        match &self.txs {
            PyTxsEnum::Hashs(vec) => vec.clone(),
            PyTxsEnum::Objects(vec) => vec
                .iter()
                .map(|tx| {
                    let cell: &PyCell<PyTx> = tx.as_ref(py);
                    let tx_rc: PyRef<PyTx> = cell.borrow();
                    U256::from(tx_rc.clone_to_body(py).hash().as_slice())
                })
                .collect(),
        }
    }

    pub fn from_hash_vec(hashs: Vec<U256>) -> Self {
        PyTxs {
            iter_index: None,
            txs: PyTxsEnum::Hashs(hashs),
        }
    }
}

#[pyproto]
impl PyObjectProtocol for PyTxs {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self.txs))
    }
}

#[pyclass]
pub struct PyBlock {
    // meta
    pub work_hash: Option<U256>,
    #[pyo3(get)]
    pub height: u32,
    pub flag: BlockFlag,
    #[pyo3(get, set)]
    pub bias: f32,

    // header (not static)
    pub header: BlockHeader,

    // body
    pub txs: Py<PyTxs>,

    // object creation time
    #[pyo3(get, set)]
    pub create_time: f64,
}

#[pyproto]
impl PyObjectProtocol for PyBlock {
    fn __repr__(&self) -> PyResult<String> {
        let hash = sha256double(&self.header.to_bytes());
        let hash = hex::encode(hash.as_slice());
        Ok(format!("<PyBlock {:?} {} {}>", self.flag, self.height, hash))
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
        py: Python,
        height: u32,
        flag: u8,
        bias: f32,
        version: u32,
        previous_hash: &PyBytes,
        time: u32,
        bits: u32,
        nonce: u32,
        txs: PyRef<PyTxs>,
    ) -> PyResult<Self> {
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let previous_hash = previous_hash.as_bytes();
        // auto calc merkleroot hash
        let merkleroot = if 0 < txs.len() {
            let hashs = txs.hash_list(py);
            calc_merkleroot_hash(hashs)
        } else {
            U256::from(0u32) // dummy hash
        };
        // check
        if previous_hash.len() == 32 {
            let header = BlockHeader {
                version,
                previous_hash: U256::from(previous_hash),
                merkleroot,
                time,
                bits,
                nonce,
            };
            Ok(PyBlock {
                work_hash: None,
                height,
                flag,
                bias,
                header,
                txs: txs.into(),
                create_time: get_current_time(),
            })
        } else {
            Err(ValueError::py_err(
                "previous_hash, merkleroot and txs_hash is 32bytes hash",
            ))
        }
    }

    fn hex(&self) -> String {
        // for debug
        let hash = sha256double(&self.header.to_bytes());
        hex::encode(hash.as_slice())
    }

    fn hash(&self, py: Python) -> PyObject {
        let hash = sha256double(&self.header.to_bytes());
        PyBytes::new(py, hash.as_ref()).to_object(py)
    }

    #[classmethod]
    fn from_bytes(
        _cls: &PyType,
        height: u32,
        flag: u8,
        bias: f32,
        binary: &PyBytes,
        txs: PyRef<PyTxs>,
    ) -> PyResult<Self> {
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let binary = binary.as_bytes();
        // check
        if binary.len() == 80 {
            let header = BlockHeader::from_bytes(binary);
            Ok(PyBlock {
                work_hash: None,
                height,
                flag,
                bias,
                header,
                txs: txs.into(),
                create_time: get_current_time(),
            })
        } else {
            Err(ValueError::py_err(
                "binary is 80 bytes & txs_hash is 32bytes hash list",
            ))
        }
    }

    fn to_bytes(&self, py: Python) -> PyObject {
        // header 80 bytes
        let bytes = self.header.to_bytes();
        PyBytes::new(py, bytes.as_ref()).to_object(py)
    }

    fn get_work_hash(&mut self, py: Python, update: bool) -> PyResult<PyObject> {
        // generate workHash if required
        if self.work_hash.is_none() || update {
            let work = match &self.flag {
                BlockFlag::CoinPos | BlockFlag::CapPos | BlockFlag::FlkPos => {
                    let (inputs_cache, coinbase) = self.get_coinbase_inputs_cache(py)?;
                    let input_cache = inputs_cache.get(0);
                    // return Err if input's length is zero
                    get_work_hash(&self.flag, &self.header, Some(&coinbase), input_cache)
                },
                _others => get_work_hash(&self.flag, &self.header, None, None),
            };
            match work {
                Ok(hash) => self.work_hash.replace(hash),
                Err(err) => return Err(AssertionError::py_err(err)),
            };
        }

        // return generated workHash
        let hash = self.work_hash.as_ref().unwrap();
        let hash = u256_to_bytes(&hash);
        Ok(PyBytes::new(py, hash.as_ref()).to_object(py))
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

    #[getter]
    fn get_txs(&self, py: Python) -> PyObject {
        // return List[bytes] for edit
        self.txs.to_object(py)
    }

    #[setter]
    fn set_txs(&mut self, txs: PyRef<PyTxs>) {
        self.txs = txs.into();
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

    fn update_merkleroot(&mut self, py: Python) -> PyResult<()> {
        let txs: &PyCell<PyTxs> = self.txs.as_ref(py);
        let hashs = txs.borrow().hash_list(py);

        // not allow empty hashs
        if hashs.len() == 0 {
            return Err(AssertionError::py_err("not allow empty hashs to calc merkleroot"));
        }

        // calc merkleroot
        self.header.merkleroot = calc_merkleroot_hash(hashs);
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

    fn get_size(&self, py: Python) -> PyResult<usize> {
        // return block_header + txs (not include signature)
        let txs: &PyCell<PyTxs> = self.txs.as_ref(py);
        match &txs.borrow().txs {
            PyTxsEnum::Hashs(_) => Err(ValueError::py_err("try to get_size but txs' type is hash")),
            PyTxsEnum::Objects(vec) => {
                let mut size = 0;
                for tx in vec.iter() {
                    let tx: &PyCell<PyTx> = tx.as_ref(py);
                    size += tx.borrow().get_size(py);
                }
                Ok(80 + size)
            },
        }
    }

    fn getinfo(&self, py: Python) -> PyResult<PyObject> {
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
        // dict.set_item("is_orphan", self.is_orphan())?; REMOVED
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
        // txs
        let txs: &PyCell<PyTxs> = self.txs.as_ref(py);
        let txs: PyObject = match &txs.borrow().txs {
            PyTxsEnum::Hashs(vec) => {
                // hash hex list
                vec.iter().map(u256_to_hex).collect::<Vec<String>>().to_object(py)
            },
            PyTxsEnum::Objects(vec) => {
                // tx's info list
                let mut new = Vec::with_capacity(vec.len());
                for tx in vec.iter() {
                    let tx: &PyCell<PyTx> = tx.as_ref(py);
                    new.push(tx.borrow().getinfo(py)?);
                }
                new.to_object(py)
            },
        };
        dict.set_item("txs", txs)?;
        dict.set_item("create_time", self.create_time)?;
        // dict.set_item("size", )?;  REMOVED
        dict.set_item("hex", hex::encode(self.header.to_bytes().as_ref()))?;
        Ok(dict.to_object(py))
    }
}

impl fmt::Debug for PyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let txs = {
            let gil = Python::acquire_gil();
            let py = gil.python();
            let cell: &PyCell<PyTxs> = self.txs.as_ref(py);
            cell.borrow()
        };
        f.debug_map()
            .entry(&"header", &self.header)
            .entry(&"work", &self.work_hash.map(|hash| u256_to_hex(&hash)))
            .entry(&"height", &self.height)
            .entry(&"flag", &self.flag)
            .entry(&"bias", &self.bias)
            .entry(&"txs", &txs.txs)
            .finish()
    }
}

impl PyBlock {
    pub fn from_block(py: Python, block: Block) -> PyResult<Self> {
        // moved
        let txs = PyTxs {
            iter_index: None,
            txs: PyTxsEnum::Hashs(block.txs_hash),
        };
        let txs: _ = PyCell::new(py, txs)?;
        Ok(PyBlock {
            work_hash: Some(block.work_hash),
            height: block.height,
            flag: block.flag,
            bias: block.bias,
            header: block.header,
            txs: txs.into(),
            create_time: get_current_time(),
        })
    }

    pub fn from_full_block(py: Python, block: Block, txs: BlockTxs) -> PyResult<Self> {
        // moved
        let mut vec = Vec::with_capacity(txs.len());
        for tx in txs.into_iter() {
            vec.push(Py::new(py, PyTx::from_recoded(py, tx)?)?);
        }
        let txs = PyTxs {
            iter_index: None,
            txs: PyTxsEnum::Objects(vec),
        };
        let txs: _ = PyCell::new(py, txs)?;
        Ok(PyBlock {
            work_hash: Some(block.work_hash),
            height: block.height,
            flag: block.flag,
            bias: block.bias,
            header: block.header,
            txs: txs.into(),
            create_time: get_current_time(),
        })
    }

    #[allow(dead_code)]
    fn clone_to_block(&self, py: Python) -> PyResult<Block> {
        // clone
        if self.work_hash.is_none() {
            return Err(ValueError::py_err(
                "cannot clone to block because work_hash is None",
            ));
        }
        let txs: &PyCell<PyTxs> = self.txs.as_ref(py);
        Ok(Block {
            work_hash: self.work_hash.unwrap(),
            height: self.height,
            flag: self.flag.clone(),
            bias: self.bias,
            header: self.header.clone(),
            txs_hash: txs.borrow().hash_list(py),
        })
    }

    pub fn clone_to_full_block(&self, py: Python) -> PyResult<(Block, Vec<TxVerifiable>)> {
        // clone
        if self.work_hash.is_none() {
            return Err(ValueError::py_err(
                "cannot clone to full block because work_hash is None",
            ));
        }
        let txs: &PyCell<PyTxs> = self.txs.as_ref(py);
        let txs = txs.borrow();
        let block = Block {
            work_hash: self.work_hash.unwrap(),
            height: self.height,
            flag: self.flag.clone(),
            bias: self.bias,
            header: self.header.clone(),
            txs_hash: txs.hash_list(py),
        };
        match &txs.txs {
            PyTxsEnum::Hashs(_) => Err(ValueError::py_err(
                "cannot clone to full block because txs isn't object",
            )),
            PyTxsEnum::Objects(vec) => {
                let mut txs = Vec::with_capacity(vec.len());
                for tx in vec.iter() {
                    let tx: &PyCell<PyTx> = tx.as_ref(py);
                    let tx = tx.borrow();
                    let tx = tx.clone_to_verifiable(py)?;
                    txs.push(tx);
                }
                Ok((block, txs))
            },
        }
    }

    /// get coinbase info for PoS type verification
    ///
    /// return (inputsCache, coinbase)
    fn get_coinbase_inputs_cache(&self, py: Python) -> PyResult<(Vec<TxOutput>, TxBody)> {
        let cell: &PyCell<PyTxs> = self.txs.as_ref(py);
        match &cell.borrow().txs {
            PyTxsEnum::Hashs(_) => Err(AssertionError::py_err("try to get coinbase but PyTxs is hash")),
            PyTxsEnum::Objects(vec) => match vec.get(0) {
                Some(coinbase) => {
                    let cell: &PyCell<PyTx> = coinbase.as_ref(py);
                    let coinbase = cell.borrow();
                    match &coinbase.inputs_cache {
                        Some(cache) => Ok((cache.clone(), coinbase.clone_to_body(py))),
                        None => Err(AssertionError::py_err(
                            "try to get coinbase but inputs_cache is empty",
                        )),
                    }
                },
                None => Err(AssertionError::py_err("try to get coinbase but tx is empty")),
            },
        }
    }
}
