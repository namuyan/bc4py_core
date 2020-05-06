use crate::block::*;
use crate::utils::{sha256double, u256_to_bytes};
use bigint::U256;
use pyo3::basic::CompareOp;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyType};
use pyo3::PyObjectProtocol;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

#[pyclass]
pub struct PyHeader {
    pub header: BlockHeader,
}

#[pyproto]
impl PyObjectProtocol for PyHeader {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self))
    }

    fn __hash__(&self) -> PyResult<isize> {
        let mut hasher = DefaultHasher::new();
        let header = &self.header;
        hasher.write_u32(header.version);
        header.previous_hash.0.iter().for_each(|i| hasher.write_u64(*i));
        header.merkleroot.0.iter().for_each(|i| hasher.write_u64(*i));
        hasher.write_u32(header.time);
        hasher.write_u32(header.bits);
        hasher.write_u32(header.nonce);
        let hash = hasher.finish();
        // note: convert 8bytes u64 to 8bytes or 4bytes isize
        let hash = (hash % usize::MAX as u64) as i64 - (usize::MAX / 2) as i64;
        Ok(hash as isize)
    }

    fn __richcmp__(&self, other: PyRef<'p, Self>, op: CompareOp) -> PyResult<bool> {
        // only check version + identifier
        let myself = self.__hash__()?;
        let other = other.__hash__()?;
        match op {
            CompareOp::Eq => Ok(myself == other), // `__eq__`
            CompareOp::Ne => Ok(myself != other), // `__ne__`
            _ => Err(ValueError::py_err("not implemented")),
        }
    }
}

#[pymethods]
impl PyHeader {
    #[new]
    fn new(
        version: u32,
        previous_hash: &PyBytes,
        merkleroot: &PyBytes,
        time: u32,
        bits: u32,
        nonce: u32,
    ) -> PyResult<Self> {
        let previous_hash = previous_hash.as_bytes();
        let merkleroot = merkleroot.as_bytes();
        if previous_hash.len() != 32 || merkleroot.len() != 32 {
            Err(ValueError::py_err(
                "previous_hash or merkleroot's length isn't 32 bytes",
            ))
        } else {
            Ok(PyHeader {
                header: BlockHeader {
                    version,
                    previous_hash: U256::from(previous_hash),
                    merkleroot: U256::from(merkleroot),
                    time,
                    bits,
                    nonce,
                },
            })
        }
    }

    #[classmethod]
    fn from_binary(_cls: &PyType, binary: &PyBytes) -> PyResult<Self> {
        let binary = binary.as_bytes();
        if binary.len() != 80 {
            Err(ValueError::py_err("block header size is 80 bytes"))
        } else {
            let header = BlockHeader::from_bytes(binary);
            Ok(PyHeader { header })
        }
    }

    fn to_binary(&self, py: Python) -> PyObject {
        PyBytes::new(py, self.header.to_bytes().as_ref()).to_object(py)
    }

    fn hash(&self, py: Python) -> PyObject {
        let hash = sha256double(self.header.to_bytes().as_ref());
        PyBytes::new(py, hash.as_slice()).to_object(py)
    }

    #[getter]
    fn get_version(&self) -> u32 {
        self.header.version
    }

    #[getter]
    fn get_previous_hash(&self, py: Python) -> PyObject {
        let previous_hash = u256_to_bytes(&self.header.previous_hash);
        PyBytes::new(py, previous_hash.as_ref()).to_object(py)
    }

    #[getter]
    fn get_merkleroot(&self, py: Python) -> PyObject {
        let merkleroot = u256_to_bytes(&self.header.merkleroot);
        PyBytes::new(py, merkleroot.as_ref()).to_object(py)
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
}

impl std::fmt::Debug for PyHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = sha256double(self.header.to_bytes().as_ref());
        f.debug_tuple("PyHeader").field(&hex::encode(&hash)).finish()
    }
}

#[pyclass]
pub struct PyBlock {
    pub work_hash: Option<U256>,
    #[pyo3(get, set)]
    pub height: u32,
    pub flag: BlockFlag,
    #[pyo3(get, set)]
    pub bias: f32,
    pub header: Py<PyHeader>, // header
    pub txs_hash: Vec<U256>,  // body
}

#[pyproto]
impl PyObjectProtocol for PyBlock {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self))
    }

    fn __hash__(&self) -> PyResult<isize> {
        // return header's
        let gil = Python::acquire_gil();
        let cell: &PyCell<PyHeader> = self.header.as_ref(gil.python());
        let header_rc: PyRef<PyHeader> = cell.borrow();
        header_rc.__hash__()
    }

    fn __richcmp__(&self, other: PyRef<'p, Self>, op: CompareOp) -> PyResult<bool> {
        // check header's
        let gil = Python::acquire_gil();
        let py = gil.python();
        let cell: &PyCell<PyHeader> = self.header.as_ref(py);
        let header_rc: PyRef<PyHeader> = cell.borrow();
        let cell: &PyCell<PyHeader> = other.header.as_ref(py);
        let other_rc: PyRef<PyHeader> = cell.borrow();
        header_rc.__richcmp__(other_rc, op)
    }
}

#[pymethods]
impl PyBlock {
    #[new]
    fn new(height: u32, flag: u8, bias: f32, header: PyRef<PyHeader>, txs_hash: &PyAny) -> PyResult<Self> {
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let header = header.into();
        let txs_hash: Vec<Vec<u8>> = txs_hash.extract()?;
        let txs_check = txs_hash.iter().all(|hash| hash.len() == 32);
        if !txs_check {
            Err(ValueError::py_err("some txs' hash are not 32 bytes"))
        } else {
            Ok(PyBlock {
                work_hash: None, // insert after
                height,
                flag,
                bias,
                header,
                txs_hash: txs_hash
                    .into_iter()
                    .map(|hash| U256::from(hash.as_slice()))
                    .collect(),
            })
        }
    }

    #[getter]
    fn get_work_hash(&self, py: Python) -> Option<PyObject> {
        match self.work_hash.as_ref() {
            Some(hash) => Some(PyBytes::new(py, &u256_to_bytes(&hash)).to_object(py)),
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

    #[getter]
    fn get_header(&self, py: Python) -> PyObject {
        self.header.to_object(py)
    }

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

    fn update_merkleroot(&self, py: Python) -> PyResult<()> {
        let hashs: _ = self
            .txs_hash
            .iter()
            .map(|_hash| sha256double(u256_to_bytes(_hash).as_ref()))
            .collect::<Vec<Vec<u8>>>();

        // calc merkleroot
        let hash = utils::calc_merkleroot_hash(hashs)
            .map_err(|_err| ValueError::py_err(format!("calc merkleroot hash is failed: {}", _err)))?;

        // success
        let cell: &PyCell<PyHeader> = self.header.as_ref(py);
        let mut header_rc: PyRefMut<PyHeader> = cell.borrow_mut();
        header_rc.header.merkleroot = U256::from(hash.as_slice());
        Ok(())
    }
}

impl std::fmt::Debug for PyBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let gil = Python::acquire_gil();
        let cell: &PyCell<PyHeader> = self.header.as_ref(gil.python());
        let header_rc: PyRef<PyHeader> = cell.borrow();
        let hash = sha256double(header_rc.header.to_bytes().as_ref());
        f.debug_tuple("PyBlock")
            .field(&self.height)
            .field(&self.flag)
            .field(&hex::encode(&hash))
            .finish()
    }
}

impl PyBlock {
    pub fn from_block(block: Block) -> PyResult<Self> {
        // moved
        let gil = Python::acquire_gil();
        let py = gil.python();
        let header = PyCell::new(py, PyHeader { header: block.header })?;
        Ok(PyBlock {
            work_hash: Some(block.work_hash),
            height: block.height,
            flag: block.flag,
            bias: block.bias,
            header: header.into(),
            txs_hash: block.txs_hash,
        })
    }

    pub fn clone_to_block(&self) -> Result<Block, String> {
        // clone
        if self.work_hash.is_none() {
            return Err("cannot clone to block because work_hash is None".to_owned());
        }
        let gil = Python::acquire_gil();
        let py = gil.python();
        let cell: &PyCell<PyHeader> = self.header.as_ref(py);
        let header_rc: PyRef<PyHeader> = cell.borrow();
        Ok(Block {
            work_hash: self.work_hash.unwrap(),
            height: self.height,
            flag: self.flag.clone(),
            bias: self.bias,
            header: header_rc.header.clone(),
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
