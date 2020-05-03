use crate::block::*;
use crate::utils::{sha256double, u256_to_bytes};
use bigint::U256;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};

#[pyclass]
pub struct PyHeader {
    #[pyo3(get, set)]
    pub version: u32,
    pub previous_hash: U256,
    pub merkleroot: U256,
    #[pyo3(get, set)]
    pub time: u32,
    #[pyo3(get, set)]
    pub bits: u32,
    #[pyo3(get, set)]
    pub nonce: u32,
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
                version,
                previous_hash: U256::from(previous_hash),
                merkleroot: U256::from(merkleroot),
                time,
                bits,
                nonce,
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
            Ok(PyHeader {
                version: header.version,
                previous_hash: header.previous_hash,
                merkleroot: header.merkleroot,
                time: header.time,
                bits: header.bits,
                nonce: header.nonce,
            })
        }
    }

    fn to_binary(&self, py: Python) -> PyObject {
        let header = BlockHeader {
            version: self.version,
            previous_hash: self.previous_hash,
            merkleroot: self.merkleroot,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        };
        PyBytes::new(py, header.to_bytes().as_ref()).to_object(py)
    }

    #[getter]
    fn get_previous_hash(&self, py: Python) -> PyObject {
        PyBytes::new(py, u256_to_bytes(&self.previous_hash).as_ref()).to_object(py)
    }

    #[setter]
    fn set_previous_hash(&mut self, hash: &PyBytes) -> PyResult<()> {
        let hash = hash.as_bytes();
        if hash.len() == 32 {
            self.previous_hash = U256::from(hash);
            Ok(())
        } else {
            Err(ValueError::py_err("previous_hash is 32 bytes"))
        }
    }

    #[getter]
    fn get_merkleroot(&self, py: Python) -> PyObject {
        PyBytes::new(py, u256_to_bytes(&self.merkleroot).as_ref()).to_object(py)
    }

    #[setter]
    fn set_merkleroot(&mut self, hash: &PyBytes) -> PyResult<()> {
        let hash = hash.as_bytes();
        if hash.len() == 32 {
            self.merkleroot = U256::from(hash);
            Ok(())
        } else {
            Err(ValueError::py_err("merkleroot is 32 bytes"))
        }
    }

    fn hash(&self, py: Python) -> PyObject {
        let header = BlockHeader {
            version: self.version,
            previous_hash: self.previous_hash,
            merkleroot: self.merkleroot,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        };
        let hash = sha256double(header.to_bytes().as_ref());
        PyBytes::new(py, hash.as_slice()).to_object(py)
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
    pub header: Py<PyHeader>,  // header
    pub txs_hash: Box<[U256]>, // body
}

#[pymethods]
impl PyBlock {
    #[new]
    fn new(
        height: u32,
        flag: u8,
        bias: f32,
        header: &PyCell<PyHeader>,
        txs_hash: &PyAny,
    ) -> PyResult<Self> {
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let header: Py<PyHeader> = header.borrow().into();
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
}

impl PyBlock {
    pub fn from_block(block: Block) -> PyResult<Self> {
        // moved
        let gil = Python::acquire_gil();
        let py = gil.python();
        let header = PyCell::new(py, PyHeader {
            version: block.header.version,
            previous_hash: block.header.previous_hash,
            merkleroot: block.header.merkleroot,
            time: block.header.time,
            bits: block.header.bits,
            nonce: block.header.nonce,
        })?;
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
            header: BlockHeader {
                version: header_rc.version,
                previous_hash: header_rc.previous_hash,
                merkleroot: header_rc.merkleroot,
                time: header_rc.time,
                bits: header_rc.bits,
                nonce: header_rc.nonce,
            },
            txs_hash: self.txs_hash.clone(),
        })
    }
}
