use crate::tx::{params2bech, string2addr};
use crate::utils::write_slice;
use pyo3::basic::CompareOp;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use pyo3::PyObjectProtocol;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::Hasher;

type Address = [u8; 21];

#[pyclass]
pub struct PyAddress {
    pub addr: Address,
}

#[pyproto]
impl PyObjectProtocol for PyAddress {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self))
    }

    fn __hash__(&self) -> PyResult<isize> {
        let mut hasher = DefaultHasher::new();
        hasher.write(self.addr.as_ref());
        let hash = hasher.finish();
        // note: convert 8bytes u64 to 8bytes or 4bytes isize
        let hash = (hash % usize::MAX as u64) as i64 - (usize::MAX / 2) as i64;
        Ok(hash as isize)
    }

    fn __richcmp__(&self, other: PyRef<'p, Self>, op: CompareOp) -> PyResult<bool> {
        // only check version + identifier
        match op {
            CompareOp::Eq => Ok(self.addr == other.addr), // `__eq__`
            CompareOp::Ne => Ok(self.addr != other.addr), // `__ne__`
            _ => Err(ValueError::py_err("not implemented")),
        }
    }
}

#[pymethods]
impl PyAddress {
    #[new]
    fn new(addr: &PyBytes) -> PyResult<Self> {
        let _addr = addr.as_bytes();
        if _addr.len() != 21 {
            Err(ValueError::py_err("addr length is 21 bytes"))
        } else if 0b11111 < _addr[0] {
            Err(ValueError::py_err("addr version is 0b00000 to 0b11111"))
        } else {
            let mut addr = [0u8; 21];
            write_slice(&mut addr, _addr);
            Ok(PyAddress { addr })
        }
    }

    #[classmethod]
    fn from_string(_cls: &PyType, string: &str) -> PyResult<Self> {
        let addr = string2addr(string)
            .map_err(|err| ValueError::py_err(format!("failed get address from string format: {}", err)))?;
        Ok(PyAddress { addr })
    }

    #[classmethod]
    fn from_params(_cls: &PyType, ver: u8, identifier: &PyBytes) -> PyResult<Self> {
        let identifier = identifier.as_bytes();
        if identifier.len() != 20 {
            Err(ValueError::py_err("identifier is 20 bytes"))
        } else if 0b11111 < ver {
            Err(ValueError::py_err("version is 0b00000 to 0b11111"))
        } else {
            let mut addr = [ver; 21];
            write_slice(&mut addr[1..21], identifier);
            Ok(PyAddress { addr })
        }
    }

    fn to_string(&self) -> PyResult<String> {
        let bech = params2bech(self.addr[0], &self.addr[1..21])
            .map_err(|err| ValueError::py_err(format!("failed get string format address: {}", err)))?;
        Ok(bech.to_string())
    }

    fn version(&self) -> u8 {
        self.addr[0]
    }

    fn identifier(&self, py: Python) -> PyObject {
        // return 20 bytes ripemd160(sha256()) hashed
        PyBytes::new(py, &self.addr[1..21]).to_object(py)
    }

    fn binary(&self, py: Python) -> PyObject {
        // return 21 bytes
        PyBytes::new(py, &self.addr).to_object(py)
    }
}

impl fmt::Debug for PyAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string().unwrap())
    }
}
