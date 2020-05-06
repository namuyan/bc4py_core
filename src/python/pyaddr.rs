use crate::utils::write_slice;
use pyo3::basic::CompareOp;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyType};
use pyo3::PyObjectProtocol;
use std::collections::hash_map::DefaultHasher;
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
    fn from_string(_cls: &PyType, string: &PyString) -> PyResult<Self> {
        let addr = utils::string2addr(string.to_string()?.as_ref())
            .map_err(|err| ValueError::py_err(format!("failed get address from string format: {}", err)))?;
        Ok(PyAddress { addr })
    }

    fn to_string(&self, hrp: &PyString) -> PyResult<String> {
        let bech = utils::params2bech(hrp.to_string()?.as_ref(), self.addr[0], &self.addr[1..21])
            .map_err(|err| ValueError::py_err(format!("failed get string format address: {}", err)))?;
        Ok(bech.to_string())
    }

    #[getter(version)]
    fn get_version(&self) -> u8 {
        self.addr[0]
    }

    #[setter(version)]
    fn set_version(&mut self, value: u8) -> PyResult<()> {
        if 0b11111 < value {
            Err(ValueError::py_err("addr version is 0b00000 to 0b11111"))
        } else {
            self.addr[0] = value;
            Ok(())
        }
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

impl std::fmt::Debug for PyAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PyAddress")
            .field(&hex::encode(self.addr.as_ref()))
            .finish()
    }
}

mod utils {
    use crate::utils::write_slice;
    use bech32::{convert_bits, Bech32, Error};
    use std::str::FromStr;

    type Address = [u8; 21];

    pub fn string2addr(string: &str) -> Result<Address, Error> {
        // return [ver+identifier] bytes
        match addr2params(string) {
            Ok((_, ver, identifier)) => {
                let mut addr = [ver; 21];
                write_slice(&mut addr[1..21], &identifier);
                Ok(addr)
            },
            Err(err) => Err(err),
        }
    }

    pub fn params2bech(hrp: &str, ver: u8, identifier: &[u8]) -> Result<Bech32, Error> {
        let mut data = convert_bits(identifier, 8, 5, true)?;
        data.insert(0, ver);
        Bech32::new_check_data(hrp.to_string(), data)
    }

    fn addr2params(string: &str) -> Result<(String, u8, Vec<u8>), Error> {
        // return (hrp, version, identifier)
        let bech = Bech32::from_str(string)?;
        let ver = match bech.data().get(0) {
            Some(ver) => ver.to_owned().to_u8(),
            None => return Err(Error::InvalidLength),
        };
        let identifier = convert_bits(&bech.data()[1..], 5, 8, false)?;
        Ok((bech.hrp().to_string(), ver, identifier))
    }
}
