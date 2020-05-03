use crate::utils::write_slice;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyType};

type Address = [u8; 21];

#[pyclass]
pub struct PyAddress {
    pub addr: Address,
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
        let addr = utils::string2addr(string.to_string()?.as_ref()).map_err(|err| {
            ValueError::py_err(format!("failed get address from string format: {}", err))
        })?;
        Ok(PyAddress { addr })
    }

    fn to_string(&self, hrp: &PyString) -> PyResult<String> {
        let bech = utils::params2bech(hrp.to_string()?.as_ref(), self.addr[0], &self.addr[1..21])
            .map_err(|err| {
            ValueError::py_err(format!("failed get string format address: {}", err))
        })?;
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
}

impl PyAddress {
    pub fn from_address(addr: Address) -> Self {
        PyAddress { addr }
    }

    pub fn clone_to_identifier(self) -> Address {
        self.addr
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
            Ok((_, ver, mut identifier)) => {
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
