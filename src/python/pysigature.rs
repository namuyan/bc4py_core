use crate::signature::*;
use pyo3::basic::CompareOp;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};
use pyo3::PyObjectProtocol;

#[pyclass]
pub struct PySignature {
    pub signs: Vec<Signature>,
}

#[pyproto]
impl PyObjectProtocol for PySignature {
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self.signs))
    }

    fn __richcmp__(&self, other: PyRef<'p, Self>, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.signs == other.signs), // `__eq__`
            CompareOp::Ne => Ok(self.signs != other.signs), // `__ne__`
            _ => Err(ValueError::py_err("not implemented")),
        }
    }
}

#[pymethods]
impl PySignature {
    const SINGLE: u32 = 0;
    const AGGREGATE: u32 = 1;
    const THRESHOLD: u32 = 2;

    #[new]
    fn new() -> Self {
        PySignature { signs: vec![] }
    }

    #[getter(SINGLE)]
    fn get_single(&self) -> u32 {
        Self::SINGLE
    }

    #[getter(AGGREGATE)]
    fn get_aggregate(&self) -> u32 {
        Self::AGGREGATE
    }

    #[getter(THRESHOLD)]
    fn get_threshold(&self) -> u32 {
        Self::THRESHOLD
    }

    fn get_binary_list(&self, py: Python) -> PyObject {
        let mut vec = Vec::with_capacity(33 + 32 + 32);
        let mut signs = Vec::with_capacity(self.signs.len());
        for signature in self.signs.iter() {
            signature_to_bytes(signature, &mut vec);
            signs.push(PyBytes::new(py, vec.as_slice()).to_object(py));
            vec.clear(); // reuse with capacity
        }
        PyTuple::new(py, &signs).to_object(py)
    }

    fn add_from_params(&mut self, stype: u32, params: &PyAny) -> PyResult<()> {
        // note: don't confirm "sign is three element"
        // note: `params` maybe tuple not list?
        let sign = match stype {
            Self::SINGLE => {
                let sign: (Vec<u8>, Vec<u8>, Vec<u8>) = params.extract()?;
                Signature::new_single_sig(&sign.0, &sign.1, &sign.2)
            },
            Self::AGGREGATE => {
                let sign: (Vec<u8>, Vec<u8>, Vec<u8>) = params.extract()?;
                Signature::new_aggregate_sig(&sign.0, &sign.1, &sign.2)
            },
            Self::THRESHOLD => {
                let sign: (Vec<u8>, Vec<u8>, Vec<u8>) = params.extract()?;
                Signature::new_threshold_sig(&sign.0, &sign.1, &sign.2)
            },
            _ => Err(()),
        };
        match sign {
            Ok(sign) => self.signs.push(sign),
            Err(_) => return Err(ValueError::py_err("failed to add sign from params")),
        };
        Ok(())
    }

    fn add_from_binary(&mut self, binary: &PyBytes) -> PyResult<()> {
        self.signs.push(
            bytes_to_signature(binary.as_bytes())
                .map_err(|err| ValueError::py_err(format!("failed to add sign from binary: {}", err)))?,
        );
        Ok(())
    }
}
