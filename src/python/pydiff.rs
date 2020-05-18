use crate::block::{bits_to_target, target_to_bits, target_to_diff, BlockFlag, DifficultyBuilder};
use crate::python::pychain::{PyChain, SharedChain};
use crate::utils::u256_to_bytes;
use bigint::U256;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// calculate difficulty, bits and bias
#[pyclass]
pub struct PyDiffBuilder {
    chain: SharedChain,
    diff: DifficultyBuilder,
}

#[pymethods]
impl PyDiffBuilder {
    #[new]
    fn new(params: &PyAny, chain: PyRef<PyChain>) -> PyResult<Self> {
        let vec: Vec<(u8, u32, u32, u32)> = params.extract()?;
        let mut params = Vec::with_capacity(vec.len());
        for p in vec {
            let flag = BlockFlag::from_int(p.0).map_err(|err| ValueError::py_err(err))?;
            params.push((flag, p.1, p.2, p.3));
        }
        Ok(PyDiffBuilder {
            chain: chain.clone_chain(),
            diff: DifficultyBuilder::new(params),
        })
    }

    fn calc_next_bits(&mut self, previous_hash: &PyBytes, flag: u8) -> PyResult<u32> {
        let previous_hash = previous_hash.as_bytes();
        if previous_hash.len() != 32 {
            return Err(ValueError::py_err("previous_hash is 32 bytes"));
        }
        let previous_hash = U256::from(previous_hash);
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let chain = self.chain.lock().unwrap();
        // get next bits from previous info
        self.diff
            .calc_next_bits(&previous_hash, &flag, &chain.tables)
            .map_err(|err| ValueError::py_err(err))
    }

    fn calc_next_bias(&mut self, previous_hash: &PyBytes, flag: u8) -> PyResult<f64> {
        let previous_hash = previous_hash.as_bytes();
        if previous_hash.len() != 32 {
            return Err(ValueError::py_err("previous_hash is 32 bytes"));
        }
        let previous_hash = U256::from(previous_hash);
        let flag = BlockFlag::from_int(flag).map_err(|err| ValueError::py_err(err))?;
        let chain = self.chain.lock().unwrap();
        // get next bias from previous info
        self.diff
            .calc_next_bias(&previous_hash, &flag, &chain.tables)
            .map_err(|err| ValueError::py_err(err))
    }

    #[staticmethod]
    fn bits_to_target(py: Python, bits: u32) -> PyResult<PyObject> {
        match bits_to_target(bits) {
            Ok(target) => Ok(PyBytes::new(py, u256_to_bytes(&target).as_ref()).to_object(py)),
            Err(err) => Err(ValueError::py_err(format!("cannot bits to target by: {}", err))),
        }
    }

    #[staticmethod]
    fn target_to_bits(target: &PyBytes) -> PyResult<u32> {
        let target = target.as_bytes();
        if target.len() != 32 {
            return Err(ValueError::py_err("target is 32 bytes"));
        }
        let target = U256::from(target);
        Ok(target_to_bits(&target))
    }

    #[staticmethod]
    fn target_to_diff(target: &PyBytes) -> PyResult<f64> {
        let target = target.as_bytes();
        if target.len() != 32 {
            return Err(ValueError::py_err("target is 32 bytes"));
        }
        let target = U256::from(target);
        Ok(target_to_diff(target))
    }
}
