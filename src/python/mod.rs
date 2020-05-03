pub mod pyaddr;
pub mod pyblock;
pub mod pychain;
pub mod pysigature;
pub mod pytx;
use pyo3::prelude::*;

/// This module is a python module implemented in Rust.
#[pymodule]
fn bc4py_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<pyaddr::PyAddress>()?;
    m.add_class::<pyblock::PyBlock>()?;
    m.add_class::<pytx::PyTx>()?;
    m.add_class::<pytx::PyTxInputs>()?;
    m.add_class::<pytx::PyTxOutputs>()?;
    m.add_class::<pysigature::PySignature>()?;
    m.add_class::<pychain::PyChain>()?;
    Ok(())
}
