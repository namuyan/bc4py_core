pub mod pyaccount;
pub mod pyaddr;
pub mod pyblock;
pub mod pychain;
pub mod pysigature;
pub mod pytx;
pub mod pyunspent;
pub mod utils;
use pyo3::prelude::*;

/// This module is a python module implemented in Rust.
#[pymodule]
fn bc4py_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<pyaccount::PyBalance>()?;
    m.add_class::<pyaccount::PyMovement>()?;
    m.add_class::<pyaccount::PyAccount>()?;
    m.add_class::<pyaddr::PyAddress>()?;
    m.add_class::<pyblock::PyBlock>()?;
    m.add_class::<pytx::PyTx>()?;
    m.add_class::<pytx::PyTxInputs>()?;
    m.add_class::<pytx::PyTxOutputs>()?;
    m.add_class::<pysigature::PySignature>()?;
    m.add_class::<pychain::PyChain>()?;
    m.add_class::<pyunspent::PyUnspent>()?;
    Ok(())
}
