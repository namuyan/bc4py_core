use crate::python::pychain::PyChain;
use crate::python::pysigature::PySignature;
use crate::python::pyunspent::PyUnspent;
use crate::tx::*;
use crate::utils::{u256_to_bytes, write_slice};
use bigint::U256;
use pyo3::exceptions::ValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};
use pyo3::PyIterProtocol;

#[pyclass]
pub struct PyTxInputs {
    iter_index: Option<usize>,
    inputs: Vec<TxInput>,
}

#[pymethods]
impl PyTxInputs {
    #[new]
    fn new(inputs: &PyAny) -> PyResult<Self> {
        let inputs: Vec<(Vec<u8>, u8)> = inputs.extract()?;
        let inputs = inputs
            .iter()
            .map(|(hash, index)| {
                assert_eq!(hash.len(), 32, "inputs hash is 32bytes");
                let hash = U256::from(hash.as_slice());
                TxInput(hash, *index)
            })
            .collect();
        Ok(PyTxInputs {
            iter_index: None,
            inputs,
        })
    }

    fn len(&self) -> usize {
        self.inputs.len()
    }

    fn get(&self, py: Python, index: u8) -> PyResult<Option<PyObject>> {
        match self.inputs.get(index as usize) {
            Some(input) => {
                let hash = PyBytes::new(py, &u256_to_bytes(&input.0)).to_object(py);
                let index = input.1.to_object(py);
                Ok(Some(PyTuple::new(py, &[hash, index]).to_object(py)))
            },
            None => Ok(None),
        }
    }

    fn add(&mut self, hash: &PyBytes, index: u8) -> PyResult<()> {
        let hash = hash.as_bytes();
        if 255 <= self.inputs.len() {
            Err(ValueError::py_err("inputs size is limited to 255u8"))
        } else if hash.len() == 32 {
            let hash = U256::from(hash);
            self.inputs.push(TxInput(hash, index));
            Ok(())
        } else {
            Err(ValueError::py_err("hash is 32 bytes"))
        }
    }

    fn push(&mut self, unspent: PyRef<PyUnspent>) -> PyResult<()> {
        if 255 <= self.inputs.len() {
            Err(ValueError::py_err("inputs size is limited to 255u8"))
        } else {
            self.inputs.push(unspent.clone_input());
            Ok(())
        }
    }

    fn pop(&mut self, py: Python, index: Option<u8>) -> PyResult<PyObject> {
        let removed = if index.is_some() {
            let index = index.unwrap() as usize;
            if self.inputs.get(index).is_some() {
                self.inputs.remove(index)
            } else {
                return Err(ValueError::py_err(format!(
                    "index({}) is out of range({})",
                    index,
                    self.inputs.len()
                )));
            }
        } else {
            if 0 < self.inputs.len() {
                self.inputs.pop().unwrap()
            } else {
                return Err(ValueError::py_err("inputs is empty but try to pop()"));
            }
        };
        let hash = PyBytes::new(py, &u256_to_bytes(&removed.0)).to_object(py);
        let index = removed.1.to_object(py);
        Ok(PyTuple::new(py, &[hash, index]).to_object(py))
    }

    fn extend(&mut self, value: PyRef<PyTxInputs>) -> PyResult<()> {
        if 255 <= self.inputs.len() + value.inputs.len() {
            Err(ValueError::py_err("too many inputs to extend"))
        } else {
            self.inputs.extend(
                value
                    .inputs
                    .iter()
                    .map(|item| item.clone())
                    .collect::<Vec<TxInput>>()
                    .into_iter(),
            );
            Ok(())
        }
    }

    fn clear(&mut self) {
        self.inputs.clear();
    }
}

#[pyproto]
impl PyIterProtocol for PyTxInputs {
    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<PyObject> {
        let py = unsafe { Python::assume_gil_acquired() };
        slf.iter_index.replace(0);
        Ok(slf.into_py(py))
    }

    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        let py = unsafe { Python::assume_gil_acquired() };
        let index = slf.iter_index.unwrap();
        *slf.iter_index.as_mut().unwrap() += 1; // pre increment
        match slf.inputs.get(index) {
            Some(input) => {
                let hash = PyBytes::new(py, &u256_to_bytes(&input.0)).to_object(py);
                let index = input.1.to_object(py);
                Ok(Some(PyTuple::new(py, &[hash, index]).to_object(py)))
            },
            None => {
                // clear iterator status
                slf.iter_index = None;
                Ok(None)
            },
        }
    }
}

#[pyclass]
pub struct PyTxOutputs {
    iter_index: Option<usize>,
    outputs: Vec<TxOutput>,
}

#[pymethods]
impl PyTxOutputs {
    #[new]
    fn new(outputs: &PyAny) -> PyResult<Self> {
        let outputs: Vec<(Vec<u8>, u32, u64)> = outputs.extract()?;
        let outputs = outputs
            .iter()
            .map(|(_addr, coin_id, amount)| {
                assert_eq!(_addr.len(), 21, "output address is 21bytes");
                let mut addr = [0u8; 21];
                write_slice(&mut addr, _addr);
                TxOutput(addr, *coin_id, *amount)
            })
            .collect();
        Ok(PyTxOutputs {
            iter_index: None,
            outputs,
        })
    }

    fn len(&self) -> usize {
        self.outputs.len()
    }

    fn get(&self, py: Python, index: u8) -> PyResult<Option<PyObject>> {
        match self.outputs.get(index as usize) {
            Some(output) => {
                let addr = PyBytes::new(py, output.0.as_ref()).to_object(py);
                let coin_id = output.1.to_object(py);
                let amount = output.2.to_object(py);
                Ok(Some(PyTuple::new(py, &[addr, coin_id, amount]).to_object(py)))
            },
            None => Ok(None),
        }
    }

    fn add(&mut self, addr: &PyBytes, coin_id: u32, amount: u64) -> PyResult<()> {
        if 255 <= self.outputs.len() {
            Err(ValueError::py_err("output size is limit to 255u8"))
        } else {
            let mut slice = [0u8; 21];
            write_slice(&mut slice, addr.as_bytes());
            let output = TxOutput(slice, coin_id, amount);
            self.outputs.push(output);
            Ok(())
        }
    }

    fn pop(&mut self, py: Python, index: Option<u8>) -> PyResult<PyObject> {
        let removed = if index.is_some() {
            let index = index.unwrap() as usize;
            if self.outputs.get(index).is_some() {
                self.outputs.remove(index)
            } else {
                return Err(ValueError::py_err(format!(
                    "index({}) is out of range({})",
                    index,
                    self.outputs.len()
                )));
            }
        } else {
            match self.outputs.pop() {
                Some(output) => output,
                None => return Err(ValueError::py_err("outputs is empty but try to pop()")),
            }
        };
        let addr = PyBytes::new(py, removed.0.as_ref()).to_object(py);
        let coin_id = removed.1.to_object(py);
        let amount = removed.2.to_object(py);
        Ok(PyTuple::new(py, &[addr, coin_id, amount]).to_object(py))
    }

    fn extend(&mut self, value: &PyCell<PyTxOutputs>) -> PyResult<()> {
        let extra = value.borrow();
        if 255 <= self.outputs.len() + extra.outputs.len() {
            Err(ValueError::py_err("too many outputs to extend"))
        } else {
            self.outputs.extend(
                extra
                    .outputs
                    .iter()
                    .map(|item| item.clone())
                    .collect::<Vec<TxOutput>>()
                    .into_iter(),
            );
            Ok(())
        }
    }

    fn clear(&mut self) {
        self.outputs.clear();
    }
}

#[pyproto]
impl PyIterProtocol for PyTxOutputs {
    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<PyObject> {
        let py = unsafe { Python::assume_gil_acquired() };
        slf.iter_index.replace(0);
        Ok(slf.into_py(py))
    }

    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        let py = unsafe { Python::assume_gil_acquired() };
        let index = slf.iter_index.unwrap();
        *slf.iter_index.as_mut().unwrap() += 1; // pre increment
        match slf.outputs.get(index) {
            Some(output) => {
                let addr = PyBytes::new(py, output.0.as_ref()).to_object(py);
                let coin_id = output.1.to_object(py);
                let amount = output.2.to_object(py);
                Ok(Some(PyTuple::new(py, &[addr, coin_id, amount]).to_object(py)))
            },
            None => {
                // clear iterator status
                slf.iter_index = None;
                Ok(None)
            },
        }
    }
}

#[pyclass]
pub struct PyTx {
    // TX body
    #[pyo3(get, set)]
    pub version: u32,
    pub txtype: TxType,
    #[pyo3(get, set)]
    pub time: u32,
    #[pyo3(get, set)]
    pub deadline: u32,
    pub inputs: Py<PyTxInputs>,
    pub outputs: Py<PyTxOutputs>,
    #[pyo3(get, set)]
    pub gas_price: u64,
    #[pyo3(get, set)]
    pub gas_amount: i64,
    pub message: TxMessage,

    // for verify
    pub signature: Option<Py<PySignature>>,
    pub inputs_cache: Option<Vec<TxOutput>>,
}

#[pymethods]
impl PyTx {
    #[new]
    fn new(
        version: u32,
        txtype: u32,
        time: u32,
        deadline: u32,
        inputs: &PyCell<PyTxInputs>,
        outputs: &PyCell<PyTxOutputs>,
        gas_price: u64,
        gas_amount: i64,
        message_type: u8,
        message: Option<&PyBytes>,
    ) -> PyResult<Self> {
        // tx python object
        // note:  inputs, outputs, signature and input_cache insert after
        let txtype = TxType::from_int(txtype).map_err(|err| ValueError::py_err(err))?;
        let message = match message {
            Some(message) => {
                let message = message.as_bytes().to_vec();
                TxMessage::new(message_type, message).map_err(|err| ValueError::py_err(err))?
            },
            None => TxMessage::Nothing,
        };
        Ok(PyTx {
            version,
            txtype,
            time,
            deadline,
            inputs: inputs.into(),
            outputs: outputs.into(),
            gas_price,
            gas_amount,
            message,
            signature: None,
            inputs_cache: None,
        })
    }

    #[getter]
    fn get_txtype(&self) -> u32 {
        self.txtype.to_int()
    }

    #[setter]
    fn set_txtype(&mut self, value: u32) -> PyResult<()> {
        self.txtype = TxType::from_int(value).map_err(|err| ValueError::py_err(err))?;
        Ok(())
    }

    #[getter]
    fn get_inputs(&self, py: Python) -> PyObject {
        self.inputs.to_object(py)
    }

    #[getter]
    fn get_outputs(&self, py: Python) -> PyObject {
        self.outputs.to_object(py)
    }

    fn get_message_type(&self) -> u8 {
        self.message.to_int()
    }

    fn get_message_body(&self, py: Python) -> PyObject {
        PyBytes::new(py, self.message.to_bytes()).to_object(py)
    }

    fn replace_message(&mut self, value: &PyBytes) -> PyResult<()> {
        match self.message {
            TxMessage::Nothing => Err(ValueError::py_err("message type is none")),
            TxMessage::Plain(_) => Err(ValueError::py_err("not allow string message change after")),
            TxMessage::Byte(ref mut bytes) => {
                bytes.clear();
                bytes.extend_from_slice(value.as_bytes());
                Ok(())
            },
        }
    }

    #[getter]
    fn get_signature(&self, py: Python) -> Option<PyObject> {
        match self.signature.as_ref() {
            Some(signatures) => Some(signatures.to_object(py)),
            None => None,
        }
    }

    #[setter]
    fn set_signature(&mut self, value: &PyCell<PySignature>) {
        self.signature.replace(value.into());
    }

    fn fill_input_cache(&mut self, py: Python, chain: PyRef<PyChain>) -> PyResult<()> {
        if self.inputs_cache.is_some() {
            return Err(ValueError::py_err("already input_cache is filled"));
        }
        // not only fill cache but check the input is unused
        let cell: &PyCell<PyTxInputs> = self.inputs.as_ref(py);
        let inputs_rc: PyRef<PyTxInputs> = cell.borrow();
        let mut inputs_cache = Vec::with_capacity(inputs_rc.inputs.len());
        for input in inputs_rc.inputs.iter() {
            match chain
                .lock()
                .get_output_of_input(input, true)
                .map_err(|err| ValueError::py_err(err))?
            {
                Some(output) => inputs_cache.push(output),
                None => {
                    return Err(ValueError::py_err(format!(
                        "try to fill input_cache but non exist or already used {:?}",
                        input
                    )))
                },
            }
        }
        // success!
        // note: all inputs are exist & not used at this time
        self.inputs_cache = Some(inputs_cache);
        Ok(())
    }

    #[getter]
    fn get_input_cache(&self, py: Python) -> Option<PyObject> {
        match self.inputs_cache.as_ref() {
            Some(inputs) => {
                let inputs = inputs
                    .iter()
                    .map(|input| {
                        let addr = PyBytes::new(py, input.0.as_ref()).to_object(py);
                        let coin_id = input.1.to_object(py);
                        let amount = input.2.to_object(py);
                        PyTuple::new(py, &[addr, coin_id, amount]).to_object(py)
                    })
                    .collect::<Vec<PyObject>>();
                Some(PyTuple::new(py, &inputs).to_object(py))
            },
            None => None,
        }
    }
}

// use on inner (not for Pyo3)
impl PyTx {
    pub fn from_tx(tx: Tx) -> PyResult<PyTx> {
        // convert from Tx to PyTx (moved)
        let gil = Python::acquire_gil();
        let py = gil.python();
        let inputs: _ = PyCell::new(py, PyTxInputs {
            iter_index: None,
            inputs: tx.inputs,
        })?;
        let outputs: _ = PyCell::new(py, PyTxOutputs {
            iter_index: None,
            outputs: tx.outputs,
        })?;

        let signature = tx.signature.map(|signs| {
            PyCell::new(py, PySignature { signs })
                .expect("PyCell convert failed on sign")
                .into()
        });
        Ok(PyTx {
            version: tx.version,
            txtype: tx.txtype,
            time: tx.time,
            deadline: tx.deadline,
            inputs: inputs.into(),
            outputs: outputs.into(),
            gas_price: tx.gas_price,
            gas_amount: tx.gas_amount,
            message: tx.message,
            signature,
            inputs_cache: tx.inputs_cache,
        })
    }

    pub fn clone_to_tx(&self) -> Tx {
        // covert PyTx to Tx (cloned)
        let gil = Python::acquire_gil();
        let py = gil.python();
        let cell: &PyCell<PyTxInputs> = self.inputs.as_ref(py);
        let inputs_rc: PyRef<PyTxInputs> = cell.borrow();
        let cell: &PyCell<PyTxOutputs> = self.outputs.as_ref(py);
        let output_rc: PyRef<PyTxOutputs> = cell.borrow();
        let signature = match self.signature.as_ref() {
            Some(signature) => {
                let cell: &PyCell<PySignature> = signature.as_ref(py);
                let signature_rc: PyRef<PySignature> = cell.borrow();
                Some(signature_rc.signs.to_vec())
            },
            None => None,
        };

        Tx {
            version: self.version,
            txtype: self.txtype.clone(),
            time: self.time,
            deadline: self.deadline,
            inputs: inputs_rc.inputs.clone(),
            outputs: output_rc.outputs.clone(),
            gas_price: self.gas_price,
            gas_amount: self.gas_amount,
            message: self.message.clone(),
            signature,
            inputs_cache: self.inputs_cache.clone(),
        }
    }
}
