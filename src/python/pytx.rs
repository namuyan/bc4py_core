use crate::balance::Balances;
use crate::python::pyaccount::PyBalance;
use crate::python::pyaddr::PyAddress;
use crate::python::pychain::PyChain;
use crate::python::pysigature::PySignature;
use crate::python::pyunspent::PyUnspent;
use crate::signature::{signature_to_bytes, verify_signature};
use crate::tx::*;
use crate::utils::*;
use bigint::U256;
use pyo3::exceptions::{AssertionError, IndexError, ValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple, PyType};
use pyo3::PyIterProtocol;

type Address = [u8; 21];

#[pyclass]
pub struct PyTxInputs {
    iter_index: Option<usize>,
    pub inputs: Vec<TxInput>,
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

    fn get(&self, py: Python, index: u8) -> PyResult<PyObject> {
        match self.inputs.get(index as usize) {
            Some(input) => {
                let hash = PyBytes::new(py, &u256_to_bytes(&input.0)).to_object(py);
                let index = input.1.to_object(py);
                Ok(PyTuple::new(py, &[hash, index]).to_object(py))
            },
            None => Err(IndexError::py_err(format!(
                "out of bounds index={} len={}",
                index,
                self.inputs.len()
            ))),
        }
    }

    fn tuple(&self, py: Python) -> PyObject {
        self.inputs
            .iter()
            .map(|input| {
                let hash = PyBytes::new(py, u256_to_bytes(&input.0).as_ref()).to_object(py);
                let index = input.1.to_object(py);
                (hash, index)
            })
            .collect::<Vec<(PyObject, PyObject)>>()
            .to_object(py)
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
        let outputs: Vec<(PyRef<PyAddress>, u32, u64)> = outputs.extract()?;
        let outputs = outputs
            .iter()
            .map(|(addr, coin_id, amount)| TxOutput(addr.addr, *coin_id, *amount))
            .collect();
        Ok(PyTxOutputs {
            iter_index: None,
            outputs,
        })
    }

    fn len(&self) -> usize {
        self.outputs.len()
    }

    fn get(&self, py: Python, index: u8) -> PyResult<PyObject> {
        match self.outputs.get(index as usize) {
            Some(output) => {
                let addr: _ = PyCell::new(py, PyAddress {
                    addr: output.0.clone(),
                })?;
                let coin_id = output.1.to_object(py);
                let amount = output.2.to_object(py);
                Ok(PyTuple::new(py, &[addr.into(), coin_id, amount]).to_object(py))
            },
            None => Err(IndexError::py_err(format!(
                "out of bounds index={} len={}",
                index,
                self.outputs.len()
            ))),
        }
    }

    fn tuple(&self, py: Python) -> PyObject {
        self.outputs
            .iter()
            .map(|output| {
                let addr = PyCell::new(py, PyAddress { addr: output.0 }).unwrap();
                let coin_id = output.1.to_object(py);
                let amount = output.2.to_object(py);
                (addr.into(), coin_id, amount)
            })
            .collect::<Vec<(PyObject, PyObject, PyObject)>>()
            .to_object(py)
    }

    fn add(&mut self, addr: PyRef<PyAddress>, coin_id: u32, amount: u64) -> PyResult<()> {
        if 255 <= self.outputs.len() {
            Err(ValueError::py_err("output size is limit to 255u8"))
        } else {
            let output = TxOutput(addr.addr, coin_id, amount);
            self.outputs.push(output);
            Ok(())
        }
    }

    fn replace(&mut self, index: usize, addr: PyRef<PyAddress>, coin_id: u32, amount: u64) -> PyResult<()> {
        match self.outputs.get_mut(index) {
            Some(output) => {
                output.0 = addr.addr;
                output.1 = coin_id;
                output.2 = amount;
                Ok(())
            },
            None => Err(IndexError::py_err(format!(
                "out of bounds index={} len={}",
                index,
                self.outputs.len()
            ))),
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
        let addr: _ = PyCell::new(py, PyAddress {
            addr: removed.0.clone(),
        })?;
        let coin_id = removed.1.to_object(py);
        let amount = removed.2.to_object(py);
        Ok(PyTuple::new(py, &[addr.into(), coin_id, amount]).to_object(py))
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
                let addr: _ = PyCell::new(py, PyAddress {
                    addr: output.0.clone(),
                })?;
                let coin_id = output.1.to_object(py);
                let amount = output.2.to_object(py);
                Ok(Some(
                    PyTuple::new(py, &[addr.into(), coin_id, amount]).to_object(py),
                ))
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
    pub verified_list: Option<Vec<Address>>,

    // object creation time
    #[pyo3(get, set)]
    pub create_time: f64,
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
            verified_list: None,
            create_time: get_current_time(),
        })
    }

    fn hex(&self, py: Python) -> String {
        // for debug
        let hash = self.clone_to_body(py).hash();
        hex::encode(hash.as_slice())
    }

    fn hash(&self, py: Python) -> PyObject {
        let hash = self.clone_to_body(py).hash();
        PyBytes::new(py, hash.as_ref()).to_object(py)
    }

    #[classmethod]
    fn from_bytes(_cls: &PyType, py: Python, binary: &PyBytes) -> PyResult<Self> {
        let body = TxBody::from_bytes(binary.as_bytes()).map_err(|err| ValueError::py_err(err))?;
        let inputs = PyCell::new(py, PyTxInputs {
            iter_index: None,
            inputs: body.inputs,
        })
        .map_err(|err| ValueError::py_err(err))?;
        let outputs = PyCell::new(py, PyTxOutputs {
            iter_index: None,
            outputs: body.outputs,
        })
        .map_err(|err| ValueError::py_err(err))?;
        Ok(PyTx {
            version: body.version,
            txtype: body.txtype,
            time: body.time,
            deadline: body.deadline,
            inputs: inputs.into(),
            outputs: outputs.into(),
            gas_price: body.gas_price,
            gas_amount: body.gas_amount,
            message: body.message,
            signature: None,
            inputs_cache: None,
            verified_list: None,
            create_time: get_current_time(),
        })
    }

    fn to_bytes(&self, py: Python) -> PyObject {
        let body = self.clone_to_body(py);
        let bytes = body.to_bytes();
        PyBytes::new(py, bytes.as_slice()).to_object(py)
    }

    #[classmethod]
    fn template_for_staking(
        _cls: &PyType,
        py: Python,
        version: u32,
        unspent: PyRef<PyUnspent>,
    ) -> PyResult<Self> {
        // template coinbase for staking
        // note: update time, deadline, outputs' amount once a 1 sec
        let input = unspent.input.clone();
        let output = unspent.output.clone();
        let inputs = PyCell::new(py, PyTxInputs {
            iter_index: None,
            inputs: vec![input],
        })?;
        let outputs = PyCell::new(py, PyTxOutputs {
            iter_index: None,
            outputs: vec![output],
        })?;
        Ok(PyTx {
            version,
            txtype: TxType::PoS,
            time: 0,
            deadline: 0,
            inputs: inputs.into(),
            outputs: outputs.into(),
            gas_price: 0,
            gas_amount: 0,
            message: TxMessage::Nothing,
            signature: None,
            inputs_cache: Some(vec![unspent.output.clone()]),
            verified_list: None,
            create_time: get_current_time(),
        })
    }

    #[getter]
    fn get_txtype(&self) -> u32 {
        self.txtype.to_int()
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

    fn fill_input_cache(&mut self, py: Python, ignore: bool, chain: PyRef<PyChain>) -> PyResult<()> {
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
                .get_output_of_input(input, ignore)
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

    fn get_input_cache(&self) -> PyResult<PyTxOutputs> {
        if self.inputs_cache.is_none() {
            return Err(AssertionError::py_err("input_cache is none"));
        }
        Ok(PyTxOutputs {
            iter_index: None,
            outputs: self.inputs_cache.as_ref().unwrap().iter().cloned().collect(),
        })
    }

    fn fill_verified_list(&mut self, py: Python) -> PyResult<()> {
        // if self.verified_list.is_some() {
        //     return Err(AssertionError::py_err("already filled verified_list"));
        // }
        if self.signature.is_none() {
            return Err(AssertionError::py_err(
                "cannot fill verified_list because signature is none",
            ));
        }
        // calc signature -> address
        let cell: &PyCell<PySignature> = self.signature.as_ref().unwrap().as_ref(py);
        let signs = &cell.borrow().signs;
        let binary = self.clone_to_body(py).to_bytes();
        let mut verified_list = Vec::with_capacity(signs.len());
        for signature in signs.iter() {
            let result = verify_signature(signature, &binary);
            if result.is_ok() && result.unwrap() {
                verified_list.push(signature.get_address(0));
            } else {
                return Err(ValueError::py_err(format!(
                    "verification failed at {:?} by {:?}",
                    signature, result
                )));
            }
        }
        // success
        self.verified_list.replace(verified_list);
        Ok(())
    }

    fn get_verified_list(&mut self) -> PyResult<Vec<PyAddress>> {
        if self.verified_list.is_none() {
            // exec `fill_verified_list()` before
            return Err(ValueError::py_err(
                "cannot get verified addr because verified_list is none",
            ));
        }
        Ok(self
            .verified_list
            .as_ref()
            .unwrap()
            .iter()
            .map(|addr| PyAddress { addr: *addr })
            .collect())
    }

    fn get_fee(&self, py: Python, check: bool) -> PyResult<PyBalance> {
        let inputs = self
            .inputs_cache
            .as_ref()
            .ok_or(AssertionError::py_err("try to get_fee but inputs_cache is none"))?;

        // fee = inputs - outputs
        let mut fee = Balances(Vec::with_capacity(1));
        for input in inputs.iter() {
            fee.add(input.1, input.2);
        }
        let cell: &PyCell<PyTxOutputs> = self.outputs.as_ref(py);
        for output in cell.borrow().outputs.iter() {
            fee.sub(output.1, output.2);
        }
        fee.compaction();

        // check amount (optional)
        if check {
            let real = self.gas_price as i64 * self.gas_amount;
            let calc = fee.sum();
            if real != calc {
                return Err(ValueError::py_err(format!(
                    "mismatch fee amount real={} calc={}",
                    real, calc
                )));
            }
        }

        // success
        Ok(PyBalance {
            iter_index: None,
            balance: fee,
        })
    }

    pub fn get_size(&self, py: Python) -> usize {
        // note: not include signature size
        let inputs: &PyCell<PyTxInputs> = self.inputs.as_ref(py);
        let outputs: &PyCell<PyTxOutputs> = self.outputs.as_ref(py);
        // 39 is tx_static size
        39 + inputs.borrow().len() * 33 + outputs.borrow().len() * 33 + self.message.length()
    }

    pub fn getinfo(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        let tx = self.clone_to_manual(py);

        dict.set_item("hash", u256_to_hex(&tx.hash()))?;
        // dict.set_item("pos_amount", )?; REMOVED
        // dict.set_item("height", )?; REMOVED
        dict.set_item("version", self.version)?;
        dict.set_item("type", format!("{:?}", self.txtype))?;
        dict.set_item("time", self.time)?;
        dict.set_item("deadline", self.deadline)?;
        {
            let inputs = tx
                .body
                .inputs
                .iter()
                .map(|input| (u256_to_hex(&input.0), input.1))
                .collect::<Vec<(String, u8)>>();
            dict.set_item("inputs", inputs)?;
        }
        {
            let outputs = tx
                .body
                .outputs
                .iter()
                .map(|output| {
                    let bech = params2bech(output.0[0], &output.0[1..21]).unwrap();
                    let coin_id = output.1.to_object(py);
                    let amount = output.2.to_object(py);
                    (bech.to_string().to_object(py), coin_id, amount).to_object(py)
                })
                .collect::<Vec<PyObject>>();
            dict.set_item("outputs", outputs)?;
        }
        dict.set_item("gas_price", self.gas_price)?;
        dict.set_item("gas_amount", self.gas_amount)?;
        dict.set_item("message_type", self.message.to_type())?;
        dict.set_item("message", self.message.to_string())?;
        {
            let mut vec = vec![];
            let signature = match tx.signature.as_ref() {
                Some(signature) => Some(
                    signature
                        .iter()
                        .map(|sign| {
                            vec.clear();
                            signature_to_bytes(sign, &mut vec);
                            hex::encode(&vec)
                        })
                        .collect::<Vec<String>>(),
                ),
                None => None,
            };
            dict.set_item("signature", signature)?;
        }
        // dict.set_item("hash_locked", )?; REMOVED
        // dict.set_item("recode_flag", )?; REMOVED
        dict.set_item("create_time", self.create_time)?;
        let body_size = tx.body.get_size();
        dict.set_item("size", body_size)?;
        dict.set_item("total_size", match tx.get_signature_size() {
            Ok(sign_size) => Some(sign_size + body_size),
            Err(_) => None::<usize>,
        })?;
        dict.set_item("hex", hex::encode(tx.body.to_bytes()))?;
        Ok(dict.to_object(py))
    }
}

// use on inner (not for Pyo3)
impl PyTx {
    pub fn from_recoded(py: Python, tx: TxRecoded) -> PyResult<PyTx> {
        // convert from Tx to PyTx (moved)
        let inputs: _ = PyCell::new(py, PyTxInputs {
            iter_index: None,
            inputs: tx.body.inputs,
        })?;
        let outputs: _ = PyCell::new(py, PyTxOutputs {
            iter_index: None,
            outputs: tx.body.outputs,
        })?;

        let signature: &PyCell<PySignature> = PyCell::new(py, PySignature { signs: tx.signature })?;
        Ok(PyTx {
            version: tx.body.version,
            txtype: tx.body.txtype,
            time: tx.body.time,
            deadline: tx.body.deadline,
            inputs: inputs.into(),
            outputs: outputs.into(),
            gas_price: tx.body.gas_price,
            gas_amount: tx.body.gas_amount,
            message: tx.body.message,
            signature: Some(signature.into()),
            inputs_cache: None,
            verified_list: None,
            create_time: get_current_time(),
        })
    }

    pub fn from_verifiable(py: Python, tx: TxVerifiable) -> PyResult<PyTx> {
        // convert from Tx to PyTx (moved)
        let inputs: _ = PyCell::new(py, PyTxInputs {
            iter_index: None,
            inputs: tx.body.inputs,
        })?;
        let outputs: _ = PyCell::new(py, PyTxOutputs {
            iter_index: None,
            outputs: tx.body.outputs,
        })?;
        let signature: &PyCell<PySignature> = PyCell::new(py, PySignature { signs: tx.signature })?;

        Ok(PyTx {
            version: tx.body.version,
            txtype: tx.body.txtype,
            time: tx.body.time,
            deadline: tx.body.deadline,
            inputs: inputs.into(),
            outputs: outputs.into(),
            gas_price: tx.body.gas_price,
            gas_amount: tx.body.gas_amount,
            message: tx.body.message,
            signature: Some(signature.into()),
            inputs_cache: Some(tx.inputs_cache),
            verified_list: None,
            create_time: get_current_time(),
        })
    }

    pub fn clone_to_manual(&self, py: Python) -> TxManual {
        // covert PyTx to manual tx
        let cell: &PyCell<PyTxInputs> = self.inputs.as_ref(py);
        let inputs_rc: PyRef<PyTxInputs> = cell.borrow();
        let cell: &PyCell<PyTxOutputs> = self.outputs.as_ref(py);
        let output_rc: PyRef<PyTxOutputs> = cell.borrow();
        let signature = self.signature.as_ref().map(|sign| {
            let cell: &PyCell<PySignature> = sign.as_ref(py);
            let sign_rc: PyRef<PySignature> = cell.borrow();
            sign_rc.signs.to_vec()
        });
        let inputs_cache = self.inputs_cache.clone();

        let body = TxBody {
            version: self.version,
            txtype: self.txtype.clone(),
            time: self.time,
            deadline: self.deadline,
            inputs: inputs_rc.inputs.clone(),
            outputs: output_rc.outputs.clone(),
            gas_price: self.gas_price,
            gas_amount: self.gas_amount,
            message: self.message.clone(),
        };
        TxManual {
            body,
            signature,
            inputs_cache,
        }
    }

    pub fn clone_to_verifiable(&self, py: Python) -> PyResult<TxVerifiable> {
        // covert PyTx to verifiable tx
        let cell: &PyCell<PyTxInputs> = self.inputs.as_ref(py);
        let inputs_rc: PyRef<PyTxInputs> = cell.borrow();
        let cell: &PyCell<PyTxOutputs> = self.outputs.as_ref(py);
        let output_rc: PyRef<PyTxOutputs> = cell.borrow();
        let signature = match self.signature.as_ref() {
            Some(signature) => {
                let cell: &PyCell<PySignature> = signature.as_ref(py);
                let signature_rc: PyRef<PySignature> = cell.borrow();
                signature_rc.signs.to_vec()
            },
            None => {
                return Err(ValueError::py_err(
                    "cannot clone to VerifiableTx because signature is none",
                ))
            },
        };
        let inputs_cache = self
            .inputs_cache
            .as_ref()
            .ok_or(ValueError::py_err(
                "cannot clone to VerifiableTx because inputs_cache is none",
            ))?
            .clone();

        let body = TxBody {
            version: self.version,
            txtype: self.txtype.clone(),
            time: self.time,
            deadline: self.deadline,
            inputs: inputs_rc.inputs.clone(),
            outputs: output_rc.outputs.clone(),
            gas_price: self.gas_price,
            gas_amount: self.gas_amount,
            message: self.message.clone(),
        };
        Ok(TxVerifiable {
            hash: U256::from(body.hash().as_slice()),
            body,
            signature,
            inputs_cache,
        })
    }

    pub fn clone_to_body(&self, py: Python) -> TxBody {
        // covert PyTx to tx body
        let cell: &PyCell<PyTxInputs> = self.inputs.as_ref(py);
        let inputs_rc: PyRef<PyTxInputs> = cell.borrow();
        let cell: &PyCell<PyTxOutputs> = self.outputs.as_ref(py);
        let output_rc: PyRef<PyTxOutputs> = cell.borrow();
        TxBody {
            version: self.version,
            txtype: self.txtype.clone(),
            time: self.time,
            deadline: self.deadline,
            inputs: inputs_rc.inputs.clone(),
            outputs: output_rc.outputs.clone(),
            gas_price: self.gas_price,
            gas_amount: self.gas_amount,
            message: self.message.clone(),
        }
    }
}
