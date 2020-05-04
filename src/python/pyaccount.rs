use crate::balance::*;
use crate::utils::u256_to_bytes;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};
use pyo3::PyIterProtocol;

#[pyclass]
pub struct PyBalance {
    pub iter_index: Option<usize>,
    pub balance: Balances,
}

#[pymethods]
impl PyBalance {
    #[new]
    fn new(balance: Option<&PyAny>) -> PyResult<Self> {
        // get initial balance [[coinId, amount], ...]
        match balance {
            Some(balance) => {
                let balance = Balances(
                    balance
                        .extract::<Vec<(u32, i64)>>()?
                        .into_iter()
                        .map(|(coin_id, amount)| Balance { coin_id, amount })
                        .collect(),
                );
                Ok(PyBalance {
                    iter_index: None,
                    balance,
                })
            },
            None => Ok(PyBalance {
                iter_index: None,
                balance: Balances(vec![]),
            }),
        }
    }

    fn get_amount(&self, coin_id: u32) -> i64 {
        self.balance.get_amount_by(coin_id).unwrap_or(0)
    }

    fn add_amount(&mut self, coin_id: u32, amount: i64) {
        // sub by minus amount
        match self.balance.0.iter_mut().find(|_b| _b.coin_id == coin_id) {
            Some(balance) => balance.amount += amount,
            None => self.balance.0.push(Balance { coin_id, amount }),
        }
    }

    fn sub_amount(&mut self, coin_id: u32, amount: i64) {
        self.add_amount(coin_id, amount * -1);
    }

    fn marge_balance(&mut self, balance: PyRef<PyBalance>) {
        for balance in balance.balance.0.iter() {
            self.balance.add_balance(&balance);
        }
        self.balance.compaction();
    }
}

#[pyproto]
impl PyIterProtocol for PyBalance {
    fn __iter__(mut slf: PyRefMut<Self>) -> PyResult<PyObject> {
        let py = unsafe { Python::assume_gil_acquired() };
        slf.balance.compaction();
        slf.iter_index = Some(0);
        Ok(slf.into_py(py))
    }

    fn __next__(mut slf: PyRefMut<Self>) -> PyResult<Option<PyObject>> {
        let py = unsafe { Python::assume_gil_acquired() };
        let index = slf.iter_index.unwrap();
        *slf.iter_index.as_mut().unwrap() += 1; // increment iter_index
        match slf.balance.0.get(index) {
            Some(balance) => {
                let coin_id = balance.coin_id.to_object(py);
                let amount = balance.amount.to_object(py);
                Ok(Some(PyTuple::new(py, &[coin_id, amount]).to_object(py)))
            },
            None => {
                // reset iter_index
                slf.iter_index = None;
                Ok(None)
            },
        }
    }
}

#[pyclass]
pub struct PyMovement {
    pub movement: BalanceMovement,
}

#[pymethods]
impl PyMovement {
    #[getter]
    fn get_hash(&self, py: Python) -> PyObject {
        let hash = u256_to_bytes(&self.movement.hash);
        PyBytes::new(py, hash.as_ref()).to_object(py)
    }

    #[getter]
    fn get_type(&self) -> String {
        format!("{:?}", self.movement.get_movement_type())
    }

    #[getter]
    fn get_movement(&self, py: Python) -> PyObject {
        let movement = self.movement.get_account_movement();
        let movement = movement
            .into_iter()
            .map(|(account_id, balance)| {
                let account_id = account_id.to_object(py);
                let balances = Py::new(py, PyBalance {
                    iter_index: None,
                    balance,
                })
                .unwrap()
                .to_object(py);
                PyTuple::new(py, &[account_id, balances]).to_object(py)
            })
            .collect::<Vec<PyObject>>();
        PyTuple::new(py, &movement).to_object(py)
    }

    #[getter]
    fn get_fee(&self) -> PyBalance {
        PyBalance {
            iter_index: None,
            balance: self.movement.fee.clone(),
        }
    }
}

#[pyclass]
pub struct PyAccount {
    #[pyo3(get)]
    pub account_id: u32,
    pub confirmed: Py<PyBalance>,
    pub unconfirmed: Py<PyBalance>,
}

#[pymethods]
impl PyAccount {
    #[getter]
    fn get_confirmed(&self, py: Python) -> PyObject {
        self.confirmed.to_object(py)
    }

    #[getter]
    fn get_unconfirmed(&self, py: Python) -> PyObject {
        self.unconfirmed.to_object(py)
    }
}
