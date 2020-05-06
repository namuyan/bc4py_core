from typing import Tuple, List, Sequence, Optional, Iterator

"""
Address
"""

class PyAddress:
    version: int
    def __init__(self, addr: bytes) -> None: ...
    @classmethod
    def from_string(cls, string: str) -> None: ...
    def to_string(self, hrp: str) -> str: ...
    def identifier(self) -> bytes:
        """20 bytes"""
    def binary(self) -> bytes:
        """21 bytes"""


"""
Tx
"""


TxInput = Tuple[bytes, int]
TxOutput = Tuple[bytes, int, int]


class PyTxInputs:
    def __init__(self, inputs: Sequence[TxInput]) -> None: ...
    def __iter__(self) -> Iterator[TxInput]: ...
    def len(self) -> int: ...
    def get(self, index: int) -> Optional[TxInput]: ...
    def add(self, hash: bytes, index: int) -> None: ...
    def push(self, unspent: PyUnspent) -> None: ...
    def pop(self, index: Optional[int]) -> TxInput: ...
    def extend(self, value: PyTxInputs) -> None: ...
    def clear(self) -> None: ...


class PyTxOutputs:
    def __init__(self, outputs: Sequence[TxOutput]) -> None: ...
    def __iter__(self) -> Iterator[TxOutput]: ...
    def len(self) -> int: ...
    def get(self, index: int) -> Optional[TxOutput]: ...
    def add(self, addr: bytes, coin_id: int, amount: int) -> None: ...
    def pop(self, index: Optional[int]) -> TxOutput: ...
    def extend(self, value: PyTxOutputs) -> None: ...
    def clear(self) -> None: ...


class PyTx:
    version: int
    txtype: int
    time: int
    deadline: int
    inputs: PyTxInputs
    outputs: PyTxOutputs
    gas_price: int
    gas_amount: int
    signature: Optional[PySignature]

    def __init__(
            self,
            version: int,
            txtype: int,
            time: int,
            deadline: int,
            inputs: PyTxInputs,
            outputs: PyTxOutputs,
            gas_price: int,
            gas_amount: int,
            message_type: int,
            message: Optional[bytes],
    ) -> None: ...
    def get_message_type(self) -> int: ...
    def get_message_body(self) -> bytes: ...
    def replace_message(self, value: bytes) -> None: ...
    def fill_input_cache(self, chain: PyChain) -> None: ...
    def get_input_cache(self) -> Optional[PyTxOutputs]: ...


"""
Block
"""

class PyHeader:
    version: int
    previous_hash: bytes
    merkleroot: bytes
    time: int
    bits: int
    nonce: int

    def __init__(
            self,
            version: int,
            previous_hash: bytes,
            merkleroot: bytes,
            time: int,
            bits: int,
            nonce: int
    ) -> None: ...
    @classmethod
    def from_binary(cls, binary: bytes) -> None: ...
    def to_binary(self) -> bytes: ...
    def hash(self) -> bytes: ...


class PyBlock:
    # meta
    work_hash: Optional[bytes]
    height: int
    flag: int
    bias: int
    # header
    header: PyHeader
    # body
    txs_hash: List[bytes]

    def __init__(
            self,
            height: int,
            flag: int,
            bias: float,
            header: PyHeader,
            txs_hash: Sequence[bytes]
    ) -> None: ...
    def update_merkleroot(self) -> None: ...


"""
Signature
"""

class PySignature:
    SINGLE: int = 0
    AGGREGATE: int = 1
    THRESHOLD: int = 2

    def __init__(self) -> None: ...
    def get_binary_list(self) -> Sequence[bytes]: ...
    def add_from_params(self, stype: int, params: Sequence[bytes]) -> None: ...
    def add_from_binary(self, binary: bytes) -> None: ...


"""
Unspent
"""

class PyUnspent:
    txhash: bytes
    txindex: int
    address: PyAddress
    coin_id: int
    amount: int

"""
Account
"""

class PyBalance:
    def __init__(self, balance: Optional[Sequence[Tuple[int, int]]]) -> None: ...
    def __iter__(self) -> Iterator[Tuple[int, int]]: ...
    def get_amount(self, coin_id: int) -> int: ...
    def add_amount(self, coin_id: int, amount: int) -> None: ...
    def marge_balance(self, balance: PyBalance) -> None: ...


class PyMovement:
    hash: bytes
    type: str
    height: Optional[int]
    position: Optional[int]
    movement: Sequence[Tuple[int, PyBalance]]
    fee: PyBalance


class PyAccount:
    account_id: int
    confirmed: PyBalance
    unconfirmed: PyBalance


"""
Chain
"""


class PyChain:
    is_closed: bool

    def __init__(
            self,
            root_dir: str,
            sk: Optional[bytes],
            deadline: int,
            tx_index: bool,
            addr_index: bool
    ) -> None: ...
    def push_new_block(self, block: PyBlock, txs: Sequence[PyTx]) -> None: ...
    def push_unconfirmed(self, tx: PyTx) -> None: ...
    def get_block(self, hash: bytes) -> Optional[PyBlock]: ...
    def get_tx(self, hash: bytes) -> Optional[PyTx]: ...
    def get_account_balance(self, account_id: int, confirm: int) -> PyAccount: ...
    def calc_unspent_by_amount(self, balances: PyBalance) -> Sequence[PyUnspent]: ...
    def list_unspent_by_addr(self, addrs: Sequence[PyAddress], page: int, size: int) -> Sequence[PyUnspent]: ...
    def list_account_movement(self, page: int, size: int) -> Sequence[PyMovement]: ...
    def close(self) -> None: ...
