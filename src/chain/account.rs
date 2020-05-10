use crate::balance::*;
use crate::block::Block;
use crate::chain::tables::{TableCursor, Tables};
use crate::tx::TxVerifiable;
use crate::utils::*;
use hdwallet::traits::{Deserialize, Serialize};
use hdwallet::{error::Error, ExtendedPrivKey, ExtendedPubKey, KeyIndex};
use std::slice::Iter;

type Address = [u8; 21];
const PRE_FETCH_ADDR_LEN: usize = 25;
const PRE_FETCH_ACCOUNT_LEN: usize = 20;
const BIP32_HARDEN: u32 = 0x80000000;

/// listen account related all address, don't require secret key.
/// derive `m/44'/CoinType'/account'/is_inner/index` from root_key.
#[derive(Debug, PartialEq)]
pub struct Account {
    pub account_id: u32,      // = AccountBuilder.accounts position
    root_key: ExtendedPubKey, // m/44'/CoinType'/account_id'
    unused_index: usize,      // user's generated address index on outer
    listen_inner: Vec<Address>,
    listen_outer: Vec<Address>,
    pub balance: Balances,
    visible: bool,

    // for detect account status change
    changed: bool,
}

impl Account {
    fn new(account_id: u32, visible: bool, root_key: ExtendedPubKey) -> Result<Self, Error> {
        let listen_inner = Vec::with_capacity(PRE_FETCH_ADDR_LEN);
        let listen_outer = Vec::with_capacity(PRE_FETCH_ADDR_LEN);
        let mut account = Account {
            account_id,
            root_key,
            unused_index: 0,
            listen_inner,
            listen_outer,
            balance: Balances(vec![Balance {
                coin_id: 0,
                amount: 0,
            }]),
            visible,
            changed: true,
        };

        // fill
        for index in 0..PRE_FETCH_ADDR_LEN {
            let index = index as u32;
            let addr = account.derive_address(true, index)?;
            account.listen_inner.push(addr);
            let addr = account.derive_address(false, index)?;
            account.listen_outer.push(addr);
        }
        Ok(account)
    }

    fn from_bytes(account_id: u32, bytes: &[u8]) -> Result<Self, Error> {
        // [root_key 33+32b][unused_index u32][inner_len u32][outer_len u32][visible u8]
        // [balance_len u32][coinId u32, amount i64]..

        // static
        let root_key = ExtendedPubKey::deserialize(&bytes[0..33 + 32])?;
        let unused_index = bytes_to_u32(&bytes[65..65 + 4]) as usize;
        let inner_len = bytes_to_u32(&bytes[69..69 + 4]) as usize;
        let outer_len = bytes_to_u32(&bytes[73..73 + 4]) as usize;
        let visible = 0 < bytes[77];
        let balance_len = bytes_to_u32(&bytes[78..78 + 4]) as usize;

        // listen inner
        let inner_key = root_key.derive_public_key(KeyIndex::Normal(1))?;
        let listen_inner: _ = (0..inner_len as u32)
            .map(|index| {
                let key = inner_key.derive_public_key(KeyIndex::Normal(index)).unwrap();
                sha256ripemd160(0, key.public_key.serialize().as_ref())
            })
            .collect::<Vec<Address>>();

        // listen outer
        let outer_key = root_key.derive_public_key(KeyIndex::Normal(0))?;
        let listen_outer: _ = (0..outer_len as u32)
            .map(|index| {
                let key = outer_key.derive_public_key(KeyIndex::Normal(index)).unwrap();
                sha256ripemd160(0, key.public_key.serialize().as_ref())
            })
            .collect::<Vec<Address>>();

        // balance
        let mut balance = Balances(Vec::with_capacity(balance_len));
        let mut pos = 82;
        for _ in 0..balance_len {
            let coin_id = bytes_to_u32(&bytes[pos..pos + 4]);
            let amount = bytes_to_u64(&bytes[pos + 4..pos + 4 + 8]);
            pos += 12;
            balance.add(coin_id, amount);
        }

        // check
        assert_eq!(pos, bytes.len());
        Ok(Account {
            account_id,
            root_key,
            unused_index,
            listen_inner,
            listen_outer,
            balance,
            visible,
            changed: false,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        // [root_key 33+32b][unused_index u32][inner_len u32][outer_len u32][visible u8]
        // [balance_len u32][coinId u32, amount i64]..
        let mut vec = Vec::with_capacity(33 + 32 + 4 * 3 + 1 + 4);

        // static
        vec.extend_from_slice(&self.root_key.serialize());
        assert_eq!(vec.len(), 33 + 32);
        vec.extend_from_slice(&u32_to_bytes(self.unused_index as u32));
        vec.extend_from_slice(&u32_to_bytes(self.listen_inner.len() as u32));
        vec.extend_from_slice(&u32_to_bytes(self.listen_outer.len() as u32));
        vec.push(if self.visible { 1 } else { 0 });
        vec.extend_from_slice(&u32_to_bytes(self.balance.0.len() as u32));

        // balance
        vec.reserve(self.balance.0.len() * (4 + 8));
        for balance in self.balance.0.iter() {
            balance.to_bytes(&mut vec);
        }

        // success
        vec
    }

    fn check_and_expand_listen(&mut self, addr: &Address) -> Result<Option<bool>, Error> {
        // check inner
        if self.listen_inner.contains(addr) {
            let addr_index = self.listen_inner.iter().position(|_addr| _addr == addr).unwrap();
            let next_index = self.listen_inner.len();

            // expand
            if next_index < addr_index + PRE_FETCH_ADDR_LEN {
                for index in next_index..(addr_index + PRE_FETCH_ADDR_LEN) {
                    let addr = self.derive_address(true, index as u32)?;
                    self.listen_inner.push(addr);
                    self.changed = true;
                }
            }
            // return
            return Ok(Some(true));
        }

        // check outer
        if self.listen_outer.contains(addr) {
            let addr_index = self.listen_outer.iter().position(|_addr| _addr == addr).unwrap();
            let next_index = self.listen_outer.len();

            // expand
            if next_index < addr_index + PRE_FETCH_ADDR_LEN {
                for index in next_index..(addr_index + PRE_FETCH_ADDR_LEN) {
                    let addr = self.derive_address(false, index as u32)?;
                    self.listen_outer.push(addr);
                    self.changed = true;
                }
            }
            // return
            return Ok(Some(false));
        }

        // not found any relatives
        Ok(None)
    }

    fn get_address_path(&self, addr: &Address) -> Option<(bool, u32)> {
        // return (is_inner, index)
        let index = self.listen_inner.iter().position(|_addr| _addr == addr);
        if index.is_some() {
            return Some((true, index.unwrap() as u32));
        }
        let index = self.listen_outer.iter().position(|_addr| _addr == addr);
        if index.is_some() {
            return Some((false, index.unwrap() as u32));
        }
        None
    }

    fn derive_address(&self, is_inner: bool, index: u32) -> Result<Address, Error> {
        let change = if is_inner { 1 } else { 0 };
        let key = self
            .root_key
            .derive_public_key(KeyIndex::Normal(change))?
            .derive_public_key(KeyIndex::Normal(index))?;
        let addr = sha256ripemd160(0, key.public_key.serialize().as_ref());
        Ok(addr)
    }

    #[inline]
    fn add_balance(&mut self, coin_id: u32, amount: i64) {
        // note: update after by `write_account_state`
        match self.balance.0.iter_mut().find(|_b| _b.coin_id == coin_id) {
            Some(balance) => balance.amount += amount,
            None => self.balance.0.push(Balance { coin_id, amount }),
        }
        self.changed = true;
    }

    fn add_balances_and_update(&mut self, balances: &Balances) {
        for balance in balances.0.iter() {
            self.add_balance(balance.coin_id, balance.amount);
        }
        self.changed = true;
    }

    pub fn get_new_address(&mut self, new: bool, cur: &mut TableCursor) -> Result<Address, Error> {
        // return a address generated before but no incoming if `new` is false
        let index = if new {
            self.unused_index
        } else {
            if self.unused_index == 0 {
                self.unused_index
            } else {
                self.unused_index - 1
            }
        };

        // get addr from outer
        match self.listen_outer.get(index) {
            Some(addr) => {
                let addr = addr.clone();
                if new {
                    // new address
                    self.unused_index += 1;
                    self.expand_outer_size(1).unwrap();

                    // update only this account
                    cur.write_account_state(self.account_id, &self.to_bytes())
                        .unwrap();
                }
                Ok(addr)
            },
            None => {
                // expand `listen_outer` to `unused_index`
                self.expand_outer_size(PRE_FETCH_ADDR_LEN as u32).unwrap();
                // retry
                self.get_new_address(new, cur)
            },
        }
    }

    fn expand_outer_size(&mut self, size: u32) -> Result<(), Error> {
        // expand outer to enough size
        let last_index = self.listen_outer.len() as u32;
        for index in last_index..last_index + size {
            let addr = self.derive_address(false, index)?;
            self.listen_outer.push(addr);
        }
        self.changed = true;
        Ok(())
    }

    fn update_unused_index(&mut self, addr: &Address) {
        // check incoming address used
        match self.listen_outer.iter().position(|_addr| _addr == addr) {
            Some(addr_index) => {
                // find incoming on unused_index
                if self.unused_index <= addr_index {
                    self.unused_index = addr_index + 1;
                    self.changed = true;
                }
            },
            None => (),
        }
    }
}

pub struct AccountBuilder {
    root_key: Option<ExtendedPrivKey>, // m/44'/CoinType'
    accounts: Vec<Account>,
}

impl AccountBuilder {
    pub fn new(sk: &[u8], cur: &mut TableCursor) -> Result<Self, Error> {
        assert_eq!(sk.len(), 32 + 32);
        // init account
        let initial_len = 50;
        let sk = ExtendedPrivKey::deserialize(sk)?;
        let mut accounts = Vec::with_capacity(initial_len);

        // fill
        for index in 0..initial_len {
            let account_id = index as u32;
            let key_index = KeyIndex::Hardened(BIP32_HARDEN + account_id);
            let key = sk.derive_private_key(key_index)?;
            let root_key = ExtendedPubKey::from_private_key(&key);
            let account = Account::new(account_id, false, root_key)?;
            accounts.push(account);
        }
        let mut accounts = AccountBuilder {
            root_key: Some(sk),
            accounts,
        };
        // update accounts
        accounts.update_all_account_status(cur);
        Ok(accounts)
    }

    pub fn restore_from_tables(tables: &Tables, sk: &Option<Vec<u8>>) -> Result<Self, Error> {
        // note: check root_key is same with table's key
        let root_key = match sk {
            Some(sk) => Some(ExtendedPrivKey::deserialize(sk)?),
            None => None,
        };

        let mut accounts = vec![];
        for (key, value) in tables.read_account_iter() {
            let account_id = bytes_to_u32(&key);
            accounts.push(Account::from_bytes(account_id, &value)?);
        }

        Ok(AccountBuilder { root_key, accounts })
    }

    pub fn get_new_account<'a>(&'a mut self, cur: &mut TableCursor) -> Result<&'a mut Account, String> {
        match self
            .accounts
            .iter()
            .position(|_account| _account.visible == false)
        {
            Some(account_id) => {
                // expand if too few capacity
                if self.root_key.is_some() && self.accounts.len() < account_id + PRE_FETCH_ACCOUNT_LEN {
                    self.expand_account_capacity().unwrap();
                }

                // set visible flag to account
                let account = self.accounts.get_mut(account_id).unwrap();
                account.visible = true;

                // update one new account
                cur.write_account_state(account.account_id, &account.to_bytes())
                    .unwrap();

                // success
                Ok(account)
            },
            None => {
                if self.root_key.is_some() {
                    // fill capacity
                    for _ in 0..PRE_FETCH_ACCOUNT_LEN {
                        self.expand_account_capacity().unwrap();
                    }
                    // retry
                    // note: accounts update reflect by ok return
                    self.get_new_account(cur)
                } else {
                    Err("cannot get account because capacity is 0 & root_key is None".to_owned())
                }
            },
        }
    }

    pub fn get_account_ref(&self, account_id: u32) -> Result<&Account, String> {
        match self
            .accounts
            .iter()
            .find(|_account| _account.account_id == account_id)
        {
            Some(account) => Ok(account),
            None => Err(format!("not found account_id {}", account_id)),
        }
    }

    pub fn get_path_from_addr(&self, addr: &Address) -> Option<(u32, bool, u32)> {
        // return (account_id, is_inner, index)
        for account in self.accounts.iter() {
            match account.get_address_path(addr) {
                Some((is_inner, index)) => {
                    return Some((account.account_id, is_inner, index));
                },
                None => continue,
            }
        }
        None
    }

    pub fn update_by_tx(&mut self, tx: &TxVerifiable, cur: &mut TableCursor) -> Result<(), Error> {
        // use when accept unconfirmed tx
        // note: update `unused_index` and `listen_*`
        let inputs_cache = &tx.inputs_cache;
        let body = &tx.body;

        // calc fee by `incoming - outgoing`
        let mut fee = Balances(Vec::with_capacity(1));
        inputs_cache
            .iter()
            .map(|output| Balance {
                coin_id: output.1,
                amount: output.2 as i64,
            })
            .for_each(|balance| fee.add_balance(&balance));
        body.outputs
            .iter()
            .map(|output| Balance {
                coin_id: output.1,
                amount: output.2 as i64,
            })
            .for_each(|balance| fee.sub_balance(&balance));
        fee.compaction();
        assert_eq!(fee.sum(), body.gas_amount * body.gas_price as i64);
        let mut movement = BalanceMovement::new(tx.hash, fee);

        // inputs
        for inputs_cache in inputs_cache.iter() {
            let addr = &inputs_cache.0;
            for account in self.accounts.iter_mut() {
                if account.check_and_expand_listen(addr)?.is_some() {
                    account.update_unused_index(addr);
                    movement.push_outgoing(inputs_cache.1, inputs_cache.2);
                    break;
                }
            }
        }

        // outputs
        for output in body.outputs.iter() {
            let addr = &output.0;
            for account in self.accounts.iter_mut() {
                match account.check_and_expand_listen(addr)? {
                    Some(is_inner) => {
                        account.update_unused_index(addr);
                        movement.push_incoming(account.account_id, output.1, output.2, is_inner);
                        break;
                    },
                    None => (),
                }
            }
        }

        // write movement as cache if need
        // ignore if no move in the movement
        if movement.get_movement_type() != MovementType::Nothing {
            cur.write_temporary_movement(&movement).unwrap();
        }

        // update accounts
        self.update_all_account_status(cur);

        // success
        Ok(())
    }

    pub fn finalize_block(&mut self, block: &Block, cur: &mut TableCursor) -> Result<(), String> {
        // use when finalize block to tables
        // note: update `balance` and `movement`
        for (position, hash) in block.txs_hash.iter().enumerate() {
            // update account balance by movement recoded before
            match cur.tables.read_temporary_movement(hash)? {
                Some(movement) => {
                    for (account_id, balances) in movement.get_account_movement() {
                        self.accounts
                            .get_mut(account_id as usize)
                            .expect("already known account but?")
                            .add_balances_and_update(&balances);
                    }
                },
                None => continue, // skip next update because no account tx
            };

            // update movement state (if need)
            cur.update_movement_status(hash, block.height, position as u32)?;
        }

        // update accounts
        self.update_all_account_status(cur);

        // success
        Ok(())
    }

    pub fn is_account_address(&self, addr: &Address) -> bool {
        for account in self.accounts.iter() {
            if account.listen_inner.contains(addr) || account.listen_outer.contains(addr) {
                return true;
            }
        }
        false
    }

    pub fn get_account_addr_iter(&self) -> AccountAddrIter {
        AccountAddrIter {
            account_iter: self.accounts.iter(),
            inner_iter: None,
            outer_iter: None,
        }
    }

    fn expand_account_capacity(&mut self) -> Result<(), Error> {
        // add a invisible account for listen
        assert!(self.root_key.is_some());
        let last = self.accounts.last().unwrap();
        let account_id = last.account_id + 1;
        let key = self
            .root_key
            .as_ref()
            .unwrap()
            .derive_private_key(KeyIndex::Hardened(BIP32_HARDEN + account_id))?;
        let root_key = ExtendedPubKey::from_private_key(&key);
        // note: new account isn't updated yet
        let new_account = Account::new(account_id, false, root_key)?;
        self.accounts.push(new_account);
        Ok(())
    }

    fn update_all_account_status(&mut self, cur: &mut TableCursor) {
        // refract status to tables at once
        // execute after account edit
        for account in self.accounts.iter_mut() {
            if account.changed {
                cur.write_account_state(account.account_id, &account.to_bytes())
                    .unwrap();
                account.changed = false;
            }
        }
    }
}

/// iterate all account address
pub struct AccountAddrIter<'a> {
    account_iter: Iter<'a, Account>,
    inner_iter: Option<Iter<'a, Address>>,
    outer_iter: Option<Iter<'a, Address>>,
}

impl Iterator for AccountAddrIter<'_> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.inner_iter.is_some() {
                match self.inner_iter.as_mut().unwrap().next() {
                    Some(address) => return Some(*address),
                    None => self.inner_iter = None,
                }
            } else if self.outer_iter.is_some() {
                match self.outer_iter.as_mut().unwrap().next() {
                    Some(address) => return Some(*address),
                    None => self.outer_iter = None,
                }
            } else {
                match self.account_iter.next() {
                    Some(account) => {
                        self.inner_iter = Some(account.listen_inner.iter());
                        self.outer_iter = Some(account.listen_outer.iter());
                    },
                    None => return None,
                }
            }
        }
    }
}

#[allow(unused_imports)]
#[cfg(test)]
mod account {
    use crate::chain::account::Account;
    use hdwallet::traits::Deserialize;
    use hdwallet::{ExtendedPrivKey, ExtendedPubKey};

    #[test]
    fn encode_decode() {
        let account_id = 1;
        let prv = ExtendedPrivKey::random().unwrap();
        let root_key = ExtendedPubKey::from_private_key(&prv);
        let mut account = Account::new(account_id, false, root_key).unwrap();

        account.add_balance(0, 100);
        account.add_balance(0, 200);
        account.add_balance(1, 300);
        account.unused_index = 3;

        let bytes = account.to_bytes();
        let new_account = Account::from_bytes(account_id, &bytes).unwrap();
        assert_eq!(new_account, account);
    }
}
