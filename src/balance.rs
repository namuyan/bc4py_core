use crate::utils::*;
use bigint::U256;
use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq)]
pub struct Balance {
    pub coin_id: u32,
    pub amount: i64, // allow minus balance
}

impl Balance {
    #[inline]
    pub fn to_bytes(&self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&u32_to_bytes(self.coin_id));
        vec.extend_from_slice(&i64_to_bytes(self.amount));
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 4 + 8);
        let coin_id = bytes_to_u32(&bytes[0..4]);
        let amount = bytes_to_i64(&bytes[4..4 + 8]);
        Self { coin_id, amount }
    }
}

#[derive(Clone, Debug)]
pub struct Balances(pub Vec<Balance>);

impl PartialEq for Balances {
    fn eq(&self, other: &Self) -> bool {
        for balance in self.0.iter() {
            if other.0.iter().find(|_b| _b == &balance).is_none() {
                return false;
            }
        }
        true
    }
}

impl PartialOrd for Balances {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // get (self - other) balance
        let mut balances = self.clone();
        other.0.iter().for_each(|_balance| balances.sub_balance(_balance));
        balances.compaction();
        // check all plus or minus
        let mut all_lesser = true;
        let mut all_greater = true;
        for balance in balances.0.iter() {
            if 0 < balance.amount {
                all_lesser = false;
            }
            if 0 > balance.amount {
                all_greater = false;
            }
        }
        // return ordering type
        if all_lesser && all_greater {
            Some(Ordering::Equal) // self = other
        } else if all_lesser {
            Some(Ordering::Less) // self < other
        } else if all_greater {
            Some(Ordering::Greater) // self > other
        } else {
            None // cannot define lesser or greater
        }
    }
}

impl Balances {
    /// remove zero balance
    pub fn compaction(&mut self) {
        self.0.drain_filter(|balance| balance.amount == 0).for_each(drop);
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    /// sum up all amount regardless coinId
    pub fn sum(&self) -> i64 {
        self.0.iter().map(|balance| balance.amount).sum()
    }

    pub fn get_amount_by(&self, coin_id: u32) -> Option<i64> {
        match self.0.iter().find(|b| b.coin_id == coin_id) {
            Some(b) => Some(b.amount),
            None => None,
        }
    }

    pub fn add(&mut self, coin_id: u32, amount: u64) {
        let amount = amount as i64;
        match self.0.iter_mut().find(|_b| _b.coin_id == coin_id) {
            Some(balance) => balance.amount += amount,
            None => self.0.push(Balance { coin_id, amount }),
        }
    }

    pub fn sub(&mut self, coin_id: u32, amount: u64) {
        let amount = amount as i64 * -1; // minus
        match self.0.iter_mut().find(|_b| _b.coin_id == coin_id) {
            Some(balance) => balance.amount += amount,
            None => self.0.push(Balance { coin_id, amount }),
        }
    }

    pub fn add_balance(&mut self, other: &Balance) {
        match self.0.iter_mut().find(|_b| _b.coin_id == other.coin_id) {
            Some(_balance) => _balance.amount += other.amount,
            None => self.0.push(other.clone()),
        }
    }

    pub fn sub_balance(&mut self, other: &Balance) {
        match self.0.iter_mut().find(|_b| _b.coin_id == other.coin_id) {
            Some(_balance) => _balance.amount -= other.amount,
            None => self.0.push(Balance {
                coin_id: other.coin_id,
                amount: other.amount * -1,
            }),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum MovementType {
    Nothing, // no movement or inner transfer
    Sending, // send to guest address
    Receive, // receive from guest
    Complex, // send and receive by some accounts
}

pub struct BalanceMovement {
    pub hash: U256,    // txhash
    pub fee: Balances, // note: unused
    outgoing: Balances,
    incoming: Vec<(u32, bool, Balance)>, // (accountId, isInner, balance)
}

impl BalanceMovement {
    pub fn new(hash: U256, fee: Balances) -> Self {
        Self {
            hash,
            fee,
            outgoing: Balances(vec![]),
            incoming: vec![],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        // [txhash 32b][outgoing_len u32][incoming_len u32][fee_len u32]
        // ~[outgoing 12b].. [incoming 4+1+12b].. [fee 12b]..
        let hash = U256::from(&bytes[0..32]);
        let outgoing_len = bytes_to_u32(&bytes[32..32 + 4]) as usize;
        let incoming_len = bytes_to_u32(&bytes[36..36 + 4]) as usize;
        let fee_len = bytes_to_u32(&bytes[40..40 + 4]) as usize;
        let mut outgoing = Balances(Vec::with_capacity(outgoing_len));
        let mut incoming = Vec::with_capacity(incoming_len);
        let mut fee = Balances(Vec::with_capacity(fee_len));
        let mut pos = 44;
        for _ in 0..outgoing_len {
            outgoing.0.push(Balance::from_bytes(&bytes[pos..pos + 12]));
            pos += 12;
        }
        for _ in 0..incoming_len {
            let account_id = bytes_to_u32(&bytes[pos..pos + 4]);
            let is_inner = 0 < bytes[pos + 4];
            let balance = Balance::from_bytes(&bytes[pos + 4 + 1..pos + 4 + 1 + 12]);
            incoming.push((account_id, is_inner, balance));
            pos += 17;
        }
        for _ in 0..fee_len {
            fee.0.push(Balance::from_bytes(&bytes[pos..pos + 12]));
            pos += 12;
        }
        assert_eq!(pos, bytes.len());
        BalanceMovement {
            hash,
            fee,
            outgoing,
            incoming,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // [txhash 32b][outgoing_len u32][incoming_len u32][fee_len u32]
        // ~[outgoing 12b].. [incoming 4+1+12b].. [fee 12b]..
        let size = 32 + 12 + self.outgoing.0.len() * 12 + self.incoming.len() * 17 + self.fee.0.len() * 12;
        let mut vec = Vec::with_capacity(size);
        vec.extend_from_slice(&u256_to_bytes(&self.hash));
        vec.extend_from_slice(&u32_to_bytes(self.outgoing.0.len() as u32));
        vec.extend_from_slice(&u32_to_bytes(self.incoming.len() as u32));
        vec.extend_from_slice(&u32_to_bytes(self.fee.0.len() as u32));
        for balance in self.outgoing.0.iter() {
            balance.to_bytes(&mut vec);
        }
        for (id, is_inner, balance) in self.incoming.iter() {
            vec.extend_from_slice(&u32_to_bytes(*id));
            vec.push(if *is_inner { 1u8 } else { 0u8 });
            balance.to_bytes(&mut vec);
        }
        for balance in self.fee.0.iter() {
            balance.to_bytes(&mut vec);
        }
        vec
    }

    pub fn push_outgoing(&mut self, coin_id: u32, amount: u64) {
        let amount = amount as i64;
        match self
            .outgoing
            .0
            .iter_mut()
            .find(|_balance| _balance.coin_id == coin_id)
        {
            Some(balance) => balance.amount += amount,
            None => self.outgoing.0.push(Balance { coin_id, amount }),
        }
    }

    pub fn push_incoming(&mut self, account_id: u32, coin_id: u32, amount: u64, is_inner: bool) {
        let amount = amount as i64;
        match self
            .incoming
            .iter_mut()
            .find(|(_id, _inner, _b)| _id == &account_id && _inner == &is_inner && _b.coin_id == coin_id)
        {
            Some((_id, _inner, balance)) => balance.amount += amount,
            None => self
                .incoming
                .push((account_id, is_inner, Balance { coin_id, amount })),
        }
    }

    pub fn get_movement_type(&self) -> MovementType {
        if self.outgoing.0.len() == 0 && self.incoming.len() == 0 {
            MovementType::Nothing
        } else {
            // inner address means `refund`, outer address means `receive`.
            // simple send if incoming addresses are all inner.
            // simple receive if incoming addresses are all outer.
            // complex if incoming addresses include inner & outer.
            let flags = self
                .incoming
                .iter()
                .map(|(_id, is_inner, _b)| *is_inner)
                .collect::<Vec<bool>>();

            if flags.iter().all(|f| f == &true) {
                MovementType::Sending
            } else if flags.iter().all(|f| f == &false) {
                if self.outgoing.0.len() == 0 {
                    MovementType::Receive
                } else {
                    // note: no inner but has outgoing => receive with unknown sending
                    MovementType::Complex
                }
            } else {
                MovementType::Complex
            }
        }
    }

    pub fn get_account_movement(&self) -> Vec<(u32, Balances)> {
        // note: accountId not duplicate (don't use HashMap)
        let type_size = self.outgoing.0.len();
        let mut result: HashMap<u32, Balances> = HashMap::with_capacity(type_size);
        let mut base = Balances(Vec::with_capacity(type_size));

        // incoming (add)
        for (account_id, is_inner, balance) in self.incoming.iter() {
            match result.get_mut(account_id) {
                Some(balances) => balances.add_balance(balance),
                None => {
                    result.insert(*account_id, Balances(vec![balance.clone()]));
                },
            }
            // only inner is `refund` type
            if *is_inner {
                base.add_balance(balance);
            }
        }

        // outgoing (sub)
        // result -= amount_out * amount_in / amount_base
        for balance_out in self.outgoing.0.iter() {
            let coin_id = balance_out.coin_id;
            let amount_out = balance_out.amount;
            let mut success = false;
            for (account_id, is_inner, balance_in) in self.incoming.iter() {
                if balance_in.coin_id != coin_id {
                    continue;
                }
                if !is_inner {
                    continue;
                }
                match base.get_amount_by(coin_id) {
                    Some(amount_base) => {
                        let amount_in = balance_in.amount;
                        let sub = Balance {
                            coin_id,
                            amount: amount_out * amount_in / amount_base,
                        };
                        match result.get_mut(account_id) {
                            Some(balances) => balances.sub_balance(&sub),
                            None => {
                                let mut balances = Balances(Vec::with_capacity(1));
                                balances.sub_balance(&sub);
                                result.insert(*account_id, balances);
                            },
                        };
                        success = true;
                    },
                    None => continue,
                }
            }
            // there is no inner account about the coinId
            // note: this is *exception* route
            if !success {
                // guest accountId
                let account_id = 0;
                // result -= amount_out
                match result.get_mut(&account_id) {
                    Some(balances) => {
                        let sub = Balance {
                            coin_id,
                            amount: amount_out,
                        };
                        balances.sub_balance(&sub);
                    },
                    None => {
                        let minus = Balance {
                            coin_id,
                            amount: amount_out * -1,
                        };
                        let balances = Balances(vec![minus]);
                        result.insert(account_id, balances);
                    },
                }
            }
        }

        // remove zero balance
        result.iter_mut().for_each(|(_id, _b)| _b.compaction());
        let mut vec = result
            .into_iter()
            .filter(|(_id, _b)| !_b.is_empty())
            .collect::<Vec<(u32, Balances)>>();
        // order by accountId
        vec.sort_by_key(|a| a.0);
        vec
    }
}

#[cfg(test)]
mod movement {
    use crate::balance::*;
    use bigint::U256;
    const DUMMY_HASH: [u8; 32] = [1u8; 32];

    #[test]
    fn encode_decode() {
        let hash = U256::from(DUMMY_HASH.as_ref());
        let fee = Balances(vec![
            Balance {
                coin_id: 0,
                amount: 12,
            },
            Balance {
                coin_id: 1,
                amount: 2,
            },
        ]);
        let mut movement = BalanceMovement::new(hash, fee);

        movement.push_outgoing(0, 100);
        movement.push_outgoing(0, 20);
        movement.push_outgoing(1, 50);
        movement.push_incoming(0, 0, 100, true);
        movement.push_incoming(0, 1, 10, true);
        movement.push_incoming(0, 0, 20, false);
        let bytes = movement.to_bytes();
        let new_movement = BalanceMovement::from_bytes(&bytes);

        assert_eq!(new_movement.hash, movement.hash);
        assert_eq!(new_movement.fee, movement.fee);
        assert_eq!(new_movement.outgoing, movement.outgoing);
        assert_eq!(new_movement.incoming, movement.incoming);
    }

    #[test]
    fn distribution() {
        let hash = U256::from(DUMMY_HASH.as_ref());
        let fee = Balances(vec![]);
        let mut movement = BalanceMovement::new(hash.clone(), fee.clone());

        // 0: no movement
        assert_eq!(movement.get_movement_type(), MovementType::Nothing);
        assert_eq!(movement.get_account_movement(), vec![]);

        // 1: simple sending
        // send 0:20 to outside from account0
        //            +---+
        // 0:100  +--->   +---> account0, 0:80, inner
        //            +---+
        movement.push_outgoing(0, 100);
        movement.push_incoming(0, 0, 80, true);
        let estimate = vec![(
            0,
            Balances(vec![Balance {
                coin_id: 0,
                amount: -20,
            }]),
        )];
        assert_eq!(movement.get_movement_type(), MovementType::Sending);
        assert_eq!(movement.get_account_movement(), estimate);

        // 2: simple receive
        // receive 0:80 to account0
        //     +---+
        //     |   +---> account0, 0:80, outer
        //     +---+
        let mut movement = BalanceMovement::new(hash.clone(), fee.clone());
        movement.push_incoming(0, 0, 80, false);
        let estimate = vec![(
            0,
            Balances(vec![Balance {
                coin_id: 0,
                amount: 80,
            }]),
        )];
        assert_eq!(movement.get_movement_type(), MovementType::Receive);
        assert_eq!(movement.get_account_movement(), estimate);

        // 3: complex receive (as exception)
        // receive 0:80 to account1 but unknown sending 0:50 from account0
        //           +---+
        // 0:50  +--->   +---> account1, 0:80, outer
        //           +---+
        let mut movement = BalanceMovement::new(hash.clone(), fee.clone());
        movement.push_outgoing(0, 50);
        movement.push_incoming(1, 0, 80, false);
        let estimate = vec![
            (
                0,
                Balances(vec![Balance {
                    coin_id: 0,
                    amount: -50,
                }]),
            ),
            (
                1,
                Balances(vec![Balance {
                    coin_id: 0,
                    amount: 80,
                }]),
            ),
        ];
        assert_eq!(movement.get_movement_type(), MovementType::Complex);
        assert_eq!(movement.get_account_movement(), estimate);

        // 4. complex
        // account0 -> 0:+20+50-100  2:-300
        // account1 -> 1:+100+50-200*50/(50+20)
        // account2 -> 1:+80+20-200*20/(50+20)
        let mut movement = BalanceMovement::new(hash.clone(), fee.clone());
        movement.push_outgoing(0, 100);
        movement.push_outgoing(1, 200);
        movement.push_outgoing(2, 300);
        movement.push_incoming(0, 0, 20, false);
        movement.push_incoming(0, 0, 50, true);
        movement.push_incoming(1, 1, 100, false);
        movement.push_incoming(1, 1, 50, true);
        movement.push_incoming(2, 1, 80, false);
        movement.push_incoming(2, 1, 20, true);
        let estimate = vec![
            (
                0,
                Balances(vec![
                    Balance {
                        coin_id: 0,
                        amount: -30,
                    },
                    Balance {
                        coin_id: 2,
                        amount: -300,
                    },
                ]),
            ),
            (
                1,
                Balances(vec![Balance {
                    coin_id: 1,
                    amount: 8,
                }]),
            ),
            (
                2,
                Balances(vec![Balance {
                    coin_id: 1,
                    amount: 43,
                }]),
            ),
        ];
        assert_eq!(movement.get_movement_type(), MovementType::Complex);
        assert_eq!(movement.get_account_movement(), estimate);
    }
}
