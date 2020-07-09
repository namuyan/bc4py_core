/// LWMA-2 difficulty algorithm (commented version)
/// Copyright (c) 2017-2018 Zawy, MIT License
/// https://github.com/zawy12/difficulty-algorithms/issues/3
/// Bitcoin clones must lower their FTL.
/// Cryptonote et al coins must make the following changes:
/// #define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW    11
/// #define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT        3 * DIFFICULTY_TARGET
/// #define DIFFICULTY_WINDOW                      60 //  45, 60, & 90 for T=600, 120, & 60.
/// Bytecoin / Karbo clones may not have the following
/// #define DIFFICULTY_BLOCKS_COUNT       DIFFICULTY_WINDOW+1
/// The BLOCKS_COUNT is to make timestamps & cumulative_difficulty vectors size N+1
/// Do not sort timestamps.
/// CN coins (but not Monero >= 12.3) must deploy the Jagerman MTP Patch. See:
/// https://github.com/loki-project/loki/pull/26   or
/// https://github.com/graft-project/GraftNetwork/pull/118/files
use crate::block::*;
use crate::chain::tables::Tables;
use bigint::{U256, U512};
use std::cmp::max;
use std::collections::HashMap;

/// maximum bits
static MAX_BITS: u32 = 0x1f0fffff;

lazy_static! {
    // genesis block's previous_hash is "ffff..ffff"
    static ref GENESIS_PREVIOUS_HASH: U256 = U256::from([
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ].as_ref());
    // maximum target calc from maximum bits
    static ref MAX_TARGET: U256 = bits_to_target(MAX_BITS).unwrap();
    // max target int for calc difficulty
    static ref MAX: U512 = U512::from(U256::from([
        255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    ].as_ref()));
}

/// maximum HashMap cache size
static MAX_CACHE_SIZE: usize = 200;

/// maximum blocks number to calc bits
static MAX_SEARCH_BLOCKS: usize = 1000;

/// block time params (BlockFlag, T, N, K)
pub type BlockTimeParams = Vec<(BlockFlag, u32, u32, u32)>;

/// BlockHeader with meta info
#[derive(PartialEq)]
struct MetaHeader {
    height: u32,
    flag: BlockFlag,
    work: U256,
    header: BlockHeader,
}

pub struct DifficultyBuilder {
    cache: HashMap<U256, MetaHeader>,
    params: BlockTimeParams,
}

#[allow(non_snake_case)]
impl DifficultyBuilder {
    pub fn new(params: BlockTimeParams) -> Self {
        DifficultyBuilder {
            cache: HashMap::with_capacity(MAX_CACHE_SIZE),
            params,
        }
    }

    pub fn calc_next_bits(
        &mut self,
        previous_hash: &U256,
        flag: &BlockFlag,
        tables: &Tables,
    ) -> Result<u32, String> {
        if *previous_hash == *GENESIS_PREVIOUS_HASH {
            return Ok(MAX_BITS);
        }

        // block difficulty params
        let (_flag, _T, N, K) = self.params.iter().find(|p| &p.0 == flag).unwrap();
        let (mut N, K) = (*N, *K);

        // Loop through N most recent blocks.  "< height", not "<=".
        // height-1 = most recently solved rblock
        let mut target_hash = previous_hash.clone();
        let mut timestamps = Vec::with_capacity(100);
        let mut targets = Vec::with_capacity(100);
        let mut breaked = false;
        let mut j = 0;
        for _ in 0..MAX_SEARCH_BLOCKS {
            let result = self.get_header_ref(&target_hash, tables)?;

            // may reached root
            if result.is_none() {
                return Ok(MAX_BITS);
            }
            let meta = result.unwrap();
            if &meta.flag != flag {
                target_hash = meta.header.previous_hash.clone();
                continue;
            }
            if j == N + 1 {
                breaked = true;
                break;
            }
            // accept the header
            j += 1;
            timestamps.insert(0, meta.header.time);
            targets.insert(0, bits_to_target(meta.header.bits)?);
            target_hash = meta.header.previous_hash.clone();
            if target_hash == *GENESIS_PREVIOUS_HASH {
                return Ok(MAX_BITS);
            }
        }

        // check run out of for loop
        if !breaked {
            // search too many block
            if targets.len() < 2 {
                // # not found any mined blocks
                return Ok(MAX_BITS);
            } else {
                // May have been a sudden difficulty raise
                // overwrite N param
                N = (timestamps.len() - 1) as u32;
            }
        }

        // calc target sum
        let mut sum_target = U512::from(0u32);
        let mut t = 0;
        let mut j = 0;
        for i in 0..N as usize {
            let solve_time = max(0, timestamps[i + 1] - timestamps[i]);
            j += 1;
            t += solve_time * j;
            sum_target = sum_target + U512::from(targets[i + 1]);
        }

        // Keep t reasonable in case strange solvetimes occurred
        if t < N * K / 3 {
            t = N * K / 3;
        }

        // get result
        let t = U512::from(t);
        let K = U512::from(K);
        let N = U512::from(N);
        let new_target = U256::from(t * sum_target / K / N / N);

        // check target limit
        if *MAX_TARGET < new_target {
            return Ok(MAX_BITS);
        }

        // convert new target to bits
        // note: bits->target is accurate but target->bits isn't accurate
        Ok(target_to_bits(&new_target))
    }

    pub fn calc_next_bias(
        &mut self,
        previous_hash: &U256,
        flag: &BlockFlag,
        tables: &Tables,
    ) -> Result<f32, String> {
        let N = 30u32; // target blocks

        // genesis block is exception
        if flag == &BlockFlag::Genesis {
            return Ok(1.0);
        }

        // first block is exception
        if *previous_hash == *GENESIS_PREVIOUS_HASH {
            return Ok(1.0);
        }

        // calc
        let mut target_sum = U512::from(0u32);
        let mut target_cnt = 0;
        let mut others_best = HashMap::with_capacity(self.params.len());
        let mut target_hash = previous_hash.clone();
        for _ in 0..MAX_SEARCH_BLOCKS {
            let result = self.get_header_ref(&target_hash, tables)?;

            // may reached root
            if result.is_none() {
                return Ok(1.0);
            }
            let meta = result.unwrap();

            // set newest target if not found flag before
            if !others_best.contains_key(&meta.flag) {
                others_best.insert(meta.flag.clone(), bits_to_target(meta.header.bits)?);
            }

            // set next header's hash
            target_hash = meta.header.previous_hash.clone();

            // check
            if target_hash == *GENESIS_PREVIOUS_HASH {
                // reached root
                return Ok(1.0);
            } else if &meta.flag == flag && N > target_cnt {
                // match require info
                let _target = U512::from(bits_to_target(meta.header.bits)?);
                let _mul = U512::from(N - target_cnt);
                target_sum = target_sum + _target * _mul;
                target_cnt += 1;
            } else if self.params.len() <= others_best.len() + 1 {
                // break because get enough info
                break;
            } else {
                continue;
            }
        }

        // note: BASE = MAX / 0x100000000
        if target_cnt == 0 {
            Ok(1.0)
        } else if others_best.len() == 0 {
            // = BASE_TARGET * target_cnt / target_sum
            // = double(MAX * target_cnt / target_sum) / 0x100000000
            Ok((*MAX * U512::from(target_cnt) / target_sum).as_u64() as f32 / 4294967296f32)
        } else {
            // = average_target * target_cnt / target_sum
            // = double(average_target * target_cnt / target_sum * 0x100000000) / 0x100000000
            let mut average_target = U512::from(0u32);
            for target in others_best.values() {
                average_target = average_target + U512::from(target);
            }
            average_target = average_target / U512::from(others_best.len());
            let int = average_target * U512::from(target_cnt) / target_sum * U512::from(0x100000000u64);
            Ok(int.as_u64() as f32 / 4294967296f32)
        }
    }

    fn get_header_ref(&mut self, hash: &U256, tables: &Tables) -> Result<Option<&MetaHeader>, String> {
        // note: err occur by tables exception
        if !self.cache.contains_key(hash) {
            // need to insert new header
            match tables.read_block(hash)? {
                Some(block) => {
                    let header = MetaHeader {
                        height: block.height,
                        flag: block.flag,
                        work: block.work_hash,
                        header: block.header,
                    };
                    self.cache.insert(hash.clone(), header);
                },
                None => return Ok(None),
            }
        }

        // check cache limit reached
        if MAX_CACHE_SIZE <= self.cache.len() {
            let (delete_hash, _) = self
                .cache
                .iter()
                .min_by_key(|(_hash, header)| header.height)
                .unwrap();
            let delete_hash = delete_hash.clone();
            // delete one header
            self.cache.remove(&delete_hash);
        }

        // return ref
        Ok(Some(self.cache.get(hash).unwrap()))
    }
}
