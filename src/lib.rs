#![feature(in_band_lifetimes)]
#![feature(drain_filter)]

extern crate bigint;
extern crate num_bigint;
extern crate num_traits;
extern crate sha2;
#[macro_use]
extern crate lazy_static;
extern crate remove_dir_all;

pub mod balance;
pub mod block;
pub mod chain;
pub mod pickle;
pub mod python;
pub mod signature;
pub mod tx;
pub mod utils;

type StrResult<T> = Result<T, String>;
