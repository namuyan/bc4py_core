use crate::signature::utils::*;
use std::fmt;

mod aggregate;
mod threshold;
mod utils;

// signature data type
type POINT = [u8; 33];
type SCALAR = [u8; 32];

#[derive(Clone)]
pub enum Signature {
    SingleSig((POINT, SCALAR, SCALAR)),    // (pk, r, s)
    AggregateSig((POINT, SCALAR, SCALAR)), // (apk, r, s)
    ThresholdSig((POINT, POINT, SCALAR)),  // (Y, V, sigma)
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signature::SingleSig((pk, _, _)) => {
                f.debug_tuple("Single").field(&hex::encode(&pk[1..33])).finish()
            },
            Signature::AggregateSig((pk, _, _)) => f
                .debug_tuple("Aggregate")
                .field(&hex::encode(&pk[1..33]))
                .finish(),
            Signature::ThresholdSig((pk, _, _)) => f
                .debug_tuple("Threshold")
                .field(&hex::encode(&pk[1..33]))
                .finish(),
        }
    }
}

impl std::cmp::PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        let (a, b, c) = match (self, other) {
            (Signature::SingleSig((_a, _b, _c)), Signature::SingleSig((_d, _e, _f))) => {
                (slice_eq(_a, _d), slice_eq(_b, _e), slice_eq(_c, _f))
            },
            (Signature::AggregateSig((_a, _b, _c)), Signature::AggregateSig((_d, _e, _f))) => {
                (slice_eq(_a, _d), slice_eq(_b, _e), slice_eq(_c, _f))
            },
            (Signature::ThresholdSig((_a, _b, _c)), Signature::ThresholdSig((_d, _e, _f))) => {
                (slice_eq(_a, _d), slice_eq(_b, _e), slice_eq(_c, _f))
            },
            _ => return false,
        };
        a && b && c
    }
}

impl Signature {
    pub fn new() -> Result<Self, ()> {
        // auto detect sig type
        unimplemented!()
    }

    pub fn new_single_sig(pk: &[u8], r: &[u8], s: &[u8]) -> Result<Self, ()> {
        let a = Self::slice_to_point(pk)?;
        let b = Self::slice_to_scalar(r)?;
        let c = Self::slice_to_scalar(s)?;
        Ok(Signature::SingleSig((a, b, c)))
    }

    pub fn new_aggregate_sig(pk: &[u8], r: &[u8], s: &[u8]) -> Result<Self, ()> {
        let a = Self::slice_to_point(pk)?;
        let b = Self::slice_to_scalar(r)?;
        let c = Self::slice_to_scalar(s)?;
        Ok(Signature::AggregateSig((a, b, c)))
    }

    pub fn new_threshold_sig(y: &[u8], v: &[u8], sigma: &[u8]) -> Result<Self, ()> {
        let a = Self::slice_to_point(y)?;
        let b = Self::slice_to_point(v)?;
        let c = Self::slice_to_scalar(sigma)?;
        Ok(Signature::ThresholdSig((a, b, c)))
    }

    fn slice_to_point(slice: &[u8]) -> Result<POINT, ()> {
        if slice.len() == 33 {
            // prefix is 0x02, 0x03, 0x04
            if slice[0] < 0x02 || 0x04 < slice[0] {
                Err(())
            } else {
                let mut tmp = [0u8; 33];
                tmp.clone_from_slice(slice);
                Ok(tmp)
            }
        } else {
            Err(())
        }
    }

    fn slice_to_scalar(slice: &[u8]) -> Result<SCALAR, ()> {
        if slice.len() == 32 {
            let mut tmp = [0u8; 32];
            tmp.clone_from_slice(slice);
            Ok(tmp)
        } else {
            Err(())
        }
    }
}

/// get signature size
#[inline]
pub fn get_signature_size(signature: &Signature) -> usize {
    match signature {
        Signature::SingleSig(_) => 33 + 32 + 32,
        Signature::AggregateSig(_) => 33 + 32 + 32,
        Signature::ThresholdSig(_) => 33 + 33 + 32,
    }
}

#[inline]
pub fn signature_to_bytes(signature: &Signature, vec: &mut Vec<u8>) {
    match signature {
        // pk prefix: 0x02, 0x03, 0x04 -> 0x02, 0x03, 0x04
        Signature::SingleSig((pk, r, s)) => {
            let mut pk = pk.clone();
            pk[0] += 0;
            vec.extend_from_slice(&pk);
            vec.extend_from_slice(r);
            vec.extend_from_slice(s);
        },

        // pk prefix: 0x02, 0x03, 0x04 -> 0x05, 0x06, 0x07
        Signature::AggregateSig((pk, r, s)) => {
            let mut pk = pk.clone();
            pk[0] += 3;
            vec.extend_from_slice(&pk);
            vec.extend_from_slice(r);
            vec.extend_from_slice(s);
        },

        // pk prefix: 0x02, 0x03, 0x04 -> 0x08, 0x09, 0x0a
        Signature::ThresholdSig((pk, r, s)) => {
            let mut pk = pk.clone();
            pk[0] += 6;
            vec.extend_from_slice(&pk);
            vec.extend_from_slice(r);
            vec.extend_from_slice(s);
        },
    }
}

#[inline]
pub fn bytes_to_signature(bytes: &[u8]) -> Result<Signature, String> {
    if bytes[0] < 0x02 {
        Err(format!(
            "unknown pk type or wrong length prefix={} len={}",
            bytes[0],
            bytes.len()
        ))
    } else if bytes[0] < 0x05 && 33 + 32 + 32 <= bytes.len() {
        // single sig
        let mut pk = [0u8; 33];
        pk.clone_from_slice(&bytes[0..33]);
        pk[0] -= 0;
        let mut r = [0u8; 32];
        r.clone_from_slice(&bytes[33..33 + 32]);
        let mut p = [0u8; 32];
        p.clone_from_slice(&bytes[65..65 + 32]);
        Ok(Signature::SingleSig((pk, r, p)))
    } else if bytes[0] < 0x08 && 33 + 32 + 32 <= bytes.len() {
        // aggregate sig
        let mut pk = [0u8; 33];
        pk.clone_from_slice(&bytes[0..33]);
        pk[0] -= 3;
        let mut r = [0u8; 32];
        r.clone_from_slice(&bytes[33..33 + 32]);
        let mut p = [0u8; 32];
        p.clone_from_slice(&bytes[65..65 + 32]);
        Ok(Signature::AggregateSig((pk, r, p)))
    } else if bytes[0] < 0x0b && 33 + 33 + 32 <= bytes.len() {
        // threshold sig
        let mut pk = [0u8; 33];
        pk.clone_from_slice(&bytes[0..33]);
        pk[0] -= 6;
        let mut r = [0u8; 33];
        r.clone_from_slice(&bytes[33..33 + 33]);
        let mut p = [0u8; 32];
        p.clone_from_slice(&bytes[66..66 + 32]);
        Ok(Signature::ThresholdSig((pk, r, p)))
    } else {
        Err(format!(
            "unknown pk type or wrong length prefix={} len={}",
            bytes[0],
            bytes.len()
        ))
    }
}

/// verify with auto detect type
#[allow(non_snake_case)]
pub fn verify_signature(signature: &Signature, message: &[u8]) -> Result<bool, secp256k1::Error> {
    // note: single and aggregate are same verification route
    match signature {
        Signature::SingleSig((pk, r, s)) => aggregate::verify_aggregate(pk, r, s, message),
        Signature::AggregateSig((pk, r, s)) => aggregate::verify_aggregate(pk, r, s, message),
        Signature::ThresholdSig((y, v, sigma)) => threshold::verify_threshold(y, v, sigma, message),
    }
}
