use crate::signature::SCALAR;
use num_bigint::BigUint;
use num_traits::identities::One;
use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};
use secp256k1::{Error, PublicKey, Secp256k1, SecretKey, VerifyOnly};
use std::ops::{Add, Div, Sub};
use std::sync::Once;

static mut CONTEXT: Option<Secp256k1<VerifyOnly>> = None;

pub const P: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47,
];
pub const N: [u8; 32] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 186, 174, 220, 230, 175,
    72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
];

/// generate secp256k1 context at once
pub fn get_context() -> &'static Secp256k1<VerifyOnly> {
    static INIT_CONTEXT: Once = Once::new();
    INIT_CONTEXT.call_once(|| unsafe {
        CONTEXT = Some(Secp256k1::verification_only());
    });
    unsafe { CONTEXT.as_ref().unwrap() }
}

/// generate basement point
pub fn generator() -> PublicKey {
    let mut v = Vec::with_capacity(1 + 32 + 32);
    v.push(4);
    v.extend(GENERATOR_X.as_ref());
    v.extend(GENERATOR_Y.as_ref());
    PublicKey::from_slice(&v).unwrap()
}

/// POINT * SCALAR
pub fn scalar_mul(point: &mut PublicKey, fe: &SecretKey) -> Result<(), Error> {
    point.mul_assign(get_context(), &fe[..])
}

/// POINT * SCALAR(slice)
pub fn raw_scalar_mul(point: &mut PublicKey, fe: &[u8]) -> Result<(), Error> {
    point.mul_assign(get_context(), fe)
}

/// POINT - POINT
pub fn sub_point(point: &PublicKey, other: &PublicKey) -> Result<PublicKey, Error> {
    let p = BigUint::from_bytes_be(&P);
    let serialized_pk = PublicKey::serialize_uncompressed(other);
    let x = BigUint::from_bytes_be(&serialized_pk[1..1 + 32]);
    let y = BigUint::from_bytes_be(&serialized_pk[33..33 + 32]);
    let minus_y = if p < y { y.sub(&p) } else { p.sub(&y) };

    let mut tmp = [0u8; 1 + 32 + 32];
    tmp[0] = 4;

    let x_vec = x.to_bytes_be();
    (&mut tmp[1 + 32 - x_vec.len()..1 + 32]).clone_from_slice(x_vec.as_slice());

    let y_vec = minus_y.to_bytes_be();
    (&mut tmp[1 + 64 - y_vec.len()..1 + 64]).clone_from_slice(y_vec.as_slice());

    let minus_point = PublicKey::from_slice(&tmp)?;
    point.combine(&minus_point)
}

/// invert secret key (N - sk)
pub fn inv_scalar(secret: &SecretKey) -> Result<SecretKey, Error> {
    let sk = BigUint::from_bytes_be(&secret[..]);
    let n = BigUint::from_bytes_be(N.as_ref());
    SecretKey::from_slice(&n.sub(sk).to_bytes_be())
}

/// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification
/// has_square_y(P), or fails if no such point exists
///     Let c = r^3 + 7 mod p
///     Let y = c^(p+1)/4 mod p
///     Fail if c ≠ y^2 mod p
pub fn has_square_y(r: &SCALAR) -> bool {
    let r = BigUint::from_bytes_be(r);
    let p = BigUint::from_bytes_be(&P);
    let mut c = r.modpow(&BigUint::from(3u32), &p).add(7u32);
    if p < c {
        c = c.div(&p); // for adding 7
    }
    let e = p.clone().add(1u32).div(4u32);
    let y = c.clone().modpow(&e, &p);
    let out = y.modpow(&BigUint::from(2u32), &p);
    out == c
}

/// Jacobian Coordinates
///    let j = x^(p-1)/2 mod p
///    fail if j ≠ 1
pub fn is_jacobi(point: &PublicKey) -> bool {
    let y = BigUint::from_bytes_be(&point.serialize_uncompressed()[33..33 + 32]);
    let p = BigUint::from_bytes_be(&P);
    let j = y.modpow(&p.clone().sub(1u32).div(2u32), &p);
    j.is_one()
}

#[inline]
pub fn slice_eq(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).all(|(a, b)| a == b)
}
