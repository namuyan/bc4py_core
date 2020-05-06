use crate::signature::utils::*;
use crate::signature::{POINT, SCALAR};
use secp256k1::{Error, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Y: shared public key
#[allow(non_snake_case)]
pub fn verify_threshold(y: &POINT, v: &POINT, sigma: &SCALAR, message: &[u8]) -> Result<bool, Error> {
    // hash by sha256
    let length = v.len() + y.len() + message.len();
    let mut vec = Vec::with_capacity(length);
    vec.extend_from_slice(v);
    vec.extend_from_slice(y);
    vec.extend_from_slice(message);
    let e = Sha256::digest(&vec);
    let e = SecretKey::from_slice(e.as_slice())?;

    // calc: sigma_g = G * sigma
    let sigma = SecretKey::from_slice(sigma)?;
    let mut sigma_g = generator();
    scalar_mul(&mut sigma_g, &sigma)?;

    // calc: eY = Y * e
    let mut eY = PublicKey::from_slice(y)?;
    scalar_mul(&mut eY, &e)?;

    // calc: sigma_g = eY + V
    let v = PublicKey::from_slice(v)?;
    let eY_plus_v = eY.combine(&v)?;
    Ok(eY_plus_v == sigma_g)
}

#[cfg(test)]
mod threshold_verify {
    use crate::signature::{verify_signature, Signature};

    #[test]
    fn vector_0() {
        // https://github.com/namuyan/multi-party-schnorr/blob/master/static_params.py
        let y = hex::decode("03b655c50b577764ab170225ae4578cdc3bb16ad35c62c4664fd783ffc4967fb82").unwrap();
        let v = hex::decode("03361991856119c7bd009b709e9afd786eb18ac09ce14ad52471516faba7e08b9a").unwrap();
        let sigma = hex::decode("4b76d08ccfc96e81c66691d8d1b98aa1cdd076256cc8a7e038edcd33468f17ab").unwrap();
        let msg = [79u8, 77, 69, 82].to_vec();

        let signature = Signature::new_threshold_sig(&y, &v, &sigma).unwrap();
        assert_eq!(verify_signature(&signature, &msg), Ok(true));
    }
}
