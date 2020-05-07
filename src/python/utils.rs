use crate::utils::write_slice;
use bech32::{convert_bits, Bech32, Error};
use std::str::FromStr;

type Address = [u8; 21];
static HRP: &str = "kuma";

pub fn string2addr(string: &str) -> Result<Address, Error> {
    // return [ver+identifier] bytes
    match addr2params(string) {
        Ok((ver, identifier)) => {
            let mut addr = [ver; 21];
            write_slice(&mut addr[1..21], &identifier);
            Ok(addr)
        },
        Err(err) => Err(err),
    }
}

pub fn params2bech(ver: u8, identifier: &[u8]) -> Result<Bech32, Error> {
    assert_eq!(identifier.len(), 20);
    let mut data = convert_bits(identifier, 8, 5, true)?;
    data.insert(0, ver);
    Bech32::new_check_data(HRP.to_owned(), data)
}

fn addr2params(string: &str) -> Result<(u8, Vec<u8>), Error> {
    // return (version, identifier)
    let bech = Bech32::from_str(string)?;
    if bech.hrp() != HRP {
        return Err(Error::InvalidChar('?'));
    }
    let ver = match bech.data().get(0) {
        Some(ver) => ver.to_owned().to_u8(),
        None => return Err(Error::InvalidLength),
    };
    let identifier = convert_bits(&bech.data()[1..], 5, 8, false)?;
    Ok((ver, identifier))
}
