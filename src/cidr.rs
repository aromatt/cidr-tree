use std::net;
use std::str::FromStr;
use std::num;
use prefix::Prefix;

#[derive(Debug, PartialEq)]
pub struct Cidr {
    pub prefix: Prefix,
    pub length: u8,
}

#[derive(Debug)]
pub enum CidrParseError {
    Prefix(net::AddrParseError),
    Length(num::ParseIntError),
}

impl From<net::AddrParseError> for CidrParseError {
    fn from(err: net::AddrParseError) -> CidrParseError {
        CidrParseError::Prefix(err)
    }
}

impl From<num::ParseIntError> for CidrParseError {
    fn from(err: num::ParseIntError) -> CidrParseError {
        CidrParseError::Length(err)
    }
}

impl FromStr for Cidr {
    type Err = CidrParseError;

    fn from_str(s: &str) -> Result<Cidr, CidrParseError> {
        let parts = s.split("/").collect::<Vec<&str>>();
        let mut length = 32;
        if parts.len() > 1 {
            length = try!(parts[1].parse::<u8>());
        }
        let prefix = try!(Prefix::from_str(parts[0]));
        return Ok(Cidr {
            prefix: prefix,
            length: length,
        })
    }
}

impl Cidr {
    pub fn new(prefix: Prefix, length: u8) -> Cidr {
        Cidr {
            prefix: prefix,
            length: length,
        }
    }

    pub fn next(&self) -> Cidr {
        Cidr::new(self.prefix.shift_left(1), self.length - 1)
    }

    pub fn msbit(&self) -> u8 {
        if self.length > 0 { self.prefix.msbit() } else { 0 }
    }
}

#[test]
fn test_from_str() {
    assert!(Cidr::from_str("1.2.3.4/32").unwrap().prefix ==
            Cidr::from_str("1.2.3.4").unwrap().prefix);

    assert!(Cidr::from_str("1.2.3.4/32").unwrap().length == 32);
    assert!(Cidr::from_str("1.2.3.4/0").unwrap().length == 0);

    assert!(Cidr::from_str("0::/0").unwrap().length == 0);
    assert!(Cidr::from_str("8000::/1").unwrap().length == 1);
}

#[test]
fn test_next() {
    assert!(Cidr::from_str("1.0.0.0/32").unwrap().next() ==
            Cidr::from_str("2.0.0.0/31").unwrap());
    assert!(Cidr::from_str("0.0.128.0/32").unwrap().next() ==
            Cidr::from_str("0.1.0.0/31").unwrap());
}

#[test]
fn test_msbit() {
    assert!(0 == Cidr::from_str("1.0.0.0").unwrap().msbit());
    assert!(1 == Cidr::from_str("128.0.0.0").unwrap().msbit());
    assert!(0 == Cidr::from_str("128.0.0.0/0").unwrap().msbit());
}
