use std::net;
use std::str::FromStr;
use std::num;

#[derive(Debug, PartialEq)]
pub struct Cidr {
    pub prefix: net::Ipv4Addr,
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
        return Ok(Cidr {
            prefix: try!(net::Ipv4Addr::from_str(parts[0])),
            length: length,
        })
    }
}

impl Cidr {
    pub fn from_bits(bits: u32, length: u8) -> Option<Cidr> {
        Some(Cidr {
            prefix: net::Ipv4Addr::new(
                        (bits >> 24) as u8,
                        (bits >> 16) as u8,
                        (bits >>  8) as u8,
                        (bits)       as u8),
            length: length,
        })
    }

    pub fn prefix_bits(&self) -> u32 {
        let octets = self.prefix.octets();
        ((octets[0] as u32) << 24) |
        ((octets[1] as u32) << 16) |
        ((octets[2] as u32) << 8) |
        ((octets[3] as u32))
    }
}

#[test]
fn test_from_str() {
    assert!(Cidr::from_str("1.2.3.4/32").unwrap().prefix ==
            Cidr::from_str("1.2.3.4").unwrap().prefix);

    assert!(Cidr::from_str("1.2.3.4/32").unwrap().length == 32);
    assert!(Cidr::from_str("1.2.3.4/0").unwrap().length == 0);

    let from_bits = Cidr::from_bits(0x80000000, 1).unwrap();
    let from_str = Cidr::from_str("128.0.0.0/1").unwrap();
    assert!(from_bits == from_str);
}