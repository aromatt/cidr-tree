use std::net;
use std::str::FromStr;
use std::num;

#[derive(Debug, PartialEq)]
pub struct Prefix {
    pub bits: net::Ipv4Addr,
}

impl Prefix {
    pub fn octets(&self) -> [u8; 4] {
        self.bits.octets()
    }
}

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
        return Ok(Cidr {
            prefix: Prefix { bits: try!(net::Ipv4Addr::from_str(parts[0])) },
            length: length,
        })
    }
}

impl Cidr {
    pub fn from_bits(bits: u32, length: u8) -> Option<Cidr> {
        Some(Cidr {
            prefix: Prefix {
                bits: net::Ipv4Addr::new((bits >> 24) as u8,
                                         (bits >> 16) as u8,
                                         (bits >>  8) as u8,
                                         (bits)       as u8)
            },
            length: length,
        })
    }

    pub fn from_slice(bits: [u8; 4], length: u8) -> Cidr {
        Cidr {
            prefix: Prefix {
                bits: net::Ipv4Addr::new(bits[0], bits[1], bits[2], bits[3])
            },
            length: length,
        }
    }

    pub fn prefix_bits(&self) -> u32 {
        let octets = self.prefix.octets();
        ((octets[0] as u32) << 24) |
        ((octets[1] as u32) << 16) |
        ((octets[2] as u32) << 8) |
        ((octets[3] as u32))
    }

    pub fn next(&self) -> Cidr {
        let o = self.prefix.octets();
        Cidr::from_slice([o[0] << 1, o[1] << 1, o[2] << 1, o[3] << 1], self.length - 2)
    }

    pub fn msbit(&self) -> u8 {
        match self.prefix.octets()[0] & 0x80 {
            0 => 0,
            _ => 1
        }
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

#[test]
fn test_msbit() {
    assert!(Cidr::from_str("0.0.0.0/32").unwrap().msbit() == 0);
    assert!(Cidr::from_str("255.0.0.0/32").unwrap().msbit() == 1);
}
