use std::net;
use std::str::FromStr;
use std::mem::transmute;

// Stores an IPv4 prefix or an IPv6 prefix in a byte array.
// Bytes are stored little-endian; e.g.:
//   1.2.3.4 -> [4, 3, 2, 1]
#[derive(Debug, PartialEq)]
pub enum Prefix {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl FromStr for Prefix {
    type Err = net::AddrParseError;
    fn from_str(s: &str) -> Result<Prefix, net::AddrParseError> {
        let v4 = net::Ipv4Addr::from_str(s).and_then(|ip| Ok(Prefix::from_ipv4(ip)));
        if v4.is_ok() { return v4 };
        net::Ipv6Addr::from_str(s).and_then(|ip| Ok(Prefix::from_ipv6(ip)))
    }
}

impl Prefix {

    pub fn from_ipv4(ip: net::Ipv4Addr) -> Prefix {
        Prefix::V4(ip.octets()).reverse_bytes()
    }

    pub fn from_ipv6(ip: net::Ipv6Addr) -> Prefix {
        Prefix::V6(ip.octets()).reverse_bytes()
    }

    pub fn msbit(&self) -> u8 {
        match *self {
            Prefix::V4(bytes) => (bytes[3] & 0x80) >> 7,
            Prefix::V6(bytes) => (bytes[15] & 0x80) >> 7,
        }
    }

    pub fn shift_left(&self, n: usize) -> Prefix {
        match *self {
            Prefix::V4(bytes) => {
                let shifted = unsafe {
                    let word = transmute::<[u8; 4], u32>(bytes);
                    transmute::<u32, [u8; 4]>(word << n)
                };
                Prefix::V4(shifted)
            },
            Prefix::V6(bytes) => {
                let shifted = unsafe {
                    let words = transmute::<[u8; 16], [u64; 2]>(bytes);
                    let shifted_words = [words[0] << n, (words[1] << n) | (words[0] >> (64 - n))];
                    transmute::<[u64; 2], [u8; 16]>(shifted_words)
                };
                Prefix::V6(shifted)
            }
        }
    }

    fn reverse_bytes(&self) -> Prefix {
        match *self {
            Prefix::V4(bytes) => unsafe {
                let word = transmute::<[u8; 4], u32>(bytes);
                let swapped_bytes = transmute::<u32, [u8; 4]>(word.swap_bytes());
                Prefix::V4(swapped_bytes)
            },
            Prefix::V6(bytes) => unsafe {
                let words = transmute::<[u8; 16], [u64; 2]>(bytes);
                let swapped_words = [words[1].swap_bytes(), words[0].swap_bytes()];
                let swapped_bytes = transmute::<[u64; 2], [u8; 16]>(swapped_words);
                Prefix::V6(swapped_bytes)
            }
        }
    }
}

#[test]
fn test_from_str() {
    let p = Prefix::from_str("1.2.3.4").unwrap();
    assert!(p == Prefix::V4([4, 3, 2, 1]));

    let p = Prefix::from_str("::1.2.3.4").unwrap();
    assert!(p == Prefix::V6([4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
}

#[test]
fn test_from_msbit() {
    assert!(0 == Prefix::from_str("1.0.0.0").unwrap().msbit());
    assert!(1 == Prefix::from_str("128.0.0.0").unwrap().msbit());
}

#[test]
fn test_shift_left_v4() {
    assert!(Prefix::V4([0, 0, 0, 1]).shift_left(1) ==
            Prefix::V4([0, 0, 0, 2]));

    assert!(Prefix::V4([0, 0, 0, 128]).shift_left(1) ==
            Prefix::V4([0, 0, 0, 0]));

    assert!(Prefix::V4([128, 0, 0, 0]).shift_left(1) ==
            Prefix::V4([0, 1, 0, 0]));
}

#[test]
fn test_shift_left_v6() {
    assert!(Prefix::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).shift_left(1) ==
            Prefix::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]));

    assert!(Prefix::V6([0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 128]).shift_left(1) ==
            Prefix::V6([0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]));

    assert!(Prefix::V6([128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).shift_left(1) ==
            Prefix::V6([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
}

#[test]
fn test_reverse_bytes_v4() {
    assert!(Prefix::V4([1, 2, 3, 4]).reverse_bytes() ==
            Prefix::V4([4, 3, 2, 1]));
}

#[test]
fn test_reverse_bytes_v6() {
    assert!(Prefix::V6([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).reverse_bytes() ==
            Prefix::V6([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]));
}
