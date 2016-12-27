use std::str::FromStr;
use std::fmt::Debug;
use cidr::Cidr;

#[derive(Debug)]
pub struct CidrTree<T> where T: Debug {
    zero: Option<Box<CidrTree<T>>>,
    one: Option<Box<CidrTree<T>>>,
    data: Option<T>,
}

impl<T> CidrTree<T> where T: Debug {
    pub fn new() -> CidrTree<T> {
        CidrTree {
            zero: None,
            one: None,
            data: None,
        }
    }

    pub fn new_with_data(data: T) -> CidrTree<T> {
        CidrTree {
            zero: None,
            one: None,
            data: Some(data),
        }
    }

    // Returns a vector of all the data that applies the queried CIDR
    pub fn get(&self, cidr: &Cidr) -> Vec<Option<&T>> {
        let mut results = Vec::<Option<&T>>::new();

        // I might have something to contribute
        if let Some(ref d) = self.data {
            results.push(Some(d));
        }
        let next_cidr = cidr.next();
        match cidr.msbit() {
            0 => {
                match self.zero {
                    Some(ref child) => {
                        results.extend(child.get(&next_cidr));
                    },
                    None => {}
                }
            },
            _ => {
                match self.one {
                    Some(ref child) => {
                        results.extend(child.get(&next_cidr));
                    },
                    None => {}
                }
            },
        };
        results
    }

    pub fn has_exact(&self, cidr: &Cidr) -> bool {
        // We have a node that matches the query
        if cidr.length == 0 { return true; }

        match cidr.msbit() {
            0 => {
                match self.zero {
                    Some(ref child) => child.has_exact(&cidr.next()),
                    None => false
                }
            },
            _ => {
                match self.one {
                    Some(ref child) => child.has_exact(&cidr.next()),
                    None => false
                }
            },
        }
    }

    pub fn covers(&self, cidr: &Cidr) -> bool {
        // We have a node that matches the query
        if cidr.length == 0 { return true; }

        match cidr.msbit() {
            0 => {
                match self.zero {
                    Some(ref child) => child.covers(&cidr.next()),
                    None => true
                }
            },
            _ => {
                match self.one {
                    Some(ref child) => child.covers(&cidr.next()),
                    None => true
                }
            },
        }
    }

    pub fn get_from_str(&self, cidr: &str) -> Vec<&T> {
        self.get(&Cidr::from_str(cidr).unwrap())
    }

    pub fn insert(&mut self, cidr: &Cidr, data: Option<T>) {
        // Search is over; this node is where the data goes
        if cidr.length == 0 {
            self.data = data;
            return;
        }

        // Next cidr is the incoming cidr shifted left by one
        let next_cidr = cidr.next();

        // TODO repetitive code
        match cidr.msbit() {
            0 => {
                match self.zero {
                    Some(ref mut child) => {
                        child.insert(&next_cidr, data);
                    },
                    None => {
                        let mut child = CidrTree::<T>::new();
                        child.insert(&next_cidr, data);
                        self.zero = Some(Box::new(child));
                    },
                }
            },
            _ => {
                match self.one {
                    Some(ref mut child) => {
                        child.insert(&next_cidr, data);
                    },
                    None => {
                        let mut child = CidrTree::<T>::new();
                        child.insert(&next_cidr, data);
                        self.one = Some(Box::new(child));
                    },
                }
            },
        }
    }
}

#[test]
fn test_insert_v4() {
    let mut t = CidrTree::<String>::new();

    t.insert(&Cidr::from_str("128.0.0.0/1").unwrap(), Some("first".to_string()));

    assert!(t.get_from_str(&"1.0.0.0").is_empty());
    assert!(t.get_from_str(&"128.0.0.0").len() == 1);
    assert!(t.get_from_str(&"255.0.0.0").len() == 1);
    assert!(t.get_from_str(&"128.0.0.0")[0].unwrap() == "first");
    assert!(t.get_from_str(&"128.1.0.0").len() == 1);
    assert!(t.get_from_str(&"128.0.0.0/8").len() == 1);

    t.insert(&Cidr::from_str("255.0.0.0/2").unwrap(), Some("second".to_string()));

    assert!(t.get_from_str(&"1.0.0.0").is_empty());
    assert!(t.get_from_str(&"128.0.0.0").len() == 1);
    assert!(t.get_from_str(&"255.0.0.0").len() == 2);
    assert!(t.get_from_str(&"128.0.0.0")[0].unwrap() == "first");
    assert!(t.get_from_str(&"128.1.0.0").len() == 1);
    assert!(t.get_from_str(&"128.0.0.0/8").len() == 1);
    assert!(t.get_from_str(&"255.0.0.0").len() == 2);
    assert!(t.get_from_str(&"255.1.0.0").len() == 2);
    assert!(t.get_from_str(&"255.0.0.0/8").len() == 2);
}

#[test]
fn test_insert_v6() {
    let mut t = CidrTree::<String>::new();

    t.insert(&Cidr::from_str("8000:0:0:0::/1").unwrap(), Some("first".to_string()));
    assert!(t.get_from_str(&"0001:0:0:0::").is_empty());
    assert!(t.get_from_str(&"8000::").len() == 1);
    assert!(t.get_from_str(&"F000::").len() == 1);
    assert!(t.get_from_str(&"8000::1").len() == 1);
    assert!(t.get_from_str(&"8000::/8").len() == 1);

    t.insert(&Cidr::from_str("F000:0:0:0::/2").unwrap(), Some("second".to_string()));

    assert!(t.get_from_str(&"0001:0:0:0::").is_empty());
    assert!(t.get_from_str(&"8000::").len() == 1);
    assert!(t.get_from_str(&"F000::").len() == 2);
    assert!(t.get_from_str(&"8000::1").len() == 1);
    assert!(t.get_from_str(&"8000::/8").len() == 1);
    assert!(t.get_from_str(&"F000::").len() == 2);
    assert!(t.get_from_str(&"F800::").len() == 2);
    assert!(t.get_from_str(&"F000::/8").len() == 2);
}

#[test]
fn test_has_exact() {
    let mut t = CidrTree::<String>::new();

    t.insert(&Cidr::from_str("128.0.0.0/1").unwrap(), None);

    assert!(!t.has_exact(&Cidr::from_str("1.0.0.0").unwrap()));
    assert!(t.has_exact(&Cidr::from_str("128.0.0.0/1").unwrap()));
    assert!(t.has_exact(&Cidr::from_str("128.0.0.0/0").unwrap()));
    assert!(!t.has_exact(&Cidr::from_str("128.0.0.0/32").unwrap()));

    t.insert(&Cidr::from_str("255.0.0.0/8").unwrap(), None);

    assert!(t.has_exact(&Cidr::from_str("255.0.0.0/8").unwrap()));
    assert!(!t.has_exact(&Cidr::from_str("128.0.0.0/8").unwrap()));
}

#[test]
fn test_covers() {
    let mut t = CidrTree::<String>::new();

    assert!(t.covers(&Cidr::from_str("0.0.0.0/0").unwrap()));
    assert!(!t.covers(&Cidr::from_str("128.0.0.0/1").unwrap()));

    t.insert(&Cidr::from_str("128.0.0.0/1").unwrap(), None);

    assert!(t.covers(&Cidr::from_str("128.0.0.0/1").unwrap()));
    assert!(t.covers(&Cidr::from_str("128.0.0.0/32").unwrap()));
    assert!(!t.covers(&Cidr::from_str("1.0.0.0").unwrap()));
}
