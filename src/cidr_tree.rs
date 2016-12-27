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
        println!(" cidr: {:?}, msbit: {:?}", cidr, cidr.msbit());
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

    pub fn get_from_str(&self, cidr: &str) -> Vec<Option<&T>> {
        println!("getting {:?}", Cidr::from_str(cidr).unwrap());
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
