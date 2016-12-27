# cidr-tree [![Build Status](https://travis-ci.org/aromatt/cidr-tree.svg?branch=master)](https://travis-ci.org/aromatt/cidr-tree)
A tree-based associative data structure for CIDR blocks, in Rust

Currently implemented as a binary tree (a [radix tree](https://en.wikipedia.org/wiki/Radix_tree) would be more compact)

## Overview
The primary data type provided is `CidrTree<T>`, where the keys are CIDR blocks (i.e.
IP addresses and networks) and the values are `T`.

## Usage
Insert data into the tree using `insert()`, which accepts a key (an IP address or network) and
a value.
You can then query the tree to determine the values associated with a given key and all
networks which include that key. Results are returned as a `Vec<T>`.

### Examples
```rust
let mut tree = CidrTree::<String>::new();

let cidr = Cidr::from_str("128.0.0.0/1").unwrap();
tree.insert(&cidr, "first".to_string());

let fetched = t.get_from_str(&"128.0.0.0");
assert!(fetched.len() == 1);
assert!(fetched[0] == "first");
```

```rust
let mut tree = CidrTree::<String>::new();

tree.insert(&Cidr::from_str("128.0.0.0/1").unwrap(), "first".to_string());
tree.insert(&Cidr::from_str("255.0.0.0/8").unwrap(), "second".to_string());

assert!(t.get_from_str(&"128.0.0.0").len() == 1);

// This address is a member of both "128.0.0.0/1" and "255.0.0.0/8"
assert!(t.get_from_str(&"255.0.0.0").len() == 2);

// You can query for networks too
assert!(t.get_from_str(&"255.0.0.0/8").len() == 2);
```

```rust
let mut tree = CidrTree::<String>::new();

# IPv6
tree.insert(&Cidr::from_str("8000:0:0:0::"/1).unwrap(), "first".to_string());

assert!(t.get_from_str(&"8000:0:0:0::").len() == 1);
assert!(t.get_from_str(&"F000::").len() == 1);
```
