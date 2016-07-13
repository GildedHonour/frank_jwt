Frank JWT [![Build Status](https://travis-ci.org/GildedHonour/frank_jwt.svg)](https://travis-ci.org/GildedHonour/frank_jwt) [![crates.io](https://img.shields.io/crates/v/frank_jwt.svg)](https://crates.io/crates/frank_jwt)
================================================

Implementation of [JSON Web Tokens](http://jwt.io) in Rust. It supports HS and RS256, 384 and 512 signature algorithms.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
frank_jwt = "2.2.0"
```

And this in your crate root:

```rust
extern crate frank_jwt;

use frank_jwt::{Header, Payload, Algorithm, encode, decode};
```

## Example

```rust
//HS256
let mut payload = Payload::new();
payload.insert("key1".to_string(), "val1".to_string());
payload.insert("key2".to_string(), "val2".to_string());
let header = Header::new(Algorithm::HS256);

let secret = "secret123";

let jwt = encode(header, secret.to_string(), payload.clone());

//RS256
use std::env;

let mut payload = Payload::new();
payload.insert("key1".to_string(), "val1".to_string());
payload.insert("key2".to_string(), "val2".to_string());
let header = Header::new(Algorithm::HS256);

let mut path = env::current_dir().unwrap();
path.push("some_folder");
path.push("my_rsa_2048_key.pem");
let key_path = path.to_str().unwrap().to_string();

let jwt = encode(header, key_path, payload.clone());
```

## License

Apache 2.0

## Tests

```shell
cargo test
```

## I'm available for hire
I'm a freelance developer and looking forward to new challenges.

me@gildedhonour.com | www.gildedhonour.com