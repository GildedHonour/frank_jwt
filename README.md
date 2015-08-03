Frank JWT [![Build Status](https://travis-ci.org/GildedHonour/frank_jwt.svg)](https://travis-ci.org/GildedHonour/frank_jwt) [![crates.io](https://img.shields.io/crates/v/frank_jwt.svg)](https://crates.io/crates/frank_jwt)
================================================

Implementation of [JSON Web Tokens](http://jwt.io) in Rust. It supports HS256, 384 and 512 signature algorithms.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
frank_jwt = "*"
```

And this in your crate root:

```rust
extern crate frank_jwt;

use frank_jwt::Header;
use frank_jwt::Payload;
use frank_jwt::encode;
use frank_jwt::decode;
use frank_jwt::Algorithm;
```

## Example

```rust
let mut payload = Payload::new();
payload.insert("key1".to_string(), "val1".to_string());
payload.insert("key2".to_string(), "val2".to_string());
payload.insert("key3".to_string(), "val3".to_string());

let secret = "secret123";
let header = Header::new(Algorithm::HS256);

let jwt = encode(header, secret.to_string(), payload.clone());
```

## License

Apache 2.0

## Tests

```shell
cargo test
```

