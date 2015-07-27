Frank jwt [![Build Status](https://travis-ci.org/GildedHonour/frank_jwt.svg)](https://travis-ci.org/GildedHonour/frank_jwt)
================================================

Implementation of JSON JWT in Rust [JSON Web Tokens](http://jwt.io). It supports HS256, 384 and 512 signature algorithms.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies.jwt]
git = "https://github.com/GildedHonour/frank_jwt"
```
Or find it at https://crates.io/crates/frank_jwt and install from there.

And this in your crate root:

```rust
extern crate jwt;

use jwt::Header;
use jwt::Payload;
use jwt::encode;
use jwt::decode;
use jwt::Algorithm;
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

