rust-jwt [![Build Status](https://travis-ci.org/GildedHonour/rust-jwt.svg)](https://travis-ci.org/GildedHonour/rust-jwt)
================================================

Implementation of JSON JWT in Rust [JSON Web Tokens](http://jwt.io). It supports RS256 signature algorithm.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies.jwt]
git = "https://github.com/GildedHonour/rust-jwt"
```

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

```
let mut payload = Payload::new();
payload.insert("key1".to_string(), "val1".to_string());
payload.insert("key2".to_string(), "val2".to_string());
payload.insert("key3".to_string(), "val3".to_string());

let secret = "secret123";
let header = Header::new(Algorithm::HS256);

let jwt = encode(header, secret.to_string(), payload.clone());
```

## License

It's dually licensed - MIT and Apache 2.0 like the Rust compiler itself.

## Tests

```shell
cargo test
```

