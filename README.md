Frank JWT [![Build Status](https://travis-ci.org/GildedHonour/frank_jwt.svg)](https://travis-ci.org/GildedHonour/frank_jwt) [![crates.io](https://img.shields.io/crates/v/frank_jwt.svg)](https://crates.io/crates/frank_jwt)
================================================

Implementation of [JSON Web Tokens](http://jwt.io) in Rust.

## Algorithms and features supported
- [x] HS256
- [x] HS384
- [x] HS512
- [x] RS256
- [x] RS384
- [x] RS512
- [x] ES256
- [x] ES384
- [x] ES512
- [x] Sign
- [x] Verify
- [x] iss (issuer) check
- [x] sub (subject) check
- [x] aud (audience) check
- [x] exp (expiration time) check
- [x] nbf (not before time) check
- [x] iat (issued at) check
- [x] jti (JWT id) check

## Usage

Put this into your `Cargo.toml`:

```toml
[dependencies]
frank_jwt = "<current version of frank_jwt>"
```

And this in your crate root:

```rust
extern crate frank_jwt;
#[macro_use]
serde_json;
use frank_jwt::{Algorithm, encode, decode};
```

## Example

```rust
//HS256
let mut payload = json!({
    "key1" : "val1",
    "key2" : "val2"
});
let mut header = json!({
});
let secret = "secret123";

let jwt = encode(&header, secret.to_string(), &payload, Algorithm::HS256);

//RS256
use std::env;

let mut payload = json!({
    "key1" : "val1",
    "key2" : "val2"
});
let mut header = json!({
});

let mut keypath = env::current_dir().unwrap();
keypath.push("some_folder");
keypath.push("my_rsa_2048_key.pem");

let jwt = encode(&header, &keypath.to_path_buf(), &payload, Algorithm::RS256);

let (header, payload) = decode(&jwt, &keypath.to_path_buf(), Algorithm::RS256);
```

## License

Apache 2.0

## Tests

```shell
cargo test
```

## I'm available for hire
I'm a freelance developer and looking forward to new challenges.

me@gildedhonour.com | gildedhonour.com
