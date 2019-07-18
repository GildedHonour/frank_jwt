Frank JWT [![Build Status](https://travis-ci.org/GildedHonour/frank_jwt.svg)](https://travis-ci.org/GildedHonour/frank_jwt) [![crates.io](https://img.shields.io/crates/v/frank_jwt.svg)](https://crates.io/crates/frank_jwt)
================================================

Implementation of [JSON Web Tokens](https://jwt.io) in Rust.

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
- [ ] iss (issuer) check
- [ ] sub (subject) check
- [ ] aud (audience) check
- [x] exp (expiration time) check
- [ ] nbf (not before time) check
- [ ] iat (issued at) check
- [ ] jti (JWT id) check

## Usage

Put this into your `Cargo.toml`:

```toml
[dependencies]
frank_jwt = "<current version of frank_jwt>"
```

And this in your crate root:

```rust
extern crate frank_jwt;
#[macro_use] extern crate serde_json;


use frank_jwt::{Algorithm, encode, decode};
```

## Example

```rust
//HS256
let mut payload = json!({
    "key1": "val1",
    "key2": "val2"
});

let mut header = json!({});
let secret = "secret123";
let jwt = encode(&header, secret.to_string(), &payload, Algorithm::HS256);

//RS256
use std::env;

let mut payload = json!({
    "key1": "val1",
    "key2": "val2"
});

let mut header = json!({});
let mut keypath = env::current_dir().unwrap();
keypath.push("some_folder");
keypath.push("my_rsa_2048_key.pem");
let jwt = encode(&header, &keypath.to_path_buf(), &payload, Algorithm::RS256);
let (header, payload) = decode(&jwt, &keypath.to_path_buf(), Algorithm::RS256, &ValidationOptions::default());
```

## Validation Options
The ValidationOptions structure allows for control over which checks should be preformed when decoding a JWT. Calling new on this will provide a default set of values. There is also a dangerous function that will return validation options that doesn't perform any checking.

The default values are:

* Perform expiry check
* Allow 0 leeway for the expiry check.

It's worth noting that if the expiry check is requested and an exp claim is not within the JWT the check will fail validation.

## License

Apache 2.0

## Tests

```shell
cargo test
```


## Contributors

TODO
