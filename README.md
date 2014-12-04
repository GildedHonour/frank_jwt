rust-jwt
================================================

Implementation of JSON JWT in Rust [JSON Web Tokens](http://jwt.io). It supports RS256 signature algorithm.


## Example

```
let mut p1 = TreeMap::new();
p1.insert("key1".to_string(), "val1".to_string());
p1.insert("key2".to_string(), "val2".to_string());
p1.insert("key3".to_string(), "val3".to_string());
let secret = "secret123";

let jwt = encode(p1.clone(), secret);
```


## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
??? = "*"
```

And this in your crate root:

```rust
extern crate ???;
```

## Licence

[GNU GPL v3.0](https://raw.github.com/GildedHonour/rust-jwt/master/LICENCE)

## Tests

```shell
cargo test
```

