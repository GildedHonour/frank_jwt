use std::vec::{Vec};
use std::collections::TreeMap;

extern crate time;

struct JwtSigner {
  secret: &str
}

impl JwtSigner {
  fn sign(claims: HashMap<&str, Object>, Options options) -> &str {
    // let algorithm = Algorithm.HS256;
    let algorithm = "";
    
    // if (options != null && options.algorithm != null)
    //     algorithm = options.algorithm;

    let segments = vec![encoded_header(algorithm).to_string(), encoded_payload(claims, options).to_string()];
    let es = encoded_signature(segments.map(|x| x + "."), key, algorithm).to_string();
    segments.push(es);
    segments.map_in_place(|x| x + ".")
    }
}