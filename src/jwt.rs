extern crate serialize;
extern crate time;
extern crate "rust-crypto" as rust_crypto;

use serialize::base64;
use serialize::base64::{ToBase64, FromBase64};
use serialize::json;
use serialize::json::ToJson;
use serialize::json::Json;
use std::collections::TreeMap;
use rust_crypto::sha2::Sha256;
use rust_crypto::hmac::Hmac;
use rust_crypto::digest::Digest;
use rust_crypto::mac::Mac;
use std::str;

struct JwtHeader<'a> {
  alg: &'a str,
  typ: &'a str
}

impl<'a> ToJson for JwtHeader<'a> {
  fn to_json(&self) -> json::Json {
    let mut map = TreeMap::new();
    map.insert("typ".to_string(), self.typ.to_json());
    map.insert("alg".to_string(), self.alg.to_json());
    json::Object(map)
  }
}

enum Error {
  SignatureExpired,
  SignatureInvalid,
  JWTInvalid
}

fn encode(payload: TreeMap<String, String>, key: &str) -> String {
  let signing_input = get_signing_input(payload);
  let signature = sign_hmac256(signing_input.as_slice(), key);
  format!("{}.{}", signing_input, signature)
}

fn get_signing_input(payload: TreeMap<String, String>) -> String {
  let header = JwtHeader {alg: "HS256", typ: "JWT"};
  let header_json_str = header.to_json();
  let encoded_header = base64_url_encode(header_json_str.to_string().as_bytes()).to_string();

  let payload = payload.into_iter().map(|(k, v)| (k, v.to_json())).collect();
  let payload_json = json::Object(payload);
  let encoded_payload = base64_url_encode(payload_json.to_string().as_bytes()).to_string();

  format!("{}.{}", encoded_header, encoded_payload)
}

fn sign_hmac256(signing_input: &str, key: &str) -> String {
  let mut hmac = Hmac::new(Sha256::new(), key.to_string().as_bytes());
  hmac.input(signing_input.to_string().as_bytes());
  base64_url_encode(hmac.result().code())
}

fn base64_url_encode(bytes: &[u8]) -> String {
  bytes.to_base64(base64::URL_SAFE)
}

fn decode(jwt: &str, key: &str, verify: bool, verify_expiration: bool) -> Result<(TreeMap<String, String>, TreeMap<String, String>), Error> {
  fn json_to_tree(input: Json) -> TreeMap<String, String> {
    match input {
      json::Object(json_tree) => json_tree.into_iter().map(|(k, v)| (k, match v {
          json::String(s) => s,
          _ => unreachable!()
      })).collect(),
      _ => unreachable!()
    }
  };

  let (header_json, payload_json, signature, signing_input) = decoded_segments(jwt, verify);
  if verify {
    let res = verify_signature(key, signing_input.as_slice(), signature.as_slice());
    if !res {
      return Err(Error::SignatureInvalid)
    } 
  }

  let header = json_to_tree(header_json);
  let payload = json_to_tree(payload_json);
  if verify_expiration {
    if payload.contains_key("exp") {
      let exp: i64 = from_str(payload.get("exp").unwrap().as_slice()).unwrap();
      let now = time::get_time().sec;
      if exp <= now {
        return Err(Error::SignatureExpired)
      }
    }
  }

  Ok((header, payload))
}

fn decoded_segments(jwt: &str, verify: bool) -> (Json, Json, Vec<u8>, String) {
  let mut raw_segments = jwt.split_str(".");
  let header_segment = raw_segments.next().unwrap();
  let payload_segment = raw_segments.next().unwrap();
  let crypto_segment =  raw_segments.next().unwrap();
  let (header, payload) = decode_header_and_payload(header_segment, payload_segment);
  let signature = if verify {
    crypto_segment.as_bytes().from_base64().unwrap()
  } else {
    vec![]
  };

  let signing_input = format!("{}.{}", header_segment, payload_segment);
  (header, payload, signature, signing_input)
}

fn decode_header_and_payload(header_segment: &str, payload_segment: &str) -> (Json, Json) {
  fn base64_to_json(input: &str) -> Json {
    let bytes = input.as_bytes().from_base64().unwrap();
    let s = str::from_utf8(bytes.as_slice()).unwrap();
    json::from_str(s).unwrap()
  };

  let header_json = base64_to_json(header_segment);
  let payload_json = base64_to_json(payload_segment);
  (header_json, payload_json)
}

fn verify_signature(key: &str, signing_input: &str, signature_bytes: &[u8]) -> bool {
  let mut hmac = Hmac::new(Sha256::new(), key.to_string().as_bytes());
  hmac.input(signing_input.to_string().as_bytes());
  signature_bytes == hmac.result().code()
}

#[cfg(test)]
mod tests {
  extern crate time;

  use super::encode;
  use super::decode;
  use std::collections::TreeMap;
  use std::time::duration::Duration;

  #[test]
  fn test_encode_and_decode_jwt() {
    let mut p1 = TreeMap::new();
    p1.insert("key1".to_string(), "val1".to_string());
    p1.insert("key2".to_string(), "val2".to_string());
    p1.insert("key3".to_string(), "val3".to_string());
    let secret = "secret123";

    let jwt = encode(p1.clone(), secret);
    let res = decode(jwt.as_slice(), secret, true, false);
    assert!(res.is_ok() && !res.is_err());
    let (_, p2) = res.ok().unwrap();
    assert_eq!(p1, p2);
  } 

  #[test]
  fn test_decode_valid_jwt() {
    let mut p1 = TreeMap::new();
    p1.insert("hello".to_string(), "world".to_string());
    let secret = "secret";
    let jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8";
    
    let res = decode(jwt.as_slice(), secret, true, false);
    assert!(res.is_ok() && !res.is_err());
    let (_, p2) = res.ok().unwrap();
    assert_eq!(p1, p2);
  }

  #[test]
  fn test_error_when_expired() {
    let now = time::get_time();
    let past = now + Duration::minutes(-5);
    let mut p1 = TreeMap::new();
    p1.insert("exp".to_string(), past.sec.to_string());
    p1.insert("key1".to_string(), "val1".to_string());
    let secret = "secret123";
    let jwt = encode(p1.clone(), secret);
    let res = decode(jwt.as_slice(), secret, true, true);
    assert!(!res.is_ok() && res.is_err());
  }

  #[test]
  fn test_ok_when_expired_not_verified() {
    let now = time::get_time();
    let past = now + Duration::minutes(-5);
    let mut p1 = TreeMap::new();
    p1.insert("exp".to_string(), past.sec.to_string());
    p1.insert("key1".to_string(), "val1".to_string());
    let secret = "secret123";
    let jwt = encode(p1.clone(), secret);
    let res = decode(jwt.as_slice(), secret, true, false);
    assert!(res.is_ok() && !res.is_err());
  }
}