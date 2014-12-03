extern crate serialize;
extern crate time;
extern crate "rust-crypto" as rust_crypto;

use serialize::base64;
use serialize::base64::{ToBase64, FromBase64};
use serialize::json::ToJson;
use serialize::json;
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

fn encode_jwt(payload: TreeMap<String, String>, key: &str) -> String {
  let signing_input = get_signing_input(payload);
  let signature = sign_hmac256(signing_input.as_slice(), key);
  format!("{}.{}", signing_input, signature)
}

fn get_signing_input(payload: TreeMap<String, String>) -> String {
  let header = JwtHeader {alg: "HS256", typ: "JWT"};
  let header_json_str = header.to_json();
  let encoded_header = base64_url_encode(header_json_str.to_string().as_bytes()).to_string();

  let mut payload_json = TreeMap::new();
  for (k, v) in payload.iter() {
    payload_json.insert(k.to_string(), v.to_json());
  }
  
  let payload_json = json::Object(payload_json);
  let encoded_payload = base64_url_encode(payload_json.to_string().as_bytes()).to_string();

  format!("{}.{}", encoded_header, encoded_payload)
}

fn sign_hmac256(signing_input: &str, key: &str) -> String {
  let mut hmac = Hmac::new(Sha256::new(), key.to_string().as_bytes());
  hmac.input(signing_input.to_string().as_bytes());
  let res = hmac.result();
  base64_url_encode(res.code())
}

fn base64_url_encode(bytes: &[u8]) -> String {
  bytes.to_base64(base64::URL_SAFE)
}



//decoding
fn decode_jwt(jwt: &str, key: &str, verify: bool) -> (Json, Json) {
  let(header, payload, signature, signing_input) = decoded_segments(jwt, verify);
  if verify {
    let a = verify_signature(key, signing_input.as_slice(), signature.as_slice());
    println!("valid? {}", a);
  }

  (header, payload)
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
  // println!("signature: {}, \nsigning_input: {}", signature, signing_input); //todo
  (header, payload, signature, signing_input)
}

fn decode_header_and_payload(header_segment: &str, payload_segment: &str) -> (Json, Json) {
  let a = header_segment.as_bytes().from_base64();
  let a1 = a.unwrap();
  let header = str::from_utf8(a1.as_slice()).unwrap();

  let b = payload_segment.as_bytes().from_base64();
  let b1 = b.unwrap();
  let payload = str::from_utf8(b1.as_slice()).unwrap(); 
  (json::from_str(header).unwrap(), json::from_str(payload).unwrap())
}

fn verify_signature(key: &str, signing_input: &str, signature_bytes: &[u8]) -> bool {
  let mut hmac = Hmac::new(Sha256::new(), key.to_string().as_bytes());
  hmac.input(signing_input.to_string().as_bytes());
  let b = hmac.result();
  let b1 = b.code();

  // println!("\n\na:\n {} \n\n\nb:\n {}\n\n\n", signature_bytes, b1);
  signature_bytes == b1
}



//main
fn main() {
  let mut payload = TreeMap::new();
  payload.insert("key1111".to_string(), "val1222".to_string());
  payload.insert("key2".to_string(), "val2".to_string());
  payload.insert("key3".to_string(), "val3".to_string());
  let key = "some_key";
  let jwt_token = encode_jwt(payload, key);
  // println!("jwt_token is {}\n\n", jwt_token);
  let (header, payload2) = decode_jwt(jwt_token.as_slice(), key, true);
  // println!("header is {}, payload2 is {}\n", header, payload2);

}