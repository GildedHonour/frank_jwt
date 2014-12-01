extern crate serialize;
extern crate time;
extern crate "rust-crypto" as rust_crypto;

use serialize::base64;
use serialize::base64::{ToBase64, FromBase64};
use serialize::json::ToJson;
use serialize::json;
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
    let mut d = TreeMap::new();
    d.insert("typ".to_string(), self.typ.to_json());
    d.insert("alg".to_string(), self.alg.to_json());
    json::Object(d)
  }
}

fn encode_jwt(payload: TreeMap<&str, &str>, key: &str) -> String {
  let signing_input = get_signing_input(payload);
  let signature = sign_hmac256(signing_input.as_slice(), key);
  format!("{}.{}", signing_input, signature)
}

fn get_signing_input(payload: TreeMap<&str, &str>) -> String {
  let header = JwtHeader {alg: "HS256", typ: "JWT"};
  
  let header_json_str = header.to_json();
  let mut payload_json = TreeMap::new();
  for (k, v) in payload.iter() {
    payload_json.insert(k.to_string(), v.to_json());
  }

  let encoded_header = base64_url_encode(header_json_str.to_string().as_bytes()).to_string();

  let payload_json_str = json::Object(payload_json);
  let encoded_payload = base64_url_encode(payload_json_str.to_string().as_bytes()).to_string();
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
fn decode_jwt(jwt: &str, key: &str) -> (String, String) {
  let(a, b, c, d) = decoded_segments(jwt);
  (a, b)
}

fn decoded_segments(jwt: &str) -> (String, String, String, String) {
  let mut raw_segments = jwt.split_str(".");
  let header_segment = raw_segments.next().unwrap();
  let payload_segment = raw_segments.next().unwrap();
  let crypto_segment =  raw_segments.next().unwrap();

  let (header, payload) = decode_header_and_payload(header_segment, payload_segment);
  println!("header: {}, payload: {}", header.to_string(), payload.to_string());
  let signature = ""; // base64url_decode(crypto_segment.to_s) if verify
  let signing_input = ""; // [header_segment, payload_segment].join(".")
  (header, payload, signature.to_string(), signing_input.to_string())
}

fn decode_header_and_payload(header_segment: &str, payload_segment: &str) -> (String, String) {
  let a = header_segment.as_bytes().from_base64();
  let a1 = a.unwrap();
  let header = str::from_utf8(a1.as_slice()).unwrap();

  let b = payload_segment.as_bytes().from_base64();
  let b1 = b.unwrap();
  let payload = str::from_utf8(b1.as_slice()).unwrap(); 
  (json::from_str(header).unwrap().to_string(), json::from_str(payload).unwrap().to_string())
}




//main
fn main() {
  let mut payload = TreeMap::new();
  payload.insert("key1111", "val1222");
  payload.insert("key2", "val2");
  let key = "some_key";
  let jwt_token = encode_jwt(payload, key);
  decode_jwt(jwt_token.as_slice(), key);
}