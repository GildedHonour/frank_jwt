/**
 * Copyright (c) 2015 Alex Maslakov, <http://www.gildedhonour.com>, <http://www.alexmaslakov.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For questions and comments about this product, please see the project page at:
 *
 * https://github.com/GildedHonour/frank_jwt
 *
 */

extern crate rustc_serialize;
extern crate time;
extern crate crypto;

use rustc_serialize::base64;
use rustc_serialize::base64::{ToBase64, FromBase64};
use rustc_serialize::json;
use rustc_serialize::json::{ToJson, Json};
use std::collections::BTreeMap;
use crypto::sha2::{Sha256, Sha384, Sha512};
use crypto::hmac::Hmac;
use crypto::digest::Digest;
use crypto::mac::Mac;
use std::str;

pub type Payload = BTreeMap<String, String>; //todo replace with &str

pub struct Header {
  algorithm: Algorithm,
  ttype: String
}

impl Header {
  pub fn new(alg: Algorithm) -> Header {
    Header { algorithm: alg, ttype: Header::std_type() }
  }
  
  pub fn std_type() -> String {
    "JWT".to_string()
  }
}

#[derive(Clone, Copy)]
pub enum Algorithm {
  HS256,
  HS384,
  HS512,
  RS256
}

impl ToString for Algorithm {
  fn to_string(&self) -> String {
    match *self {
      Algorithm::HS256 => "HS256".to_string(),
      Algorithm::HS384 => "HS384".to_string(),
      Algorithm::HS512 => "HS512".to_string(),
      Algorithm::RS256 => "RS256".to_string()
    } 
  }
}

#[derive(Debug)]
pub enum Error {
  SignatureExpired,
  SignatureInvalid,
  JWTInvalid,
  IssuerInvalid,
  ExpirationInvalid,
  AudienceInvalid
}

impl ToJson for Header {
  fn to_json(&self) -> json::Json {
    let mut map = BTreeMap::new();
    map.insert("typ".to_string(), self.ttype.to_json());
    map.insert("alg".to_string(), self.algorithm.to_string().to_json());
    Json::Object(map)
  }
}

pub fn encode(header: Header, secret: String, payload: Payload) -> String {
  let signing_input = get_signing_input(payload, &header.algorithm);
  let signature = sign_hmac(&signing_input, secret, header.algorithm);
  format!("{}.{}", signing_input, signature)
}

pub fn decode(encoded_token: String, secret: String, algorithm: Algorithm) -> Result<(Header, Payload), Error> {
  match decode_segments(encoded_token) {
    Some((header, payload, signature, signing_input)) => {
      if !verify_signature(algorithm, signing_input, &signature, secret.to_string()) {
        return Err(Error::SignatureInvalid)
      }  
      //todo
      // verify_issuer(payload_json);
      // verify_expiration(payload_json);
      // verify_audience();
      // verify_subject();
      // verify_notbefore();
      // verify_issuedat();
      // verify_jwtid();

      //todo
      Ok((header, payload))
    },

    None => Err(Error::JWTInvalid)
  }
}

fn segments_count() -> usize {
  3
}

fn get_signing_input(payload: Payload, algorithm: &Algorithm) -> String {
  let header = Header::new(*algorithm);
  let header_json_str = header.to_json();
  let encoded_header = base64_url_encode(header_json_str.to_string().as_bytes()).to_string();
  let p = payload.into_iter().map(|(k, v)| (k, v.to_json())).collect();
  let payload_json = Json::Object(p);
  let encoded_payload = base64_url_encode(payload_json.to_string().as_bytes()).to_string();
  format!("{}.{}", encoded_header, encoded_payload)
}


fn sign_hmac(signing_input: &str, secret: String, algorithm: Algorithm) -> String {
  let mut hmac = match algorithm {
    Algorithm::HS256 => create_hmac(Sha256::new(), secret),
    Algorithm::HS384 => create_hmac(Sha384::new(), secret),
    Algorithm::HS512 => create_hmac(Sha512::new(), secret),
    Algorithm::RS256 => unimplemented!()
  };
  
  hmac.input(signing_input.as_bytes());
  base64_url_encode(hmac.result().code())
}

fn base64_url_encode(bytes: &[u8]) -> String {
  bytes.to_base64(base64::URL_SAFE)
}

fn json_to_tree(input: Json) -> BTreeMap<String, String> {
  match input {
    Json::Object(json_tree) => json_tree.into_iter().map(|(k, v)| (k, match v {
      Json::String(s) => s,
      _ => unreachable!()
    })).collect(),
    _ => unreachable!()
  }
}

fn decode_segments(encoded_token: String) ->  Option<(Header, Payload, Vec<u8>, String)> {
  let raw_segments: Vec<&str> = encoded_token.split(".").collect();
  if raw_segments.len() != segments_count() {
    return None
  }

  let header_segment = raw_segments[0];
  let payload_segment = raw_segments[1];
  let crypto_segment =  raw_segments[2];
  let (header, payload) = decode_header_and_payload(header_segment, payload_segment);
  let signature = &crypto_segment.as_bytes().from_base64().unwrap();

  let signing_input = format!("{}.{}", header_segment, payload_segment);
  Some((header, payload, signature.clone(), signing_input))
}

fn decode_header_and_payload<'a>(header_segment: &str, payload_segment: &str) -> (Header, Payload) {
  fn base64_to_json(input: &str) -> Json {
    let bytes = input.as_bytes().from_base64().unwrap();
    let s = str::from_utf8(&bytes).unwrap();
    Json::from_str(s).unwrap()
  };

  let header_json = base64_to_json(header_segment);
  let header_tree = json_to_tree(header_json);
  let alg = header_tree.get("alg").unwrap();
  let header = Header::new(parse_algorithm(alg));
  let payload_json = base64_to_json(payload_segment);
  let payload = json_to_tree(payload_json);
  (header, payload)
}

fn parse_algorithm(alg: &str) -> Algorithm {
  match alg {
    "HS256" => Algorithm::HS256,
    "HS384" => Algorithm::HS384,
    "HS512" => Algorithm::HS512,
    "RS256" => Algorithm::HS512,
    _ => panic!("Unknown algorithm")
  }
}

fn verify_signature(algorithm: Algorithm, signing_input: String, signature: &[u8], secret: String) -> bool {
  let mut hmac = match algorithm {
    Algorithm::HS256 => create_hmac(Sha256::new(), secret),
    Algorithm::HS384 => create_hmac(Sha384::new(), secret),
    Algorithm::HS512 => create_hmac(Sha512::new(), secret),
    Algorithm::RS256 => unimplemented!()
  };

  hmac.input(signing_input.to_string().as_bytes());
  secure_compare(signature, hmac.result().code())
}

fn secure_compare(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false
  }

  let mut res = 0_u8;
  for (&x, &y) in a.iter().zip(b.iter()) {
    res |= x ^ y;
  }

  res == 0
}

fn create_hmac<'a, D: Digest + 'a>(digest: D, some_str: String) -> Box<Mac + 'a> {
  Box::new(Hmac::new(digest, some_str.as_bytes()))
}

#[cfg(test)]
mod tests {
  extern crate time;

  use super::Header;
  use super::Payload;
  use super::encode;
  use super::decode;
  use super::Algorithm;
  use super::secure_compare;

  #[test]
  fn test_encode_and_decode_jwt_hs256() {
    let mut p1 =  Payload::new();
    p1.insert("key1".to_string(), "val1".to_string());
    p1.insert("key2".to_string(), "val2".to_string());
    p1.insert("key3".to_string(), "val3".to_string());

    let secret = "secret123";
    let header = Header::new(Algorithm::HS256);
    let jwt1 = encode(header, secret.to_string(), p1.clone());
    let maybe_res = decode(jwt1, secret.to_string(), Algorithm::HS256);
    assert!(maybe_res.is_ok());
  } 

  #[test]
  fn test_decode_valid_jwt_hs256() {
    let mut p1 = Payload::new();
    p1.insert("key11".to_string(), "val1".to_string());
    p1.insert("key22".to_string(), "val2".to_string());
    let secret = "secret123";
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxMSI6InZhbDEiLCJrZXkyMiI6InZhbDIifQ.jrcoVcRsmQqDEzSW9qOhG1HIrzV_n3nMhykNPnGvp9c";
    let maybe_res = decode(jwt.to_string(), secret.to_string(), Algorithm::HS256);
    assert!(maybe_res.is_ok());
  }

  #[test]
  fn test_secure_compare_same_strings() {
    let str1 = "same same".as_bytes();
    let str2 = "same same".as_bytes();
    let res = secure_compare(str1, str2);
    assert!(res);
  }

  #[test]
  fn test_fails_when_secure_compare_different_strings() {
    let str1 = "same same".as_bytes();
    let str2 = "same same but different".as_bytes();
    let res = secure_compare(str1, str2);
    assert!(!res);
  }


  #[test]
  fn test_encode_and_decode_jwt_hs384() {
    let mut p1 =  Payload::new();
    p1.insert("key1".to_string(), "val1".to_string());
    p1.insert("key2".to_string(), "val2".to_string());
    p1.insert("key3".to_string(), "val3".to_string());

    let secret = "secret123";
    let header = Header::new(Algorithm::HS384);
    let jwt1 = encode(header, secret.to_string(), p1.clone());
    let maybe_res = decode(jwt1, secret.to_string(), Algorithm::HS384);
    assert!(maybe_res.is_ok());
  }

    #[test]
  fn test_encode_and_decode_jwt_hs512() {
    let mut p1 =  Payload::new();
    p1.insert("key12".to_string(), "val1".to_string());
    p1.insert("key22".to_string(), "val2".to_string());
    p1.insert("key33".to_string(), "val3".to_string());

    let secret = "secret123456";
    let header = Header::new(Algorithm::HS512);
    let jwt1 = encode(header, secret.to_string(), p1.clone());
    let maybe_res = decode(jwt1, secret.to_string(), Algorithm::HS512);
    assert!(maybe_res.is_ok());
  }

//   #[test]
//   fn test_fails_when_expired() {
//     let now = time::get_time();
//     let past = now + Duration::minutes(-5);
//     let mut p1 = BTreeMap::new();
//     p1.insert("exp".to_string(), past.sec.to_string());
//     p1.insert("key1".to_string(), "val1".to_string());
//     let secret = "secret123";
//     let jwt = sign(secret, Some(p1.clone()), None);
//     let res = verify(jwt.as_slice(), secret, None);
//     assert!(res.is_ok());
//   }

//   #[test]
//   fn test_ok_when_expired_not_verified() {
//     let now = time::get_time();
//     let past = now + Duration::minutes(-5);
//     let mut p1 = BTreeMap::new();
//     p1.insert("exp".to_string(), past.sec.to_string());
//     p1.insert("key1".to_string(), "val1".to_string());
//     let secret = "secret123";
//     let jwt = sign(secret, Some(p1.clone()), None);
//     let res = verify(jwt.as_slice(), secret, None);
//     assert!(res.is_ok());
//   }
}