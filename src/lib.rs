/**
 * Copyright (c) 2015-2017 Alex Maslakov, <http://gildedhonour.com>, <http://alexmaslakov.com>
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
extern crate openssl;

use rustc_serialize::base64;
use rustc_serialize::base64::{ToBase64, FromBase64};
use rustc_serialize::json;
use rustc_serialize::json::{ToJson, Json};

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::str;

//use openssl::crypto::rsa::RSA;
//use openssl::crypto::hash::Hasher;

use openssl::sign::Signer;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use openssl::rsa::Rsa;

pub type Payload = BTreeMap<&str, &str>; //todo replace with &str

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
  RS256,
  RS384,
  RS512,
  ES256,
  ES384,
  ES512
}

impl ToString for Algorithm {
  fn to_string(&self) -> String {
    match *self {
      Algorithm::HS256 => "HS256".to_string(),
      Algorithm::HS384 => "HS384".to_string(),
      Algorithm::HS512 => "HS512".to_string(),
      Algorithm::RS256 => "RS256".to_string(),
      Algorithm::RS384 => "RS384".to_string(),
      Algorithm::RS512 => "RS512".to_string(),
      Algorithm::ES256 => "ES256".to_string(),
      Algorithm::ES384 => "ES384".to_string(),
      Algorithm::ES512 => "ES512".to_string()
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

pub fn encode(header: Header, key: String, payload: Payload) -> String {
  let signing_input = get_signing_input(payload, &header.algorithm);
  let signature = match header.algorithm {
    Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => sign_hmac(&signing_input, key, header.algorithm),
    Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => sign_rsa(&signing_input, key, header.algorithm),
    Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => sign_rsa(&signing_input, key, header.algorithm),
  };

  format!("{}.{}", signing_input, signature)
}

pub fn decode(encoded_token: String, key: String, algorithm: Algorithm) -> Result<(Header, Payload), Error> {
  match decode_segments(encoded_token) {
    Some((header, payload, signature, signing_input)) => {
      if !verify_signature(algorithm, signing_input, &signature, key.to_string()) {
        return Err(Error::SignatureInvalid)
      }

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

fn sign_hmac(data: &str, key: String, algorithm: Algorithm) -> String {
  let stp = match algorithm {
    Algorithm::HS256 => MessageDigest::sha256(),
    Algorithm::HS384 => MessageDigest::sha384(),
    Algorithm::HS512 => MessageDigest::sha512(),
    _  => panic!("Invalid hmac algorithm")
  };

  let key = PKey::hmac(key).unwrap();
  let mut signer = Signer::new(stp, &key).unwrap();
  singer.update(data).unwrap();
  let hmac = signer.finish().unwrap();
  base64_url_encode(&hmac)
}

fn sign_rsa(data: &str, private_key_path: String, algorithm: Algorithm) -> String {
  let hmac = match algorithm {
    Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512=> {


//  let key = PKey::hmac(key).unwrap();
  let mut signer = Signer::new(stp, &key).unwrap();
  singer.update(data).unwrap();




      let mut buffer = File::open(private_key_path).unwrap();
      let private_key = Rsa::private_key_from_pem(&mut buffer).unwrap();
      let pkey = PKey::from_rsa(private_key).unwrap();



      let stp = get_sha_algorithm(algorithm);
      let mut sha = Hasher::new(stp);
      sha.write_all(&signing_input.as_bytes()).unwrap();
      let digest = sha.finish();
      private_key.sign(stp, &digest).unwrap()


//////////

//  let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
//  signer.update(INPUT).unwrap();
//  let result = signer.finish().unwrap();

//  assert_eq!(result, SIGNATURE);
//////////
    },
    _  => panic!("Invalid rsa algorithm")
  };

  base64_url_encode(&hmac)
}

fn sign_es(signing_input: &str, private_key_path: String, algorithm: Algorithm) -> String {
  let hmac = match algorithm {
    Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512=> {
      let mut buffer = File::open(private_key_path).unwrap();
      let private_key = RSA::private_key_from_pem(&mut buffer).unwrap();
      let stp = get_sha_algorithm(algorithm);
      let mut sha = Hasher::new(stp);
      sha.write_all(&signing_input.as_bytes()).unwrap();
      let digest = sha.finish();
      private_key.sign(stp, &digest).unwrap()
    },
    _  => panic!("Invalid rsa algorithm")
  };

  base64_url_encode(&hmac)
}

fn decode_segments(encoded_token: String) -> Option<(Header, Payload, Vec<u8>, String)> {
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

//todo - move to Algorithm
fn parse_algorithm(alg: &str) -> Algorithm {
  match alg {
    "HS256" => Algorithm::HS256,
    "HS384" => Algorithm::HS384,
    "HS512" => Algorithm::HS512,
    "RS256" => Algorithm::RS256,
    _ => panic!("Unknown algorithm")
  }
}

//todo refactor
fn sign_hmac2(data: &str, key: String, algorithm: Algorithm) -> Vec<u8> {
  let stp = match algorithm {
    Algorithm::HS256 => MessageDigest::sha256(),
    Algorithm::HS384 => MessageDigest::sha384(),
    Algorithm::HS512 => MessageDigest::sha512(),
    _  => panic!("Invalid hmac algorithm")
  };

//  hmac(stp, key.as_bytes(), signing_input.as_bytes())

//
  let key = PKey::hmac(key).unwrap();
  let mut signer = Signer::new(stp, &key).unwrap();
  singer.update(data).unwrap();
  signer.finish().unwrap(); //hmac
}

//todo refactor
fn verify_signature(algorithm: Algorithm, signing_input: String, signature: &[u8], key: String) -> bool {
  match algorithm {
    Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
      let signature2 = sign_hmac2(&signing_input, key, algorithm);
      secure_compare(signature, &signature2)
    },

    Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
      let mut buffer = File::open(key).unwrap();
      let public_key = Rsa::public_key_from_pem(&mut buffer).unwrap();

      let mut sha = Hasher::new(Type::SHA256);
      sha.write_all(&signing_input.as_bytes()).unwrap();
      let digest = sha.finish();

      let stp = get_sha_algorithm(algorithm);
      public_key.verify(stp, &digest, signature).unwrap()
    },

    Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => {
      let mut buffer = File::open(key).unwrap();
      let public_key = Rsa::public_key_from_pem(&mut buffer).unwrap();

      let mut sha = Hasher::new(Type::SHA256);
      sha.write_all(&signing_input.as_bytes()).unwrap();
      let digest = sha.finish();

      let stp = get_sha_algorithm(algorithm);
      public_key.verify(stp, &digest, signature).unwrap()
    }
  }
}

fn get_sha_algorithm(alg: Algorithm) -> MessageDigest {
  match alg {
    Algorithm::RS256 => MessageDigest::sha256(),
    Algorithm::RS384 => Type::SHA384,
    Algorithm::RS512 => Type::SHA512,
    _  => panic!("Invalid rsa algorithm")
  }
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

/*
#[cfg(test)]
mod tests {
  extern crate time;

  use super::Header;
  use super::Payload;
  use super::encode;
  use super::decode;
  use super::Algorithm;
  use super::secure_compare;
  use std::env;

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

  #[test]
  fn test_encode_and_decode_jwt_rs256() {
    let mut p1 =  Payload::new();
    p1.insert("key12".to_string(), "val1".to_string());
    p1.insert("key22".to_string(), "val2".to_string());
    p1.insert("key33".to_string(), "val3".to_string());
    let header = Header::new(Algorithm::RS256);

    let mut path = env::current_dir().unwrap();
    path.push("test");
    path.push("my_rsa_2048_key.pem");
    let path2 = path.to_str().unwrap().to_string();

    let jwt1 = encode(header, get_rsa_256_private_key_full_path(), p1.clone());
    let maybe_res = decode(jwt1, get_rsa_256_public_key_full_path(), Algorithm::RS256);
    assert!(maybe_res.is_ok());
  }

 #[test]
  fn test_decode_valid_jwt_rs256() {
    let mut p1 = Payload::new();
    p1.insert("key1".to_string(), "val1".to_string());
    p1.insert("key2".to_string(), "val2".to_string());
    let header = Header::new(Algorithm::RS256);
    let jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0.DFusERCFWCL3CkKBaoVKsi1Z3QO2NTTRDTGHPqm7ctzypKHxLslJXfS1p_8_aRX30V2osMAEfGzXO9U0S9J1Z7looIFNf5rWSEcqA3ah7b7YQ2iTn9LOiDWwzVG8rm_HQXkWq-TXqayA-IXeiX9pVPB9bnguKXy3YrLWhP9pxnhl2WmaE9ryn8WTleMiElwDq4xw5JDeopA-qFS-AyEwlc-CE7S_afBd5OQBRbvgtfv1a9soNW3KP_mBg0ucz5eUYg_ON17BG6bwpAwyFuPdDAXphG4hCsa7GlXea0f7DnYD5e5-CA6O7BPW_EvjaGhL_D9LNWHJuDiSDBwZ4-IEIg";
    let jwt2 = encode(header, get_rsa_256_private_key_full_path(), p1.clone());
    assert_eq!(jwt1, jwt2);
  }

 #[test]
  fn test_decode_valid_jwt_rs256_and_check_deeply() {
    let mut p1 = Payload::new();
    p1.insert("key1".to_string(), "val1".to_string());
    p1.insert("key2".to_string(), "val2".to_string());
    let h1 = Header::new(Algorithm::RS256);
    let jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0.DFusERCFWCL3CkKBaoVKsi1Z3QO2NTTRDTGHPqm7ctzypKHxLslJXfS1p_8_aRX30V2osMAEfGzXO9U0S9J1Z7looIFNf5rWSEcqA3ah7b7YQ2iTn9LOiDWwzVG8rm_HQXkWq-TXqayA-IXeiX9pVPB9bnguKXy3YrLWhP9pxnhl2WmaE9ryn8WTleMiElwDq4xw5JDeopA-qFS-AyEwlc-CE7S_afBd5OQBRbvgtfv1a9soNW3KP_mBg0ucz5eUYg_ON17BG6bwpAwyFuPdDAXphG4hCsa7GlXea0f7DnYD5e5-CA6O7BPW_EvjaGhL_D9LNWHJuDiSDBwZ4-IEIg";
    let res = decode(jwt1.to_string(), get_rsa_256_public_key_full_path(), Algorithm::RS256);
    match res {
      Ok((h2, p2)) => {
        assert_eq!(h1.ttype, h2.ttype);
        assert_eq!(h1.algorithm.to_string(), h2.algorithm.to_string()); //todo implement ==
        for (k, v) in &p1 {
          assert_eq!(true, p2.contains_key(k));
          assert_eq!(v, p2.get(k).unwrap());
        }
      },
      Err(e) => panic!("Error")
    }
  }

  fn get_rsa_256_private_key_full_path() -> String {
    let mut path = env::current_dir().unwrap();
    path.push("test");
    path.push("my_rsa_2048_key.pem");
    path.to_str().unwrap().to_string()
  }

  fn get_rsa_256_public_key_full_path() -> String {
    let mut path = env::current_dir().unwrap();
    path.push("test");
    path.push("my_rsa_public_2048_key.pem");
    path.to_str().unwrap().to_string()
  }
}

*/
