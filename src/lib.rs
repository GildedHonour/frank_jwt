extern crate serialize;
extern crate time;
extern crate "crypto" as crypto;

use serialize::base64;
use serialize::base64::{ToBase64, FromBase64};
use serialize::json;
use serialize::json::ToJson;
use serialize::json::Json;
use std::collections::BTreeMap;
use crypto::sha2::{Sha256, Sha384, Sha512};
use crypto::hmac::Hmac;
use crypto::digest::Digest;
use crypto::mac::Mac;
use std::str;
use std::from_str::FromStr;

struct Header<'a> {
  alg: Algorithm,
  typ: &'a str
}

impl<'a> Header<'a> {
  pub fn new(alg: Algorithm) -> Header<'a> {
    Header{alg: alg, typ: Header::std_type()}
  }
  
  pub fn new2(alg: &str) -> Header<'a> {
    match Header::algorithms().get(alg) {
      Some(x) => Header::new(*x),
      None => panic!("Unknown algorithm: {}", alg)
    }
  }

  pub fn std_type() -> String {
    "JWT".to_string()
  }

  pub fn alg_str(&self) -> String {
    for (key, value) in Header::algorithms().iter() {
      if value == self.alg {
        key
      }
    }

    unreachable!()
  }

  fn algorithms() -> BTreeMap<String, Algorithm> {
    let mut map = BTreeMap::new();
    map.insert("HS256".to_string(), Algorithm::HS256);
    map.insert("HS384".to_string(), Algorithm::HS384);
    map.insert("HS512".to_string(), Algorithm::HS512);
  }
}

struct Payload;

struct Token<'a> {
  header: Header<'a>,
  payload: Payload,
  signature: &'a str,
  signing_input: &'a str
}

impl<'a> Token<'a> {
  fn segments_count() -> usize {
    3
  }
}

pub enum Error {
  SignatureExpired,
  SignatureInvalid,
  JWTInvalid,
  IssuerInvalid,
  ExpirationInvalid,
  AudienceInvalid
}

enum Algorithm {
  HS256,
  HS384,
  HS512
}

impl<'a> ToJson for Header<'a> {
  fn to_json(&self) -> json::Json {
    let mut map = BTreeMap::new();
    map.insert("typ".to_string(), self.typ.to_json());
    map.insert("alg".to_string(), self.alg_str().to_json());
    Json::Object(map)
  }
}

pub fn sign(secret: &str, payload: BTreeMap<String, String>, algorithm: Option<Algorithm>) -> String {
  let signing_input = get_signing_input(payload, algorithm);
  let signature = sign_hmac(signing_input.as_slice(), secret, algorithm.unwrap_or(Algorithm::HS256));
  format!("{}.{}", signing_input, signature)
}

fn get_signing_input(payload: BTreeMap<String, String>, algorithm: Option<Algorithm>) -> String {
  let header = Header::new(algorithm.unwrap_or(Algorithm::HS256));
  let header_json_str = header.to_json();
  let encoded_header = base64_url_encode(header_json_str.to_string().as_bytes()).to_string();
  if !payload.is_empty() {
    let payload2 = payload.into_iter().map(|(k, v)| (k, v.to_json())).collect();
    let payload_json = Json::Object(payload2);
    let encoded_payload = base64_url_encode(payload_json.to_string().as_bytes()).to_string();
    format!("{}.{}", encoded_header, encoded_payload)
  } else {

  }
}

fn sign_hmac256(signing_input: &str, secret: &str) -> String {
  sign_hmac(signing_input, secret, Algorithm::HS256)
}

fn sign_hmac384(signing_input: &str, secret: &str) -> String {
  sign_hmac(signing_input, secret, Algorithm::HS384)
}

fn sign_hmac512(signing_input: &str, secret: &str) -> String {
  sign_hmac(signing_input, secret, Algorithm::HS512)
}

fn sign_hmac(signing_input: &str, secret: &str, algorithm: Algorithm) -> String {
  let mut hmac = Hmac::new(match algorithm {
      Algorithm::HS256 => Sha256::new(),
      Algorithm::HS384 => Sha384::new(),
      Algorithm::HS512 => Sha512::new()
    }, secret.to_string().as_bytes()
  );
  hmac.input(signing_input.to_string().as_bytes());
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

pub fn verify<'a>(jwt_token: &str, secret: &str, options: BTreeMap<String, String>) -> Result<Token<'a>, Error> {
  // if signing_input.is_empty() || signing_input.is_whitespace() {
  //   return None
  // }
  match decode_segments(jwt_token, true) {
    Ok((header, payload, signing_input, signature)) => {
      if !verify_signature(header.alg, signing_input, signature.as_slice(), secret) {
        Err(Error::SignatureInvalid)
      }
      // verify_issuer(payload_json);
      // verify_expiration(payload_json);
      // verify_audience();
      // verify_subject();
      // verify_notbefore();
      // verify_issuedat();
      // verify_jwtid();

      let token = Token::new();
      Ok(token)
    },

    Err(err) => Err(err)
  }
}

fn decode_segments(jwt_token: &str, perform_verification: bool) -> Result<(Header, BTreeMap<String, String>, String, Vec<u8>), Error> {
  let mut raw_segments = jwt_token.split_str(".");
  if raw_segments.count() != Token::segments_count() {
    return Err(Error::JWTInvalid)
  }

  let header_segment = raw_segments.next().unwrap();
  let payload_segment = raw_segments.next().unwrap();
  let crypto_segment =  raw_segments.next().unwrap();
  let (header, payload) = decode_header_and_payload(header_segment, payload_segment);
  let signature = if perform_verification {
    crypto_segment.as_bytes().from_base64().unwrap()
  } else {
    vec![]
  };

  let signing_input = format!("{}.{}", header_segment, payload_segment);
  Ok((header, payload, signing_input, signature))
}

fn decode_header_and_payload<'a>(header_segment: &str, payload_segment: &str) -> (Header<'a>, BTreeMap<String, String>) {
  fn base64_to_json(input: &str) -> Json {
    let bytes = input.as_bytes().from_base64().unwrap();
    let s = str::from_utf8(bytes.as_slice()).unwrap();
    json::from_str(s).unwrap()
  };

  let header_json = base64_to_json(header_segment);
  let header_tree = json_to_tree(header_json);
  let header = Header::new2(header_tree.get("alg").unwrap().as_slice());
  let payload_json = base64_to_json(payload_segment);
  let payload = json_to_tree(payload_json);
  (header, payload)
}

fn verify_signature(algorithm: Algorithm, signing_input: &str, signature: &[u8], secret: &str) -> bool {
  let mut hmac = Hmac::new(match algorithm {
      Algorithm::HS256 => Sha256::new(),
      Algorithm::HS384 => Sha384::new(),
      Algorithm::HS512 => Sha512::new(),
      _ => panic!()
    }, secret.to_string().as_bytes()
  );

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

fn verify_issuer(payload_json: Json, iss: &str) -> bool {
  // take "iss" from payload_json
  // take "iss" from ...
  // make sure they're equal

  // if iss.is_empty() || signing_input.as_slice().is_whitespace() {
  //   return Err(Error::IssuerInvalid)
  // }
  unimplemented!()
}

fn verify_expiration(payload_json: Json) -> bool {
  let payload = json_to_tree(payload_json);
  if payload.contains_key("exp") {
    match payload.get("exp").unwrap().parse()::<i64>() {
      Some(exp) => exp > time::get_time().sec,
      None => panic!()
    }
    // if exp.is_empty() || signing_input.as_slice().is_whitespace() {
    //  return false
    // }
    
    
  } else {
    false
  }
}

fn verify_audience(payload_json: Json, aud: &str) -> bool {
  unimplemented!()
}

fn verify_subject(payload_json: Json) -> bool {
  unimplemented!()
}

fn verify_notbefore(payload_json: Json) -> bool {
  unimplemented!()
}

fn verify_issuedat(payload_json: Json) -> bool {
  unimplemented!()
}

fn verify_jwtid(payload_json: Json) -> bool {
  unimplemented!()
}

fn verify_generic(payload_json: Json, parameter_name: String) -> bool {
  let payload = json_to_tree(payload_json);
  if payload.contains_key(&parameter_name) {
    
  }

  unimplemented!()
}

#[cfg(test)]
mod tests {
  extern crate time;

  use super::sign;
  use super::verify;
  use super::secure_compare;
  use super::Algorithm;
  use std::collections::BTreeMap;
  use std::time::duration::Duration;

  #[test]
  fn test_encode_and_decode_jwt() {
    let mut p1 = BTreeMap::new();
    p1.insert("key1".to_string(), "val1".to_string());
    p1.insert("key2".to_string(), "val2".to_string());
    p1.insert("key3".to_string(), "val3".to_string());

    let secret = "secret123";
    let jwt1 = sign(secret, Some(p1.clone()), Some(Algorithm::HS256));
    let maybe_res = verify(jwt1.as_slice(), secret, None);

    assert!(maybe_res.is_ok());
    assert_eq!(jwt1, maybe_res.unwrap());
  } 

  #[test]
  fn test_decode_valid_jwt() {
    let mut p1 = BTreeMap::new();
    p1.insert("key11".to_string(), "val1".to_string());
    p1.insert("key22".to_string(), "val2".to_string());
    let secret = "secret123";
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxMSI6InZhbDEiLCJrZXkyMiI6InZhbDIifQ.jrcoVcRsmQqDEzSW9qOhG1HIrzV_n3nMhykNPnGvp9c";
    let maybe_res = verify(jwt.as_slice(), secret, None);
    
    assert!(maybe_res.is_ok());
    assert_eq!(p1, maybe_res.unwrap().payload);
  }

  #[test]
  fn test_fails_when_expired() {
    let now = time::get_time();
    let past = now + Duration::minutes(-5);
    let mut p1 = BTreeMap::new();
    p1.insert("exp".to_string(), past.sec.to_string());
    p1.insert("key1".to_string(), "val1".to_string());
    let secret = "secret123";
    let jwt = sign(secret, Some(p1.clone()), None);
    let res = verify(jwt.as_slice(), secret, None);
    assert!(res.is_ok());
  }

  #[test]
  fn test_ok_when_expired_not_verified() {
    let now = time::get_time();
    let past = now + Duration::minutes(-5);
    let mut p1 = BTreeMap::new();
    p1.insert("exp".to_string(), past.sec.to_string());
    p1.insert("key1".to_string(), "val1".to_string());
    let secret = "secret123";
    let jwt = sign(secret, Some(p1.clone()), None);
    let res = verify(jwt.as_slice(), secret, None);
    assert!(res.is_ok());
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

    let str3 = "same same".as_bytes();
    let str4 = "same ssss".as_bytes();
    let res2 = secure_compare(str3, str4);
    assert!(!res2);
  }
}