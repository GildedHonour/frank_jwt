extern crate rustc_serialize;
extern crate time;
extern crate crypto;

// use std::time::duration::Duration;
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

pub type Payload = BTreeMap<String, String>;

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
  HS512
}

impl ToString for Algorithm {
  fn to_string(&self) -> String {
    unimplemented!() 
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

pub fn decode(encoded_token: String, secret: String) -> Result<(Header, Payload), Error> {
  unimplemented!()
}

pub fn is_valid(encoded_token: String, secret: String) -> bool {
  unimplemented!()
}

pub fn verify(encoded_token: String, secret: String, algorithm: Algorithm) -> Result<(Header, Payload), Error> {
  match decode_segments(encoded_token, true) {
    Some((header, payload, signature, signing_input)) => {
      if !verify_signature(algorithm, signing_input, signature.as_bytes(), secret.to_string()) {
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

// fn sign_hmac256(signing_input: String, secret: String) -> String {
//   sign_hmac(signing_input, secret, Algorithm::HS256)
// }

// fn sign_hmac384(signing_input: String, secret: String) -> String {
//   sign_hmac(signing_input, secret, Algorithm::HS384)
// }

// fn sign_hmac512(signing_input: String, secret: String) -> String {
//   sign_hmac(signing_input, secret, Algorithm::HS512)
// }

fn sign_hmac(signing_input: &str, secret: String, algorithm: Algorithm) -> String {
  let mut hmac = match algorithm {
    Algorithm::HS256 => create_hmac(Sha256::new(), secret),
    Algorithm::HS384 => create_hmac(Sha384::new(), secret),
    Algorithm::HS512 => create_hmac(Sha512::new(), secret)
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

fn decode_segments(encoded_token: String, perform_verification: bool) -> Option<(Header, Payload, String, String)> {
  let raw_segments: Vec<&str> = encoded_token.split(".").collect();
  if raw_segments.len() != segments_count() {
    return None
  }

  let header_segment = raw_segments[0];
  let payload_segment = raw_segments[1];
  let crypto_segment =  raw_segments[2];
  let (header, payload) = decode_header_and_payload(header_segment, payload_segment);

  // let signature = crypto_segment.as_bytes().from_base64().unwrap().as_slice();
  let signature = crypto_segment.as_bytes();
  let signature2 = signature.from_base64();
  let signature3 = signature2.unwrap();
  let signature4 = &signature3;
  match str::from_utf8(signature4) {
    Ok(x) => {
      let signing_input = format!("{}.{}", header_segment, payload_segment);
      Some((header, payload, x.to_string(), signing_input))
    },
    Err(_) => None
  }
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
    _ => panic!("Unknown algorithm")
  }
}

fn verify_signature(algorithm: Algorithm, signing_input: String, signature: &[u8], secret: String) -> bool {
  let mut hmac = match algorithm {
    Algorithm::HS256 => create_hmac(Sha256::new(), secret),
    Algorithm::HS384 => create_hmac(Sha384::new(), secret),
    Algorithm::HS512 => create_hmac(Sha512::new(), secret)
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

// fn verify_issuer(payload_json: Json, iss: &str) -> bool {
//   // take "iss" from payload_json
//   // take "iss" from ...
//   // make sure they're equal

//   // if iss.is_empty() || signing_input.as_slice().is_whitespace() {
//   //   return Err(Error::IssuerInvalid)
//   // }
//   unimplemented!()
// }

// fn verify_expiration(payload_json: Json) -> bool {
//   let payload = json_to_tree(payload_json);
//   if payload.contains_key("exp") {
//     match payload.get("exp").unwrap().parse::<i64>() {
//       Ok(exp) => exp > time::get_time().sec,
//       Err(e) => panic!(e)
//     }
//     // if exp.is_empty() || signing_input.as_slice().is_whitespace() {
//     //  return false
//     // }
    
    
//   } else {
//     false
//   }
// }

// fn verify_audience(payload_json: Json, aud: &str) -> bool {
//   unimplemented!()
// }

// fn verify_subject(payload_json: Json) -> bool {
//   unimplemented!()
// }

// fn verify_notbefore(payload_json: Json) -> bool {
//   unimplemented!()
// }

// fn verify_issuedat(payload_json: Json) -> bool {
//   unimplemented!()
// }

// fn verify_jwtid(payload_json: Json) -> bool {
//   unimplemented!()
// }

// fn verify_generic(payload_json: Json, parameter_name: String) -> bool {
//   let payload = json_to_tree(payload_json);
//   if payload.contains_key(&parameter_name) {
    
//   }

//   unimplemented!()
// }

fn create_hmac<'a, D: Digest + 'a>(digest: D, some_str: String) -> Box<Mac + 'a> {
  Box::new(Hmac::new(digest, some_str.as_bytes()))
}

 



// #[cfg(test)]
// mod tests {
//   extern crate time;

//   use super::sign;
//   use super::verify;
//   use super::secure_compare;
//   use super::Algorithm;
//   use std::collections::BTreeMap;
//   use std::time::duration::Duration;

//   #[test]
//   fn test_encode_and_decode_jwt() {
//     let mut p1 = BTreeMap::new();
//     p1.insert("key1".to_string(), "val1".to_string());
//     p1.insert("key2".to_string(), "val2".to_string());
//     p1.insert("key3".to_string(), "val3".to_string());

//     let secret = "secret123";
//     let jwt1 = sign(secret, Some(p1.clone()), Some(Algorithm::HS256));
//     let maybe_res = verify(jwt1.as_slice(), secret, None);

//     assert!(maybe_res.is_ok());
//     assert_eq!(jwt1, maybe_res.unwrap());
//   } 

//   #[test]
//   fn test_decode_valid_jwt() {
//     let mut p1 = BTreeMap::new();
//     p1.insert("key11".to_string(), "val1".to_string());
//     p1.insert("key22".to_string(), "val2".to_string());
//     let secret = "secret123";
//     let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxMSI6InZhbDEiLCJrZXkyMiI6InZhbDIifQ.jrcoVcRsmQqDEzSW9qOhG1HIrzV_n3nMhykNPnGvp9c";
//     let maybe_res = verify(jwt.as_slice(), secret, None);
    
//     assert!(maybe_res.is_ok());
//     assert_eq!(p1, maybe_res.unwrap().payload);
//   }

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
  
//   #[test]
//   fn test_secure_compare_same_strings() {
//     let str1 = "same same".as_bytes();
//     let str2 = "same same".as_bytes();
//     let res = secure_compare(str1, str2);
//     assert!(res);
//   }

//   #[test]
//   fn test_fails_when_secure_compare_different_strings() {
//     let str1 = "same same".as_bytes();
//     let str2 = "same same but different".as_bytes();
//     let res = secure_compare(str1, str2);
//     assert!(!res);

//     let str3 = "same same".as_bytes();
//     let str4 = "same ssss".as_bytes();
//     let res2 = secure_compare(str3, str4);
//     assert!(!res2);
//   }
// }