extern crate serialize;
extern crate time;
extern crate "rust-crypto" as rust_crypto;

use serialize::base64;
use serialize::base64::{ToBase64};
use serialize::json::ToJson;
use serialize::json;
use std::collections::TreeMap;
use rust_crypto::sha2::Sha256;
use rust_crypto::hmac::Hmac;
use rust_crypto::digest::Digest;
use rust_crypto::mac::Mac;

struct JwtHeader<'a> {
 alg: &'a str,
 typ: &'a str
}

struct JwtClaims<'a> {
  iss: &'a str,
  iat: int,
  exp: int,
  qsh: &'a str,
  sub: &'a str,
}

impl<'a> JwtClaims<'a> {
  fn new(iss: &'a str, iat: int, exp: int, qsh: &'a str) -> JwtClaims<'a> {
    JwtClaims { iss: iss, iat: iat, exp: exp, qsh: qsh, sub: "" }
  }
}

impl<'a> ToJson for JwtHeader<'a> {
  fn to_json(&self) -> json::Json {
    let mut d = TreeMap::new();
    d.insert("alg".to_string(), self.alg.to_json());
    d.insert("typ".to_string(), self.typ.to_json());
    json::Object(d)
  }
}

impl<'a> ToJson for JwtClaims<'a> {
  fn to_json(&self) -> json::Json {
    let mut d = TreeMap::new();
    d.insert("iss".to_string(), self.iss.to_json());
    d.insert("iat".to_string(), self.iat.to_json());
    d.insert("exp".to_string(), self.exp.to_json());
    d.insert("qsh".to_string(), self.qsh.to_json());
    d.insert("sub".to_string(), self.sub.to_json());
    json::Object(d)
  } 
}

fn generate_jwt_token(request_url: &str, canonical_url: &str, key: &str, shared_secret: &str) -> String {
  let iat = time::now().tm_nsec * 1000;
  let exp = iat + 180 * 1000;
  let qsh = get_query_string_hash(canonical_url);
  let claims = JwtClaims::new(key, iat as int, exp as int, qsh.as_slice());
  sign(claims, shared_secret)
}

fn sign(claims: JwtClaims, shared_secret: &str) -> String {
  let signing_input = get_signing_input(claims, shared_secret);
  let signed256 = sign_hmac256(signing_input.as_slice(), shared_secret);
  signing_input + "." + signed256
}

fn get_signing_input(claims: JwtClaims, shared_secret: &str) -> String {
  let header = JwtHeader { alg: "HS256", typ: "JWT" };
  
  let header_json_str = header.to_json();
  let claims_json_str = claims.to_json();

  let hb64_url_e_str = base64_url_encode(header_json_str.to_string().as_bytes()).to_string();
  let cb64_url_e_str = base64_url_encode(claims_json_str.to_string().as_bytes()).to_string();
  hb64_url_e_str + "." + cb64_url_e_str
}

fn sign_hmac256(signing_input: &str, shared_secret: &str) -> String {
  let mut hmac = Hmac::new(Sha256::new(), shared_secret.to_string().as_bytes());
  hmac.input(signing_input.to_string().as_bytes());
  let res = hmac.result();
  let cod = res.code();
  base64_url_encode(cod)
}

fn get_query_string_hash(canonical_url: &str) -> String {
  let mut sh = Sha256::new();
  sh.input_str(canonical_url);
  sh.result_str()
}

fn base64_url_encode(bytes: &[u8]) -> String {
  bytes.to_base64(base64::URL_SAFE)
}