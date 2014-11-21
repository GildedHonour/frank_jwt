extern crate serialize;
extern crate time;
extern crate "rust-crypto" as rust_crypto;

use serialize::json::ToJson;
use serialize::json;
use std::collections::TreeMap;

struct JwtHeader {
 alg: &str,
 typ: &str
}

struct JwtClaims {
  iss: &str,
  iat: int,
  exp: int,
  qsh: &str,
  sub: &str
}

impl ToJson for JwtHeader {
  fn to_json(&self) -> json::Json {
    let mut d = TreeMap::new();
    d.insert("alg", self.alg.to_json());
    d.insert("typ", self.typ.to_json());
    json::Object(d)
  }
}

impl ToJson for JwtClaims {
  fn to_json(&self) -> json::Json {
    let mut d = TreeMap::new();
    d.insert("iss", self.iss.to_json());
    d.insert("iat", self.iat.to_json());
    d.insert("exp", self.exp.to_json());
    d.insert("qsh", self.qsh.to_json());
    d.insert("sub", self.sub.to_json());
    json::Object(d)
  } 
}


fn generate_jwt_token(request_url: &str, canonical_url: &str, key: &str, shared_secret: &str) -> &str {
  let iat = time::now().tm_nsec * 1000;
  let exp = iat + 180 * 1000;
  let qsh = get_query_string_hash(canonical_url);
  let claims = JwtClaims { iss: key, iat: iat, exp: exp, qsh: qsh };
  sign(claims, shared_secret)
}

fn sign(claims: JwtClaims, shared_secret: &str) -> &str {
  let signing_input = get_signing_input(claims, shared_secret);
  let signed256 = sign_hmac256(signing_input, shared_secret);
  signing_input.to_string() + "." + signed256.to_string()
}

fn get_signing_input(claims: JwtClaims, shared_secret: &str) -> &str {
  let header = JwtHeader { alg: "HS256", typ: "JWT" };
  
  let header_json_str = header.to_json();
  let claims_json_str = claims.to_json();

  let hb64_url_e_str = base64_url_encode(header_json_str.to_string().into_bytes()).to_string();
  let cb64_url_e_str = base64_url_encode(claims_json_str.to_string().into_bytes()).to_string();
  hb64_url_e_str + "." + cb64_url_e_str
}


//todo
fn sign_hmac256(signing_input: &str, shared_secret: &str) -> &str {

  SecretKey key = new SecretKeySpec(sharedSecret.getBytes(), "HmacSHA256");
  Mac mac = Mac.getInstance("HmacSHA256");
  mac.init(key);
  base64_url_encode(mac.doFinal(signingInput.getBytes()))
}

//todo
fn get_query_string_hash(canonical_url: &str) -> &str {
  MessageDigest md = MessageDigest.getInstance("SHA-256");
  md.update(canonical_url.getBytes("UTF-8"));
  byte[] digest = md.digest();

  encode_hex_string(digest)
}

fn base64_url_encode(bytes: [u8]) -> &str {
  bytes.to_base64(base64::URLSAFE_CHARS).as_slice()
}

fn encode_hex_string() -> &str {

}
