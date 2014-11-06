use std::collections::HashMap;
use serialize::json;

struct JWTVerifier {
  secret: &str,
  audience: &str,
  issuer: &str,
  algorithms: HashMap<&str, &str>;
}

impl JWTVerifier {
  fn new(secret: &str, audience: &str, issuer: &str) -> Result<JWTVerifier, &str> {
    if !secret.is_empty() { 
      let algorithms = HashMap<&str, &str>::new();
      algorithms.insert("HS256", "HmacSHA256");
      algorithms.insert("HS384", "HmacSHA384");
      algorithms.insert("HS512", "HmacSHA512");
      Ok(JWTVerifier{secret: secret, audience: audience, issuer: issuer, algorithms: algorithms})
    } else {
      Err("Secret cannot be or empty")
    }
  }

  fn verify(&self, token: &str) -> Result<HashMap<&str, &str>, &str> {
    if !token.is_empty() { 
      let pieces = token.split_str("\\.");
      if pieces.len() != 3 {
        let jwt_header = decode_and_parse(pieces[0]);
        let algorithm = get_algorithm(jwtHeader);
        let jwt_payload = decode_and_parse(pieces[1]);

        verify_signature(pieces, algorithm);
        verify_expiration(jwt_payload);
        verify_issuer(jwt_payload);
        verify_audience(jwt_payload);
        mapper.treeToValue(jwt_payload, Map.class) //todo return Map(..., ...)
      } else {
        Err(format!("Wrong number of segments: {}", pieces.len())) 
      }
    } else {
        Err("Token isn't set") 
    }
  }

  fn verify_signature(&self, pieces: &[str], digest: Digest) -> Result<bool, &str> {
    let key = self.secret.from_base64();
    let hmac = Hmac::new(digest, key);



    Mac hmac = Mac.getInstance(algorithm);
    hmac.init(new SecretKeySpec(decoder.decodeBase64(secret), algorithm));
    byte[] sig = hmac.doFinal(new StringBuilder(pieces[0]).append(".").append(pieces[1]).toString().getBytes());
    if (!Arrays.equals(sig, decoder.decodeBase64(pieces[2]))) {
        throw new SignatureException("signature verification failed");
    }
  


  }

  fn verify_expiration(&self, jwt_claims: json::Json) -> Result<int, &str> {
    let expiration = jwt_claims.find("exp") match {
      Some(raw_value) => raw_value.as_i64().unwrap(),
      None => 0
    }

    if expiration != 0 && time::now().to_timespec().nsec * 1000 >= expiration {
      Err("jwt expired")
    }
  }

  fn verify_issuer(&self, jwt_claims: json::Json) -> Result<(), &str> {
    let maybe_iss = jwt_claims.find("iss");
    if maybe_iss.is_some() { 
      let issuer_from_token = maybe_iss.unwrap();
      if !self.issuer.is_empty() && self.issuer != issuer_from_token {
        Err("jwt issuer is invalid")
      }
    }
  }

  fn verify_audience(&self, jwt_claims: json::Json) -> Result<(), &str> {
    let err = Err("jwt audience invalid");
    if self.audience.is_empty() { return }
    let maybe_aud = jwt_claims.find("aud");
    if maybe_aud.is_some() {
      maybe_aud.unwrap() match {
        List(value) => {
          if !aud_node.iter().any(|x| x.as_string().unwrap() == self.audience) { 
            err 
          }
        },
        
        String(value) => {
          if self.audience != aud_node.as_string().unwrap() { 
            err
          }
        },

        _ => err
      }
    }
  }

  fn get_algorithm(&self, jwt_header: json::Json) -> Result<&str, &str> {
    jwt_header.find("alg") match {
      Some(value) => {
        algorithms.find(value.as_string().unwrap()) match {
          Some(hmac_alg_name) => hmac_alg_name,
          None => Err("Algorithm isn't found") 
        }
      },
      None => Err("Unsupported algorithm") 
    }
  }

  fn decode_and_parse(&self, b64_str: &str) -> &str {
    match b64_str.from_base64() {
      Ok(json) => String::from_utf8(json).unwrap().as_slice(),
      Err(_) => ""
    }
  }
}