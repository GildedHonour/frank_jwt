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

  fn verify(&self, token: &str) -> Result<HashMap<&str, ???>, &str> {
    if !token.is_empty() { 
      let pieces = token.split_str("\\.");
      if pieces.len() != 3 {
        let jwt_header = decode_and_parse(pieces[0]);
        let algorithm = get_algorithm(jwtHeader);
        let jwt_payload = decode_and_parse(pieces[1]);

        verify_signature(pieces, algorithm);
        verify_expiration(jwtPayload);
        verify_issuer(jwtPayload);
        verify_audience(jwtPayload);
        mapper.treeToValue(jwtPayload, Map.class)
      } else {
        Err(format!("Wrong number of segments: {}", pieces.len())) 
      }
    } else {
        Err("token not set".to_string()) 
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
    let expiration = if jwt_claims.has("exp") { 
      jwt_claims.get("exp").asLong(0) 
    } else { 
      0 
    }
    
    if expiration != 0 && time::now() * 1000 >= expiration {
      Err("jwt expired")
    }
  }

  fn verify_issuer(&self, jwt_claims: json::Json) {
    let issuerFromToken = if jwt_claims.has("iss") { jwt_claims.get("iss").asText() } else { null }
    if (issuerFromToken != null && issuer != null && !issuer.equals(issuerFromToken)) {
      throw new IllegalStateException("jwt issuer invalid");
    }
  }

  fn verify_audience(&self, jwt_claims: json::Json) -> Result<(), &str> {
      if self.audience.is_empty() { return }
      
      JsonNode aud_node = jwt_claims.get("aud");
      if (aud_node == null)
          return;
      if (aud_node.isArray()) {
          for (JsonNode jsonNode : aud_node) {
              if (audience.equals(jsonNode.textValue()))
                  return;
          }
      } else if (aud_node.isTextual()) {
          if (audience.equals(aud_node.textValue()))
              return;
      }
      throw new IllegalStateException("jwt audience invalid");
  }

  fn get_algorithm(&self, jwt_header: json::Json) -> Result<&str, &str> {
      jwt_header.find("alg") match {
        Some(value) => {
          let alg_name = value.as_string().unwrap();
          algorithms.find(alg_name) match {
            Some(hmac_alg_name) => hmac_alg_name,
            None => Err("Algorithm isn't found") 
          }
        },
        None => Err("Unsupported algorithm") 
      }
  }

  fn decode_and_parse(&self, b64_str: &str) -> &str {
    let raw_json = b64_str.from_base64();
    match raw_json {
      Ok(json) => String::from_utf8(json).unwrap().as_slice(),
      Err(_) => ""
    }
  }
}