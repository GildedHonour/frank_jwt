use std::collections::HashMap;

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

  fn verify(token: &str) -> Result<HashMap<&str, ???>, &str> {
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

  fn verify_signature(pieces: &[str], algorithm: &str) {
    Mac hmac = Mac.getInstance(algorithm);
    hmac.init(new SecretKeySpec(decoder.decodeBase64(secret), algorithm));
    byte[] sig = hmac.doFinal(new StringBuilder(pieces[0]).append(".").append(pieces[1]).toString().getBytes());

    if (!Arrays.equals(sig, decoder.decodeBase64(pieces[2]))) {
        throw new SignatureException("signature verification failed");
    }
  }

  fn verify_expiration(JsonNode jwtClaims) {
    let expiration = if jwtClaims.has("exp") { 
      jwtClaims.get("exp").asLong(0) 
    } else { 
      0 
    }
    
    if expiration != 0 && time::now() * 1000 >= expiration {
        throw new IllegalStateException("jwt expired");
    }
  }

  fn verify_issuer(JsonNode jwtClaims) {
    let issuerFromToken = if jwtClaims.has("iss") { jwtClaims.get("iss").asText() } else { null }
    if (issuerFromToken != null && issuer != null && !issuer.equals(issuerFromToken)) {
      throw new IllegalStateException("jwt issuer invalid");
    }
  }

  fn verify_audience(&self, JsonNode jwt_claims) -> bool {
      if self.audience.is_empty() { return true }
      
      JsonNode audNode = jwt_claims.get("aud");
      if (audNode == null)
          return;
      if (audNode.isArray()) {
          for (JsonNode jsonNode : audNode) {
              if (audience.equals(jsonNode.textValue()))
                  return;
          }
      } else if (audNode.isTextual()) {
          if (audience.equals(audNode.textValue()))
              return;
      }
      throw new IllegalStateException("jwt audience invalid");
  }

  fn get_algorithm(JsonNode jwtHeader) -> Result<, &str> {
      let algorithmName = jwtHeader.has("alg") ? jwtHeader.get("alg").asText() : null;
      if (jwtHeader.get("alg") == null) { 
        Err("algorithm not set")
      }

      if (algorithms.get(algorithmName) == null) {
        Err("unsupported algorithm");
      }

      algorithms.get(algorithmName)
  }

  fn decode_and_parse(b64_str: &str) -> &str {
    let raw_json = b64_str.from_base64();
    match raw_json {
      Ok(json) => String::from_utf8(json).unwrap().as_slice(),
      Err(_) => ""
    }
  }
}