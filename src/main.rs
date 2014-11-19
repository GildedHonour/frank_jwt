struct JwtHeader {
 alg: &str, ;
 typ: &str
}


struct JwtClaims {
  iss: &str,
  iat: int,
  exp: int,
  qsh: &str,
  sub: &str
}

impl JwtClaims {
  fn new() -> JwtClaims {
    
  }
}

fn generate_jwt_token(request_url: &str, canonical_url: &str, key: &str, shared_secret: &str) -> &str {
  JwtClaims claims = new JwtClaims();
  claims.setIss(key);
  claims.setIat(System.currentTimeMillis() / 1000L);
  claims.setExp(claims.getIat() + 180L);

  claims.setQsh(getQueryStringHash(canonicalUrl));
  String jwtToken = sign(claims, sharedSecret);
  return jwtToken;
}