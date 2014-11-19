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
  fn new(iss: &str, iat: int, exp: int) -> JwtClaims {

  }
}

fn generate_jwt_token(request_url: &str, canonical_url: &str, key: &str, shared_secret: &str) -> &str {
  let iat = time::now().tm_nsec * 1000;
  let exp = iat + 1000 * 180;
  let qsh = getQueryStringHash(canonical_url);
  let claims = JwtClaims { iss: key, iat: iat, exp: exp, qsh: qsh };
  sign(claims, shared_secret)
}

fn sign(claims: JwtClaims, shared_secret: &str) -> &str {
  let signing_input = get_signing_input(claims, shared_secret);
  let signed256 = sign_hmac256(signing_input, shared_secret);
  signing_input.to_string() + "." + signed256.to_string()
}

fn get_signing_input(claims: JwtClaims, shared_secret: &str) -> &str {
  let header = new JwtHeader { alg: "HS256", typ: "JWT" };
  
  Gson gson = new Gson();
  String header_json_str = gson.toJson(header);
  String claims_json_str = gson.toJson(claims);
  String signing_input = encodeBase64URLSafeString(header_json_str.getBytes()) + "." + encodeBase64URLSafeString(claims_json_str.getBytes());
  
  signing_input
}


//todo
fn signHmac256(signing_input: &str, shared_secret: &str) -> &str {
  SecretKey key = new SecretKeySpec(sharedSecret.getBytes(), "HmacSHA256");
  Mac mac = Mac.getInstance("HmacSHA256");
  mac.init(key);
  encodeBase64URLSafeString(mac.doFinal(signingInput.getBytes()))
}

//todo
fn get_query_string_hash(canonical_url: &str) -> &str {
  MessageDigest md = MessageDigest.getInstance("SHA-256");
  md.update(canonicalUrl.getBytes("UTF-8"));
  byte[] digest = md.digest();
  encodeHexString(digest)
}
