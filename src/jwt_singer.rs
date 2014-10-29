std::vec::{Vec};
extern crate time;

struct JwtSigner {
  
}

impl JwtSigner {
  fn encode(algorithm: Algorithm , payload: &str, payload_id: &str, key: &str, claim_set: ClaimSet) -> &str {
    let segments = vec![encoded_header(algorithm).to_string(), encoded_payload(payload, payload_id, claim_set).to_string()]
    let es = encoded_signature(segments.map(|x| x + "."), key, algorithm).to_string()
    segments.push(es)
    segments.map_in_place(|x| x + ".")
  }

  fn encoded_header(algorithm: Option<Algorithm>) -> &str {
    let new_algorithm = if algorithm.is_none() {
      Algorithm.HS256
    } else {
      algorithm
    }

    let header = format!(r#"{{"type": "JWT", "alg": {}}}"#, algorithm.name)
    base64_url_encode(header.toString().getBytes());
  }

  fn encoded_payload(payload: &str, payload_id: &str, claim_set: Option<ClaimSet>) -> &str {
    ObjectNode local_claim_set = JsonNodeFactory.instance.objectNode();
    let local_payload = format!(r#"{{{}: {}}}"#, payload_id, payload)
    match claim_set {
      Some(cs) => {
        if cs.exp > 0 {
          local_claim_set.put "exp", claim_set.exp;
        }

        local_payload.putAll(local_claim_set)
      },

      None => {}
    }
    
    base64_url_encode(local_payload.to_string().into_bytes())
  }

  /**
   * Sign the header and payload
   */
  fn encoded_signature(signing_input: &str, key: &str, algorithm: Algorithm) -> &str {
    let signature = sign(algorithm, signing_input, key)
    base64_url_encode(signature)
  }

  /**
   * Safe URL encode a byte array to a String
   */
  fn base64_url_encode(str: [u8]) -> &str {
    String::new(Base64.encodeBase64URLSafe(str));
  }

  /**
   * Switch the signing algorithm based on input, RSA not supported
   */
  fn sign(algorithm: Algorithm, msg: &str, key: &str) -> Result<[u8], &str> {
    match algorithm {
      HS256 | HS384 | HS512 => Ok(sign_hmac(algorithm, msg, key)),
      _ => Err("Unsupported signing method")
    }
  }

  fn sign_hmac(algorithm: Algorithm, msg: &str, key: &str) -> [u8] {
    let mac = Mac.getInstance(algorithm.getValue());
    mac.init(new SecretKeySpec(key.getBytes(), algorithm.getValue()));
    mac.doFinal(msg.getBytes());
  }
}

struct Algorithm {
  value: &str
}

enum Algorithm {
  HS256("HmacSHA256"), 
  HS384("HmacSHA384"), 
  HS512("HmacSHA512"), 
  RS256("RS256"), 
  RS384("RS384"), 
  RS512("RS512");
}

struct ClaimSet {
  exp: int
}

impl ClaimSet {
  fn set_exp(&self, value: int) {
    exp = (int)(time::now() / 1000L) + exp
  }
}