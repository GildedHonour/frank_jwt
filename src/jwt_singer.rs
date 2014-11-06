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
    base64_url_encode(header.to_string().into_bytes());
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

  fn encoded_signature(signing_input: &str, key: &str, algorithm: Algorithm) -> &str {
    let signature = sign(algorithm, signing_input, key)
    base64_url_encode(signature)
  }

  fn base64_url_encode(bytes: [u8]) -> &str {
    bytes.to_base64(base64::URLSAFE_CHARS).as_slice()
  }

  fn sign(algorithm: Algorithm, msg: &str, key: &str) -> Result<[u8], &str> {
    match algorithm {
      HS256 | HS384 | HS512 => Ok(sign_hmac(algorithm, msg, key)),
      _ => Err("Unsupported signing method")
    }
  }

  fn sign_hmac(algorithm: Algorithm, msg: &str, key: &str) -> [u8] {
    Hmac::new(Md5::new(), t.key[]);


    let mac = Mac.getInstance(algorithm.getValue());
    mac.init(new SecretKeySpec(key.getBytes(), algorithm.getValue()));
    mac.doFinal(msg.getBytes());
  }
}

struct Algorithm {
  value: &str
}

impl Algorithm {
  fn new(d: Digest) -> Algorithm {

  }
}
enum Algorithm {
  Sha224(Digest),
  Sha256(Digest),
  Sha384(Digest),
  Sha512(Digest)
}