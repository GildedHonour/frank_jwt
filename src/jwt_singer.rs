std::vec::{Vec};
extern crate time;

struct JwtSigner {
  
}

impl JwtSigner {
  fn encode(algorithm: Algorithm , payload: &str, payloadId: &str, key: &str, claimSet: ClaimSet) -> &str {
    let segments = vec![encodedHeader(algorithm), encodedPayload(payload, payloadId, claimSet), encodedSignature(join(segments, "."), key, algorithm)];
    join(segments, ".");
  }

  fn encoded_header(algorithm: Option<Algorithm>) -> &str {
    let new_algorithm = if algorithm.is_none() {
      Algorithm.HS256;
    } else {
      algorithm
    }

    // create the header
    ObjectNode header = JsonNodeFactory.instance.objectNode();
    header.put("type", "JWT");
    header.put("alg", algorithm.name());

    base64UrlEncode(header.toString().getBytes());
  }

  fn encodedPayload(payload: &str, payload_id: &str, claimSet: ClaimSet) -> &str {
    
    ObjectNode localClaimSet = JsonNodeFactory.instance.objectNode();
    ObjectNode localPayload = JsonNodeFactory.instance.objectNode();
    
    localPayload.put(payloadId, payload);
    
    if(claimSet != null) {
      if(claimSet.getExp() > 0) {
        localClaimSet.put("exp", claimSet.getExp());
      }
      localPayload.putAll(localClaimSet);
    }
    
    return base64UrlEncode(localPayload.toString().getBytes());
  }

  /**
   * Sign the header and payload
   */
  fn encoded_signature(signing_input: &str, key: &str, algorithm: Algorithm) -> &str {
    let signature = sign(algorithm, signing_input, key)
    base64UrlEncode(signature)
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
    algorithm match {
    case HS256:
    case HS384:
    case HS512:
      return signHmac(algorithm, msg, key);
    
    case RS256:
    case RS384:
    case RS512:
    default:
      throw new OperationNotSupportedException(
          "Unsupported signing method");
    }
  }

  /**
   * Sign an input string using HMAC and return the encrypted bytes
   */
  fn sign_hmac(algorithm: Algorithm, msg: &str, key: &str) -> [u8] {
    let mac = Mac.getInstance(algorithm.getValue());
    mac.init(new SecretKeySpec(key.getBytes(), algorithm.getValue()));
    mac.doFinal(msg.getBytes());
  }
  
  fn join(input: Vec, on: &str) -> &str {
    int size = input.size();
    int count = 1;
    StringBuilder joined = new StringBuilder();
    for (String string : input) {
      joined.append(string);
      if (count < size) {
        joined.append(on);
      }
      count++;
    }

    return joined.toString();
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