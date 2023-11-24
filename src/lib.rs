/**
 (c) 2015-2018 Alex Maslakov, <gildedhonour.com>, <alexmaslakoff.icu>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For questions and comments about this product, please see the project page at:
 *
 * https://github.com/GildedHonour/frank_jwt
 *
 */

extern crate openssl;
extern crate serde;
extern crate base64;

#[cfg(test)]
#[macro_use]
extern crate serde_json;

#[cfg(not(test))]
extern crate serde_json;

pub mod error;

use std::fs::File;
use std::path::{PathBuf};
use std::io::Read;
use std::str;
use openssl::bn::BigNum;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use serde_json::Value as JsonValue;
use base64::{encode_config as b64_enc, decode_config as b64_dec};

pub use error::Error;

const SEGMENTS_COUNT: usize = 3;

const STANDARD_HEADER_TYPE: &str = "JWT";

const MAXIMUM_EC_SIGNATURE_LENGTH: usize = 132;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512
}

pub struct ValidationOptions {
    verify_exp: bool,
    exp_leeway: u64
}

impl ValidationOptions {
    pub fn new() -> ValidationOptions {
        ValidationOptions::default()
    }

    pub fn dangerous() -> ValidationOptions {
        ValidationOptions {
            verify_exp: false,
            exp_leeway: 0
        }
    }
}

impl Default for ValidationOptions {
    fn default() -> ValidationOptions {
        ValidationOptions {
            verify_exp: true,
            exp_leeway: 0
        }
    }
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        match *self {
            Algorithm::HS256 => "HS256",
            Algorithm::HS384 => "HS384",
            Algorithm::HS512 => "HS512",
            Algorithm::RS256 => "RS256",
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            Algorithm::ES256 => "ES256",
            Algorithm::ES384 => "ES384",
            Algorithm::ES512 => "ES512"
        }.to_string()
    }
}

pub trait ToKey {
    fn to_key(&self) -> Result<Vec<u8>, Error>;
}

impl ToKey for PathBuf {
    fn to_key(&self) -> Result<Vec<u8>, Error> {
        let mut file = File::open(self)?;
        let mut buffer:Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}

impl ToKey for String {
    fn to_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_bytes().to_vec())
    }
}

impl ToKey for &str {
    fn to_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_bytes().to_vec())
    }
}

impl ToKey for Vec<u8> {
    fn to_key(&self) -> Result<Vec<u8>, Error> {
        Ok(self.clone())
    }
}

pub fn encode<P: ToKey>(mut header: JsonValue, signing_key: &P, payload: &JsonValue, algorithm: Algorithm) -> Result<String, Error> {
    header["alg"] = JsonValue::String(algorithm.to_string());
    if header["typ"].is_null() {
        header["typ"] = JsonValue::String(STANDARD_HEADER_TYPE.to_owned());
    }
    let signing_input = get_signing_input(&payload, &header)?;
    let signature = match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => sign_hmac(&signing_input, signing_key, algorithm)?,
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => sign_rsa(&signing_input, signing_key, algorithm)?,
        Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => sign_es(&signing_input, signing_key, algorithm)?,
    };

    Ok(format!("{}.{}", signing_input, signature))
}

pub fn decode<P: ToKey>(encoded_token: &str, signing_key: &P, algorithm: Algorithm, validation: &ValidationOptions) -> Result<(JsonValue, JsonValue), Error> {
    let (header, payload, signature, signing_input) = decode_segments(encoded_token)?;
    if !verify_signature(algorithm, signing_input, &signature, signing_key)? {
        Err(Error::SignatureInvalid)
    } else if validation.verify_exp && !verify_expiration(&payload, validation.exp_leeway) {
        Err(Error::ExpirationInvalid)
    } else {
        Ok((header, payload))
    }
}

pub fn validate_signature<P: ToKey>(encoded_token: &str, signing_key: &P, algorithm: Algorithm) -> Result<bool, Error> {
    let (signature, signing_input) = decode_signature_segments(encoded_token)?;
    verify_signature(algorithm, signing_input, &signature, signing_key)
}

fn get_signing_input(payload: &JsonValue, header: &JsonValue) -> Result<String, Error> {
    let header_json_str = serde_json::to_string(header)?;
    let encoded_header = b64_enc(header_json_str.as_bytes(), base64::URL_SAFE_NO_PAD);
    let payload_json_str = serde_json::to_string(payload)?;
    let encoded_payload = b64_enc(payload_json_str.as_bytes(), base64::URL_SAFE_NO_PAD);
    Ok(format!("{}.{}", encoded_header, encoded_payload))
}

fn sign_hmac<P: ToKey>(data: &str, key_path: &P, algorithm: Algorithm) -> Result<String, Error> {
    let stp = match algorithm {
        Algorithm::HS256 => MessageDigest::sha256(),
        Algorithm::HS384 => MessageDigest::sha384(),
        Algorithm::HS512 => MessageDigest::sha512(),
        _  => panic!("Invalid hmac algorithm")
    };

    let key = PKey::hmac(&key_path.to_key()?)?;
    let mut signer = Signer::new(stp, &key)?;
    signer.update(data.as_bytes())?;
    let hmac = signer.sign_to_vec()?;
    Ok(b64_enc(hmac.as_slice(), base64::URL_SAFE_NO_PAD))
}

fn sign_rsa<P: ToKey>(data: &str, private_key_path: &P, algorithm: Algorithm) -> Result<String, Error> {
    let stp = match algorithm {
        Algorithm::RS256 => MessageDigest::sha256(),
        Algorithm::RS384 => MessageDigest::sha384(),
        Algorithm::RS512 => MessageDigest::sha512(),
        _  => panic!("Invalid hmac algorithm")
    };

    let rsa = Rsa::private_key_from_pem(&private_key_path.to_key()?)?;
    let key = PKey::from_rsa(rsa)?;
    sign(data, key, stp)
}

fn sign_es<P: ToKey>(data: &str, private_key_path: &P, algorithm: Algorithm) -> Result<String, Error> {
    let ec_key = EcKey::private_key_from_pem(&private_key_path.to_key()?)?;
    let stp = match algorithm {
        Algorithm::ES256 => MessageDigest::sha256(),
        Algorithm::ES384 => MessageDigest::sha384(),
        Algorithm::ES512 => MessageDigest::sha512(),
        _  => panic!("Invalid hmac algorithm")
    };

    let hash = hash(stp, data.as_bytes())?;
    let sig = EcdsaSig::sign(&hash, &ec_key)?;

    let length = es_signature_length(algorithm);
    let middle = length / 2;

    let r = sig.r().to_vec();
    let s = sig.s().to_vec();
    let mut signature: Vec<u8> = [0; MAXIMUM_EC_SIGNATURE_LENGTH].to_vec();
    signature.splice(middle - r.len()..middle, r);
    signature.splice(length - s.len()..length, s);

    Ok(b64_enc(&signature[0..length], base64::URL_SAFE_NO_PAD))
}

fn sign(data: &str, private_key: PKey<Private>, digest: MessageDigest) -> Result<String, Error> {
    let mut signer = Signer::new(digest, &private_key)?;
    signer.update(data.as_bytes())?;
    let signature = signer.sign_to_vec()?;
    Ok(b64_enc(signature.as_slice(), base64::URL_SAFE_NO_PAD))
}

fn decode_segments(encoded_token: &str) -> Result<(JsonValue, JsonValue, Vec<u8>, String), Error> {
    let raw_segments: Vec<&str> = encoded_token.split(".").collect();
    if raw_segments.len() != SEGMENTS_COUNT {
        return Err(Error::JWTInvalid);
    }

    let header_segment = raw_segments[0];
    let payload_segment = raw_segments[1];
    let crypto_segment =  raw_segments[2];
    let (header, payload) = decode_header_and_payload(header_segment, payload_segment)?;
    let signature = b64_dec(crypto_segment.as_bytes(), base64::URL_SAFE_NO_PAD)?;
    let signing_input = format!("{}.{}", header_segment, payload_segment);
    Ok((header, payload, signature.clone(), signing_input))
}

fn decode_signature_segments(encoded_token: &str) -> Result<(Vec<u8>, String), Error> {
    let raw_segments: Vec<&str> = encoded_token.split(".").collect();
    if raw_segments.len() != SEGMENTS_COUNT {
        return Err(Error::JWTInvalid);
    }

    let header_segment = raw_segments[0];
    let payload_segment = raw_segments[1];
    let crypto_segment =  raw_segments[2];
    let signature = b64_dec(crypto_segment.as_bytes(), base64::URL_SAFE_NO_PAD)?;
    let signing_input = format!("{}.{}", header_segment, payload_segment);
    Ok((signature.clone(), signing_input))
}

fn decode_header_and_payload(header_segment: &str, payload_segment: &str) -> Result<(JsonValue, JsonValue), Error> {
    let b64_to_json = |seg| -> Result<JsonValue, Error> {
        serde_json::from_slice(b64_dec(seg, base64::URL_SAFE_NO_PAD)?.as_slice()).map_err(Error::from)
    };

    let header_json = b64_to_json(header_segment)?;
    let payload_json = b64_to_json(payload_segment)?;
    Ok((header_json, payload_json))
}

fn sign_hmac2(data: &str, key: &Vec<u8>, algorithm: Algorithm) -> Result<Vec<u8>, Error> {
    let stp = match algorithm {
        Algorithm::HS256 => MessageDigest::sha256(),
        Algorithm::HS384 => MessageDigest::sha384(),
        Algorithm::HS512 => MessageDigest::sha512(),
        _  => panic!("Invalid HMAC algorithm")
    };

    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(stp, &pkey)?;
    signer.update(data.as_bytes())?;
    signer.sign_to_vec().map_err(Error::from)
}

fn es_signature_length(algorithm: Algorithm) -> usize {
    return match algorithm {
        Algorithm::ES256 => 64,
        Algorithm::ES384 => 96,
        Algorithm::ES512 => 132,
        _ => unreachable!()
    };
}

fn verify_signature<P: ToKey>(algorithm: Algorithm, signing_input: String, signature: &[u8], public_key: &P) -> Result<bool, Error> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let signature2 = sign_hmac2(&signing_input, &public_key.to_key()?, algorithm)?;
            Ok(secure_compare(signature, &signature2))
        },

        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512  => {
            let rsa = Rsa::public_key_from_pem(&public_key.to_key()?)?;
            let key = PKey::from_rsa(rsa)?;

            let digest = get_sha_algorithm(algorithm);
            let mut verifier = Verifier::new(digest, &key)?;
            verifier.update(signing_input.as_bytes())?;
            verifier.verify(&signature).map_err(Error::from)
        },
        Algorithm::ES256 | Algorithm::ES384 | Algorithm::ES512 => {
            let key = PKey::public_key_from_pem(&public_key.to_key()?).map_err(Error::from)?;
            let ec_key = key.ec_key()?;

            let length = es_signature_length(algorithm);

            if signature.len() != length {
                return Err(Error::SignatureInvalid);
            }

            let middle = length / 2;

            let r = BigNum::from_slice(&signature[..middle])?;
            let s = BigNum::from_slice(&signature[middle..length])?;
            let sig = EcdsaSig::from_private_components(r, s)?;

            let digest = get_sha_algorithm(algorithm);
            let hash = hash(digest, signing_input.as_bytes())?;
            sig.verify(&hash, &ec_key).map_err(Error::from)
        },
    }
}

fn get_sha_algorithm(alg: Algorithm) -> MessageDigest {
    match alg {
        Algorithm::RS256 | Algorithm::ES256 => MessageDigest::sha256(),
        Algorithm::RS384 | Algorithm::ES384 => MessageDigest::sha384(),
        Algorithm::RS512 | Algorithm::ES512 => MessageDigest::sha512(),
        _  => panic!("Invalid RSA algorithm")
    }
}

fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false
    }

    let mut res = 0_u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }

    res == 0
}



//todo
fn verify_not_before() {
    unimplemented!()
}

fn verify_sub() {
    unimplemented!()
}

fn verify_jti() {
    unimplemented!()
}

fn verify_iss() {
    unimplemented!()
}

fn verify_iat() {

    //get date-time now
    use std::time::{SystemTime, UNIX_EPOCH};

    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("invalid timestamp");

    //get payload[:iat]
    //ensure it's integer
    //ensure that date-time now < payload[:iat]

    unimplemented!()
}

fn verify_expiration(payload: &serde_json::Value, leeway: u64) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    let exp = match payload.get("exp") {
        Some(v) => v,
        None => return false
    }.as_f64().unwrap_or(0.0) as u64;

    let utc = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(v) => v,
        Err(_) => return false
    }.as_secs();

    (exp + leeway) > utc
}

fn verify_aud() {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, encode, decode, validate_signature, secure_compare, STANDARD_HEADER_TYPE, ValidationOptions, verify_expiration};
    use std::env;
    use std::ops::{Add, Sub};
    use std::path::PathBuf;
    use std::time::Duration;
    use error::Error;

    #[test]
    fn test_encode_and_decode_jwt_hs256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let secret = "secret123";
        let  header = json!({});
        let jwt1 = encode(header, &secret, &p1, Algorithm::HS256).unwrap();
        let maybe_res = decode(&jwt1, &secret, Algorithm::HS256, &ValidationOptions::dangerous());
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_decode_valid_jwt_hs256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2"
        });
        let secret = "secret123".to_string();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxMSI6InZhbDEiLCJrZXkyMiI6InZhbDIifQ.jrcoVcRsmQqDEzSW9qOhG1HIrzV_n3nMhykNPnGvp9c".to_string();
        let maybe_res = decode(&jwt, &secret, Algorithm::HS256, &ValidationOptions::dangerous());
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_validate_signature_jwt_hs256() {
        let secret = "secret123".to_string();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxMSI6InZhbDEiLCJrZXkyMiI6InZhbDIifQ.jrcoVcRsmQqDEzSW9qOhG1HIrzV_n3nMhykNPnGvp9c".to_string();
        let maybe_res = validate_signature(&jwt, &secret, Algorithm::HS256);
        assert!(maybe_res.unwrap());
    }

    #[test]
    fn test_validate_signature_with_header_jwt_hs256() {
       let secret = "secret".to_string();
       let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJDUklTUCIsImdyb3VwIjoiQVRJIiwicmVzb3VyY2VzIjpbXX0.K9nfZnbMzF1-P1zXEQHeYYUz35NTbTPpT560wNG16DM".to_string();
       let maybe_res = validate_signature(&jwt, &secret, Algorithm::HS256);
       assert!(maybe_res.unwrap());
    }

    #[test]
    fn test_validate_signature_jwt_hs256_invalid() {
        let secret = "secret123".to_string();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ8.eyJrZXkxMSI6InZhbDEiLCJrZXkyMiI6InZhbDIifQ.jrcoVcRsmQqDEzSW9qOhG1HIrzV_n3nMhykNPnGvp9c".to_string();
        let maybe_res = validate_signature(&jwt, &secret, Algorithm::HS256);
        assert!(!maybe_res.unwrap());
    }

    #[test]
    fn test_secure_compare_same_strings() {
        let str1 = "same same".as_bytes();
        let str2 = "same same".as_bytes();
        let res = secure_compare(str1, str2);
        assert!(res);
    }

    #[test]
    fn test_fails_when_secure_compare_different_strings() {
        let str1 = "same same".as_bytes();
        let str2 = "same same but different".as_bytes();
        let res = secure_compare(str1, str2);
        assert!(!res);
    }

    #[test]
    fn test_encode_and_decode_jwt_hs384() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let secret = "secret123".to_string();
        let  header = json!({});
        let jwt1 = encode(header, &secret, &p1, Algorithm::HS384).unwrap();
        let maybe_res = decode(&jwt1, &secret, Algorithm::HS384, &ValidationOptions::dangerous());
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_validate_signature_jwt_hs384() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let secret = "secret123".to_string();
        let  header = json!({});
        let jwt1 = encode(header, &secret, &p1, Algorithm::HS384).unwrap();
        let maybe_res = validate_signature(&jwt1, &secret, Algorithm::HS384);
        assert!(maybe_res.unwrap());
    }

    #[test]
    fn test_validate_signature_jwt_hs384_invalid() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let secret = "secret123".to_string();
        let  header = json!({});
        let jwt1 = encode(header, &secret, &p1, Algorithm::HS384).unwrap();
        let bad_secret = "secret1234".to_string();
        let maybe_res = validate_signature(&jwt1, &bad_secret, Algorithm::HS384);
        assert!(!maybe_res.unwrap());
    }

    #[test]
    fn test_encode_and_decode_jwt_hs512() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let secret = "secret123456".to_string();
        let  header = json!({});
        let jwt1 = encode(header, &secret, &p1, Algorithm::HS512).unwrap();
        let maybe_res = decode(&jwt1, &secret, Algorithm::HS512, &ValidationOptions::dangerous());
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_validate_signature_jwt_hs512() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let secret = "secret123456".to_string();
        let  header = json!({});
        let jwt1 = encode(header, &secret, &p1, Algorithm::HS512).unwrap();
        let maybe_res = validate_signature(&jwt1, &secret, Algorithm::HS512);
        assert!(maybe_res.unwrap());
    }

    #[test]
    fn test_validate_signature_jwt_hs512_invalid() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let secret = "secret123456".to_string();
        let  header = json!({});
        let jwt1 = encode(header, &secret, &p1, Algorithm::HS512).unwrap();
        let bad_secret = "secret123456789".to_string();
        let maybe_res = validate_signature(&jwt1, &bad_secret, Algorithm::HS512);
        assert!(!maybe_res.unwrap());
    }

    #[test]
    fn test_encode_and_decode_jwt_rs256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let  header = json!({});
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_rsa_2048_key.pem");
        path.to_str().unwrap().to_string();

        let jwt1 = encode(header, &get_rsa_256_private_key_full_path(), &p1, Algorithm::RS256).unwrap();
        let maybe_res = decode(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256, &ValidationOptions::dangerous());
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_encoded_validate_signature_jwt_rs256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let  header = json!({});
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_rsa_2048_key.pem");
        path.to_str().unwrap().to_string();

        let jwt1 = encode(header, &get_rsa_256_private_key_full_path(), &p1, Algorithm::RS256).unwrap();
        let maybe_res = validate_signature(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256);
        assert!(maybe_res.unwrap());
    }

    #[test]
    fn test_encoded_validate_signature_jwt_rs256_invalid() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let  header = json!({});
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_rsa_2048_key.pem");
        path.to_str().unwrap().to_string();

        let jwt1 = encode(header, &get_rsa_256_private_key_full_path(), &p1, Algorithm::RS256).unwrap();
        let maybe_res = validate_signature(&jwt1, &get_bad_rsa_256_public_key_full_path(), Algorithm::RS256);
        assert!(!maybe_res.unwrap());
    }

    #[test]
    fn test_decode_valid_jwt_rs256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2"
        });

        let  header = json!({});
        let jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0.DFusERCFWCL3CkKBaoVKsi1Z3QO2NTTRDTGHPqm7ctzypKHxLslJXfS1p_8_aRX30V2osMAEfGzXO9U0S9J1Z7looIFNf5rWSEcqA3ah7b7YQ2iTn9LOiDWwzVG8rm_HQXkWq-TXqayA-IXeiX9pVPB9bnguKXy3YrLWhP9pxnhl2WmaE9ryn8WTleMiElwDq4xw5JDeopA-qFS-AyEwlc-CE7S_afBd5OQBRbvgtfv1a9soNW3KP_mBg0ucz5eUYg_ON17BG6bwpAwyFuPdDAXphG4hCsa7GlXea0f7DnYD5e5-CA6O7BPW_EvjaGhL_D9LNWHJuDiSDBwZ4-IEIg".to_string();
        let (h1, p1) = decode(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256, &ValidationOptions::dangerous()).unwrap();
        println!("\n{}",h1);
        println!("{}",p1);
        let jwt2 = encode(header, &get_rsa_256_private_key_full_path(), &p1, Algorithm::RS256).unwrap();
        let (h2, p2) = decode(&jwt2, &get_rsa_256_public_key_full_path(), Algorithm::RS256, &ValidationOptions::dangerous()).unwrap();
        println!("{}",h2);
        println!("{}",p2);
        assert_eq!(jwt1, jwt2);
    }

    #[test]
    fn test_validate_signature_jwt_rs256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2"
        });
        let  header = json!({});
        let jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0.RQdLX70LEWL3PFePR2ec7fsBLwi29qK9GL_YfiBKcOWnWsgWMrw0PeJw8h21FloKAYYRq73GmSlF39B5TWbquscf3obfD_y3TYmSjY_STlQ1UTMBnCmwZeMgxuIlq4l7RNpGh_j-42u6YJ3b4zwFiiIGWANYTL0pzXjdIFcUhuY7yeYlFHmWgUOOfv_E_MaP0CgCK6rgeorPtFZ80Z-zYc2R7oXLylgiwJQmwLGzxAcOOcNaZurhQxUQ7GrErY9fOLxfw0vmF4FMSIhQvWIiUV9Meh3MoIwybDhuy5-Y85WZwtXYC7blAZhU0h6tFqwBozt7PS34htj8rkCIqqi0Ng".to_string();
        let maybe_valid_sign1 = validate_signature(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256);
        assert!(maybe_valid_sign1.is_ok());

        let jwt2 = encode(header, &get_rsa_256_private_key_full_path(), &p1, Algorithm::RS256).unwrap();
        let maybe_valid_sign2 = validate_signature(&jwt2, &get_rsa_256_public_key_full_path(), Algorithm::RS256);

        assert!(maybe_valid_sign2.unwrap());
    }

    #[test]
    fn test_validate_signature_jwt_rs256_invalid() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2"
        });
        let  header = json!({});
        let jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0=.RQdLX70LEWL3PFePR2ec7fsBLwi29qK9GL_YfiBKcOWnWsgWMrw0PeJw8h21FloKAYYRq73GmSlF39B5TWbquscf3obfD_y3TYmSjY_STlQ1UTMBnCmwZeMgxuIlq4l7RNpGh_j-42u6YJ3b4zwFiiIGWANYTL0pzXjdIFcUhuY7yeYlFHmWgUOOfv_E_MaP0CgCK6rgeorPtFZ80Z-zYc2R7oXLylgiwJQmwLGzxAcOOcNaZurhQxUQ7GrErY9fOLxfw0vmF4FMSIhQvWIiUV9Meh3MoIwybDhuy5-Y85WZwtXYC7blAZhU0h6tFqwBozt7PS34htj8rkCIqqi0Ng==".to_string();
        let maybe_valid_sign1 = validate_signature(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256);
        assert!(maybe_valid_sign1.is_ok());

        let jwt2 = encode(header, &get_rsa_256_private_key_full_path(), &p1, Algorithm::RS256).unwrap();
        let maybe_valid_sign2 = validate_signature(&jwt2, &get_bad_rsa_256_public_key_full_path(), Algorithm::RS256);

        assert!(!maybe_valid_sign2.unwrap());
    }

    #[test]
    fn test_decode_valid_jwt_rs256_and_check_deeply() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2"
        });
        let h1 = json!({"typ" : STANDARD_HEADER_TYPE, "alg" : Algorithm::RS256.to_string()});
        let jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0=.RQdLX70LEWL3PFePR2ec7fsBLwi29qK9GL_YfiBKcOWnWsgWMrw0PeJw8h21FloKAYYRq73GmSlF39B5TWbquscf3obfD_y3TYmSjY_STlQ1UTMBnCmwZeMgxuIlq4l7RNpGh_j-42u6YJ3b4zwFiiIGWANYTL0pzXjdIFcUhuY7yeYlFHmWgUOOfv_E_MaP0CgCK6rgeorPtFZ80Z-zYc2R7oXLylgiwJQmwLGzxAcOOcNaZurhQxUQ7GrErY9fOLxfw0vmF4FMSIhQvWIiUV9Meh3MoIwybDhuy5-Y85WZwtXYC7blAZhU0h6tFqwBozt7PS34htj8rkCIqqi0Ng==".to_string();
        let (h2, p2) = decode(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256, &ValidationOptions::dangerous()).unwrap();
        assert_eq!(h1.get("typ").unwrap(), h2.get("typ").unwrap());
        assert_eq!(h1.get("alg").unwrap(), h2.get("alg").unwrap());
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_encode_and_decode_jwt_ec256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });
        let header = json!({});
        let h1 = json!({"typ" : STANDARD_HEADER_TYPE, "alg" : Algorithm::ES256.to_string()});

        let jwt1 = encode(header, &get_ec_private_key_path(), &p1, Algorithm::ES256).unwrap();
        let (header, payload) = decode(&jwt1, &get_ec_public_key_path(), Algorithm::ES256, &ValidationOptions::dangerous()).unwrap();
        assert_eq!(p1, payload);
        assert_eq!(h1, header);
    }

    #[test]
    fn test_validate_signature_jwt_ec256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });
        let header = json!({});

        let jwt1 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0.ClXK6cQOk3RgRRNZH53OFvamD9LT2mXo-YEZDlwx1tWu2xkZ9gfBEf2s6xQ9kwDAEna38upYNOrz47KkDkppZA";
        let maybe_valid_sign1 = validate_signature(jwt1, &get_ec_public_key_path(), Algorithm::ES256);
        assert!(maybe_valid_sign1.unwrap());

        let jwt2 = encode(header, &get_ec_private_key_path(), &p1, Algorithm::ES256).unwrap();
        let maybe_valid_sign2 = validate_signature(&jwt2, &get_ec_public_key_path(), Algorithm::ES256);
        assert!(maybe_valid_sign2.unwrap());
    }

    #[test]
    fn test_validate_signature_jwt_ec256_invalid_length() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });
        let header = json!({});

        let jwt1 = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0.ClXK6cQOk3RgRRNZH53OFvamD9LT2mXo-YEZDlwx1tWu2xkZ9g";
        let maybe_valid_sign1 = validate_signature(jwt1, &get_ec_public_key_path(), Algorithm::ES256);
        assert_eq!(maybe_valid_sign1, Err(Error::SignatureInvalid));
    }

    #[test]
    fn test_validate_signature_jwt_ec256_invalid() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let header = json!({});
        let jwt1 = encode(header, &get_ec_private_key_path(), &p1, Algorithm::ES256).unwrap();
        let maybe_valid_sign = validate_signature(&jwt1, &get_bad_ec_public_key_path(), Algorithm::ES256);
        assert!(!maybe_valid_sign.unwrap());
    }

    #[test]
    fn test_encode_and_decode_jwt_ec521() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });
        let header = json!({});
        let h1 = json!({"typ" : STANDARD_HEADER_TYPE, "alg" : Algorithm::ES512.to_string()});

        let jwt1 = encode(header, &get_ec521_private_key_path(), &p1, Algorithm::ES512).unwrap();
        let (header, payload) = decode(&jwt1, &get_ec521_public_key_path(), Algorithm::ES512, &ValidationOptions::dangerous()).unwrap();
        assert_eq!(p1, payload);
        assert_eq!(h1, header);
    }

    #[test]
    fn test_header_typ_override() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let h1 = json!({"typ" : "cust", "alg" : Algorithm::ES256.to_string()});
        let header = json!({"typ" : "cust"});
        let jwt1 = encode(header, &get_ec_private_key_path(), &p1, Algorithm::ES256).unwrap();
        let (header, payload) = decode(&jwt1, &get_ec_public_key_path(), Algorithm::ES256, &ValidationOptions::dangerous()).unwrap();
        assert_eq!(h1, header);
        assert_eq!(p1, payload);
    }

    #[test]
    fn test_invalidate_exp() {
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmcmFua19qd3QgdGVzdCIsImlhdCI6MTU2MzI5OTg0MCwiZXhwIjoxNTYzMjk5ODQ4LCJhdWQiOiIiLCJzdWIiOiIifQ.PgwVxIO_2I4pWiY5bLTD5EzBgcYYabxvFk7vuPO2ZPE";
        let result = decode(&jwt, &String::from("secret123"), Algorithm::HS256, &ValidationOptions::default());
        assert_eq!(result.is_err(), true);
        assert_eq!(result.err().unwrap(), Error::ExpirationInvalid);

    }

    #[test]
    fn test_valid_exp() {
        // This JWT will expire in 2080...
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmcmFua19qd3QgdGVzdCIsImlhdCI6MTU2MzI5OTg0MCwiZXhwIjozNDg4MjkyMTgzLCJhdWQiOiIiLCJzdWIiOiIifQ.jYOfBQd7QbrlSuCjXrfw4rxc2IVo3igAxZyNz49Voek";
        let result = decode(&jwt, &String::from("secret123"), Algorithm::HS256, &ValidationOptions::default());
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn test_leeway_exp() {
        let utc = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let p1 = json!({
            "exp" : utc - 2,
        });

        let secret = "secret123".to_string();
        let header = json!({});
        let jwt = encode(header, &secret, &p1, Algorithm::HS512).unwrap();

        let mut validation = ValidationOptions::default();
        validation.exp_leeway = 5;
        let result = decode(&jwt, &String::from("secret123"), Algorithm::HS512, &validation);
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn test_verify_integer_unix_timestamp_in_future() {
        let utc = std::time::SystemTime::now().add(Duration::from_secs(60)).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let result = verify_expiration(&json!({"exp" : utc}), 0);

        assert!(result);
    }

    #[test]
    fn test_do_not_verify_integer_unix_timestamp_in_past() {
        let utc = std::time::SystemTime::now().sub(Duration::from_secs(60)).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let result = verify_expiration(&json!({"exp" : utc}), 0);

        assert!(!result);
    }

    #[test]
    fn test_verify_float_unix_timestamp_in_future() {
        let utc = std::time::SystemTime::now().add(Duration::from_secs(60)).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();

        let result = verify_expiration(&json!({"exp" : utc}), 0);

        assert!(result);
    }

    #[test]
    fn test_do_not_float_integer_unix_timestamp_in_past() {
        let utc = std::time::SystemTime::now().sub(Duration::from_secs(60)).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();

        let result = verify_expiration(&json!({"exp" : utc}), 0);

        assert!(!result);
    }

    fn get_ec_private_key_path() -> PathBuf {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("ec_x9_62_prime256v1.private.key.pem");
        path.to_path_buf()
    }

    fn get_ec_public_key_path() -> PathBuf {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("ec_x9_62_prime256v1.public.key.pem");
        path.to_path_buf()
    }

    fn get_ec521_private_key_path() -> PathBuf {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("es512_private_key.pem");
        path.to_path_buf()
    }

    fn get_ec521_public_key_path() -> PathBuf {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("es512_public_key.pem");
        path.to_path_buf()
    }

    fn get_bad_ec_public_key_path() -> PathBuf {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("ec_2_x9_62_prime256v1.public.key.pem");
        path.to_path_buf()
    }

    fn get_rsa_256_private_key_full_path() -> PathBuf {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_rsa_2048_key.pem");
        path.to_path_buf()
    }

    fn get_rsa_256_public_key_full_path() -> PathBuf {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_rsa_public_2048_key.pem");
        path.to_path_buf()
    }

    fn get_bad_rsa_256_public_key_full_path() -> PathBuf {
        let mut path = env::current_dir().unwrap();
        path.push("test");
        path.push("my_bad_rsa_public_2048_key.pem");
        path.to_path_buf()
    }
}
