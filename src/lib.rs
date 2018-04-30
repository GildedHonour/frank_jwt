/**
 (c) 2015-2018 Alex Maslakov, <gildedhonour.com>, <alexmaslakov.me>
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

extern crate time;
extern crate openssl;
extern crate serde;
extern crate base64;
extern crate derp;
extern crate untrusted;

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
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::ec::EcKey;
use serde_json::Value as JsonValue;
use base64::{encode_config as b64_enc, decode_config as b64_dec};
use derp::{Tag, Der};
use untrusted::Input;

pub use error::Error;

const SEGMENTS_COUNT: usize = 3;

const STANDARD_HEADER_TYPE: &str = "JWT";

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

pub fn decode<P: ToKey>(encoded_token: &String, signing_key: &P, algorithm: Algorithm) -> Result<(JsonValue, JsonValue), Error> {
    let (header, payload, signature, signing_input) = decode_segments(encoded_token)?;
    if !verify_signature(algorithm, signing_input, &signature, signing_key)? {
        Err(Error::SignatureInvalid)
    } else {
        Ok((header, payload))
    }
}

fn get_signing_input(payload: &JsonValue, header: &JsonValue) -> Result<String, Error> {
    let header_json_str = serde_json::to_string(header)?;
    let encoded_header = b64_enc(header_json_str.as_bytes(), base64::URL_SAFE);
    let payload_json_str = serde_json::to_string(payload)?;
    let encoded_payload = b64_enc(payload_json_str.as_bytes(), base64::URL_SAFE);
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
    Ok(b64_enc(hmac.as_slice(), base64::URL_SAFE))
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
    let key = PKey::from_ec_key(ec_key)?;
    let stp = match algorithm {
        Algorithm::ES256 => MessageDigest::sha256(),
        Algorithm::ES384 => MessageDigest::sha384(),
        Algorithm::ES512 => MessageDigest::sha512(),
        _  => panic!("Invalid hmac algorithm")
    };

    let mut signer = Signer::new(stp, &key)?;
        signer.update(data.as_bytes())?;
    let signature = signer.sign_to_vec()?;

    // OpenSSL returns signature in DER format. Convert to raw format before encoding.
    let signature_raw = der_to_raw_signature(&signature);
    Ok(b64_enc(signature_raw.as_slice(), base64::URL_SAFE))
}

fn sign(data: &str, private_key: PKey,digest: MessageDigest) -> Result<String, Error> {
    let mut signer = Signer::new(digest, &private_key)?;
    signer.update(data.as_bytes())?;
    let signature = signer.sign_to_vec()?;
    Ok(b64_enc(signature.as_slice(), base64::URL_SAFE))
}

fn decode_segments(encoded_token: &String) -> Result<(JsonValue, JsonValue, Vec<u8>, String), Error> {
    let raw_segments: Vec<&str> = encoded_token.split(".").collect();
    if raw_segments.len() != SEGMENTS_COUNT {
        return Err(Error::JWTInvalid);
    }

    let header_segment = raw_segments[0];
    let payload_segment = raw_segments[1];
    let crypto_segment =  raw_segments[2];
    let (header, payload) = decode_header_and_payload(header_segment, payload_segment)?;
    let signature = b64_dec(crypto_segment.as_bytes(), base64::URL_SAFE)?;
    let signing_input = format!("{}.{}", header_segment, payload_segment);
    Ok((header, payload, signature.clone(), signing_input))
}

fn decode_header_and_payload(header_segment: &str, payload_segment: &str) -> Result<(JsonValue, JsonValue), Error> {
    let b64_to_json = |seg| -> Result<JsonValue, Error> {
        serde_json::from_slice(b64_dec(seg, base64::URL_SAFE)?.as_slice()).map_err(Error::from)
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

            let digest = get_sha_algorithm(algorithm);
            let mut verifier = Verifier::new(digest, &key)?;
            verifier.update(signing_input.as_bytes())?;

            // Format signature as DER format for openssl.
            let signature_der = raw_to_der_signature(&signature.to_vec());
            verifier.verify(&signature_der).map_err(Error::from)
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

fn der_to_raw_signature(der_sig: &[u8]) -> Vec<u8> {
    let der_sig = Input::from(der_sig);
    let (r, s) = der_sig.read_all(derp::Error::Read, |der_sig| {
        derp::nested(der_sig, Tag::Sequence, |der_sig| {
            let r = derp::positive_integer(der_sig)?;
            let s = derp::positive_integer(der_sig)?;
            Ok((r.as_slice_less_safe(), s.as_slice_less_safe()))
        })
    }).unwrap();
    let mut raw_sig = Vec::new();
    raw_sig.extend_from_slice(&r);
    raw_sig.extend_from_slice(&s);

    raw_sig
}

fn raw_to_der_signature(raw_sig: &[u8]) -> Vec<u8> {
    let raw_sig_midpoint = raw_sig.len() / 2;
    let r = raw_sig[..raw_sig_midpoint].to_vec();
    let s = raw_sig[raw_sig_midpoint..].to_vec();
    let mut der_sig = Vec::new();
    {
        let mut der = Der::new(&mut der_sig);
        der.sequence(|der| {
            der.positive_integer(&r)?;
            der.positive_integer(&s)
        }).unwrap();
    }

    der_sig
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
    unimplemented!()
}

fn verify_expiration() {
    unimplemented!()
}

fn verify_aud() {
    unimplemented!()
}





#[cfg(test)]
mod tests {
    extern crate time;

    use super::{Algorithm, encode, decode, secure_compare, STANDARD_HEADER_TYPE};
    use std::env;
    use std::path::PathBuf;

    #[test]
    fn test_encode_and_decode_jwt_hs256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });

        let secret = "secret123".to_string();
        let  header = json!({});
        let jwt1 = encode(header, &secret, &p1, Algorithm::HS256).unwrap();
        let maybe_res = decode(&jwt1, &secret, Algorithm::HS256);
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
        let maybe_res = decode(&jwt, &secret, Algorithm::HS256);
        assert!(maybe_res.is_ok());
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
        let maybe_res = decode(&jwt1, &secret, Algorithm::HS384);
        assert!(maybe_res.is_ok());
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
        let maybe_res = decode(&jwt1, &secret, Algorithm::HS512);
        assert!(maybe_res.is_ok());
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
        let maybe_res = decode(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256);
        assert!(maybe_res.is_ok());
    }

    #[test]
    fn test_decode_valid_jwt_rs256() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2"
        });
        let  header = json!({});
        let jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0=.RQdLX70LEWL3PFePR2ec7fsBLwi29qK9GL_YfiBKcOWnWsgWMrw0PeJw8h21FloKAYYRq73GmSlF39B5TWbquscf3obfD_y3TYmSjY_STlQ1UTMBnCmwZeMgxuIlq4l7RNpGh_j-42u6YJ3b4zwFiiIGWANYTL0pzXjdIFcUhuY7yeYlFHmWgUOOfv_E_MaP0CgCK6rgeorPtFZ80Z-zYc2R7oXLylgiwJQmwLGzxAcOOcNaZurhQxUQ7GrErY9fOLxfw0vmF4FMSIhQvWIiUV9Meh3MoIwybDhuy5-Y85WZwtXYC7blAZhU0h6tFqwBozt7PS34htj8rkCIqqi0Ng==".to_string();
        let (h1, p1) = decode(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256).unwrap();
        println!("\n{}",h1);
        println!("{}",p1);
        let jwt2 = encode(header, &get_rsa_256_private_key_full_path(), &p1, Algorithm::RS256).unwrap();
        let (h2, p2) = decode(&jwt2, &get_rsa_256_public_key_full_path(), Algorithm::RS256).unwrap();
        println!("{}",h2);
        println!("{}",p2);
        assert_eq!(jwt1, jwt2);
    }

    #[test]
    fn test_decode_valid_jwt_rs256_and_check_deeply() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2"
        });
        let h1 = json!({"typ" : STANDARD_HEADER_TYPE, "alg" : Algorithm::RS256.to_string()});
        let jwt1 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoidmFsMSIsImtleTIiOiJ2YWwyIn0=.RQdLX70LEWL3PFePR2ec7fsBLwi29qK9GL_YfiBKcOWnWsgWMrw0PeJw8h21FloKAYYRq73GmSlF39B5TWbquscf3obfD_y3TYmSjY_STlQ1UTMBnCmwZeMgxuIlq4l7RNpGh_j-42u6YJ3b4zwFiiIGWANYTL0pzXjdIFcUhuY7yeYlFHmWgUOOfv_E_MaP0CgCK6rgeorPtFZ80Z-zYc2R7oXLylgiwJQmwLGzxAcOOcNaZurhQxUQ7GrErY9fOLxfw0vmF4FMSIhQvWIiUV9Meh3MoIwybDhuy5-Y85WZwtXYC7blAZhU0h6tFqwBozt7PS34htj8rkCIqqi0Ng==".to_string();
        let (h2, p2) = decode(&jwt1, &get_rsa_256_public_key_full_path(), Algorithm::RS256).unwrap();
        assert_eq!(h1.get("typ").unwrap(), h2.get("typ").unwrap());
        assert_eq!(h1.get("alg").unwrap(), h2.get("alg").unwrap());
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_encode_and_decode_jwt_ec() {
        let p1 = json!({
            "key1" : "val1",
            "key2" : "val2",
            "key3" : "val3"
        });
        let header = json!({});
        let h1 = json!({"typ" : STANDARD_HEADER_TYPE, "alg" : Algorithm::ES512.to_string()});

        let jwt1 = encode(header, &get_ec_private_key_path(), &p1, Algorithm::ES512).unwrap();
        let (header, payload) = decode(&jwt1, &get_ec_public_key_path(), Algorithm::ES512).unwrap();
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
        let h1 = json!({"typ" : "cust", "alg" : Algorithm::ES512.to_string()});
        let header = json!({"typ" : "cust"});
 
        let jwt1 = encode(header, &get_ec_private_key_path(), &p1, Algorithm::ES512).unwrap();
        let (header, payload) = decode(&jwt1, &get_ec_public_key_path(), Algorithm::ES512).unwrap();
        assert_eq!(h1, header);
        assert_eq!(p1, payload);
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
}
