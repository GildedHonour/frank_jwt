/**
 * Copyright (c) 2015-2018 Alex Maslakov, <gildedhonour.com>, <alexmaslakov.me>
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

use std::io::Error as IoError;
use serde_json::Error as SJError;
use openssl::error::ErrorStack;
use base64::DecodeError as B64Error;
use std::error;
use std::fmt;

macro_rules! impl_error {
    ($from:ty, $to:path) => {
        impl From<$from> for Error {
            fn from(e: $from) -> Self {
                $to(format!("{:?}", e))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    SignatureExpired,
    SignatureInvalid,
    JWTInvalid,
    IssuerInvalid,
    ExpirationInvalid,
    AudienceInvalid,
    FormatInvalid(String),
    IoError(String),
    OpenSslError(String),
    ProtocolError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::SignatureExpired => write!(f, "Signature expired."),
            Error::SignatureInvalid => write!(f, "Signature invalid."),
            Error::JWTInvalid => write!(f, "JWT invalid."),
            Error::IssuerInvalid => write!(f, "Issuer invalid."),
            Error::ExpirationInvalid => write!(f, "Expiration invalid."),
            Error::AudienceInvalid => write!(f, "Audience invalid."),
            Error::FormatInvalid(msg) => write!(f, "Format invalid: {}.", msg),
            Error::IoError(msg) => write!(f, "Format invalid: {}.", msg),
            Error::OpenSslError(msg) => write!(f, "Format invalid: {}.", msg),
            Error::ProtocolError(msg) => write!(f, "Format invalid: {}.", msg),
        }
    }
}

impl error::Error for Error {}

impl_error!{IoError, Error::IoError}
impl_error!{SJError, Error::FormatInvalid}
impl_error!{ErrorStack, Error::OpenSslError}
impl_error!{B64Error, Error::ProtocolError}
