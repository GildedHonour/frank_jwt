use base64::DecodeError as B64Error;
use openssl::error::ErrorStack;
use serde_json::Error as SJError;
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

macro_rules! impl_error {
    ($from:ty, $to:path) => {
        impl From<$from> for Error {
            fn from(e: $from) -> Self {
                $to(format!("{:?}", e))
            }
        }
    };
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

impl_error!{IoError, Error::IoError}
impl_error!{SJError, Error::FormatInvalid}
impl_error!{ErrorStack, Error::OpenSslError}
impl_error!{B64Error, Error::ProtocolError}
