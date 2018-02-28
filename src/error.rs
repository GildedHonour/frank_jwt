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

error_chain! {

    foreign_links {
        IoError(::std::io::Error);
        FormatInvalid(::serde_json::Error);
        OpenSslError(::openssl::error::ErrorStack);
        ProtocolError(::base64::DecodeError);
    }

    errors {
        SignatureExpired
        SignatureInvalid
        JWTInvalid
        IssuerInvalid
        ExpirationInvalid
        AudienceInvalid
    }
}

