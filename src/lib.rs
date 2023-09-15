/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![recursion_limit="256"]

pub extern crate yasna;
pub extern crate num_bigint;
extern crate bitflags;
extern crate b64_ct;
extern crate num_integer;
pub extern crate bit_vec;
#[macro_use]
extern crate lazy_static;
extern crate chrono;

#[macro_use]
pub mod derives;
pub mod algorithms;
pub mod cms;
pub mod oid;
pub mod types;
pub mod x509;
pub mod pkcs10;
pub mod pem;
pub mod cmpv2;
pub mod crmf;
pub mod rfc3281;
mod serialize;
mod deserialize;

pub use serialize::{DerWrite, ToDer};
pub use deserialize::{FromDer, FromBer};

pub use yasna::{ASN1Error, ASN1Result};

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use yasna::BERDecodable;
    use std::fmt::Debug;

    pub fn test_encode_decode<T: DerWrite + BERDecodable + Debug + PartialEq>(value: &T, expected_der: &[u8]) {
        assert_eq!(yasna::construct_der(|w| value.write(w)), expected_der);
        assert_eq!(&yasna::parse_der(expected_der, |r| T::decode_ber(r)).unwrap(), value);
    }
}
