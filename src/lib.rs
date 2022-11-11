/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![deny(warnings)]
#![recursion_limit="256"]

pub extern crate yasna;
pub extern crate num_bigint;
extern crate b64_ct;
extern crate num_integer;
pub extern crate bit_vec;
#[macro_use]
extern crate lazy_static;
extern crate chrono;
extern crate hex;

#[macro_use]
pub mod derives;
pub mod error;
pub mod algorithms;
pub mod cms;
pub mod oid;
pub mod types;
pub mod x509;
pub mod pkcs10;
pub mod pem;
mod serialize;
mod deserialize;

pub use serialize::{DerWrite, ToDer};
pub use deserialize::{FromDer, FromBer};

pub use yasna::{ASN1Error, ASN1Result, construct_der};
