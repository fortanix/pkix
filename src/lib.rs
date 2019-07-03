/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![deny(warnings)]
#![recursion_limit="128"]

pub extern crate yasna;
pub extern crate num_bigint;
extern crate rustc_serialize;
extern crate num_integer;
pub extern crate bit_vec;
#[macro_use]
extern crate lazy_static;

#[macro_use]
pub mod derives;
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

pub use yasna::{ASN1Error, ASN1Result};
