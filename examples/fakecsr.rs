/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate pkix;

use pkix::pem::{der_to_pem, PEM_CERTIFICATE_REQUEST};

#[path="../tests/fakes.rs"]
pub mod fakes;

fn main() {
    let csr = fakes::csr_der(fakes::random_printable_string);

    println!("{}", der_to_pem(&csr, PEM_CERTIFICATE_REQUEST));
}
