/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! Rust implementation of the Certificate Management Protocol (CMP) as
//! described in [RFC 4210](https://datatracker.ietf.org/doc/html/rfc4210)

pub mod body;
pub mod gen;
pub mod header;
pub mod message;
