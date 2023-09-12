/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! Controls-related types

use yasna::{ASN1Result, BERDecodable, BERReader, DERWriter};

use crate::{x509::AttributeTypeAndValue, DerWrite};

derive_sequence_of!{
    /// The `Controls` type is defined in [RFC 4211 Section 6].
    ///
    /// ```text
    ///   Controls  ::= SEQUENCE SIZE(1..MAX) OF SingleAttribute
    ///                     {{RegControlSet}}
    /// ```
    ///
    /// [RFC 4211 Section 6]: https://www.rfc-editor.org/rfc/rfc4211#section-6
    AttributeTypeAndValue => Controls
}
