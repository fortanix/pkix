/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::types::{GeneralName, GeneralNames};
use crate::yasna::{BERDecodable, BERReader, DERWriter, Tag};
use crate::{ASN1Result, DerWrite};

/// The role attribute, specified in [X.509-2000], carries information
/// about role allocations of the AC holder.
///
/// The syntax used for this attribute is as described in [RFC 3281 Section 4.4.5]:
/// ```text
///
/// RoleSyntax ::= SEQUENCE {
///         roleAuthority   [0] GeneralNames OPTIONAL,
///         roleName        [1] GeneralName
/// }
/// ```
/// [X.509-2000]: https://datatracker.ietf.org/doc/html/rfc3281#ref-X.509-2000
/// [RFC 3281 Section 4.4.5]: https://datatracker.ietf.org/doc/html/rfc3281#section-4.4.5
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Role<'a> {
    pub role_authority: Option<GeneralNames<'a>>,
    pub role_name: GeneralName<'a>,
}

impl Role<'_> {
    /// IMPLICIT TAG (rfc3281#appendix B)
    const TAG_ROLE_AUTHORITY: u64 = 0;
    /// EXPLICIT TAG because [GeneralName] is type of CHOICE
    const TAG_ROLE_NAME: u64 = 1;
}

impl DerWrite for Role<'_> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            if let Some(role_authority) = self.role_authority.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_ROLE_AUTHORITY), |w| {
                        role_authority.write(w)
                    })
            };
            writer
                .next()
                .write_tagged(Tag::context(Self::TAG_ROLE_NAME), |w| self.role_name.write(w))
        });
    }
}

impl BERDecodable for Role<'_> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let role_authority = reader.read_optional(|r_optional| {
                r_optional.read_tagged_implicit(Tag::context(Self::TAG_ROLE_AUTHORITY), |r| {
                    GeneralNames::decode_ber(r)
                })
            })?;
            let role_name = reader
                .next()
                .read_tagged(Tag::context(Self::TAG_ROLE_NAME), |r| GeneralName::decode_ber(r))?;
            Ok(Role {
                role_authority,
                role_name,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use b64_ct::{ToBase64, STANDARD};
    use crate::{FromDer, ToDer};

    use super::*;

    #[test]
    fn role_construct() {
        let example = Role {
            role_authority: None,
            role_name: GeneralName::RegisteredID(vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into()),
        };
        let der = example.to_der();
        println!("{}", der.to_base64(STANDARD));
        let example_decode = Role::from_der(&der).expect("from der");
        assert_eq!(example_decode, example);
    }
}
