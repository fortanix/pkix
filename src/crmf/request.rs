/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! Request-related types

use bit_vec::BitVec;
use num_bigint::{BigInt, BigUint};
use yasna::{ASN1Result, BERDecodable, BERReader, DERWriter, Tag};

use crate::{
    types::{Attribute, Extensions, Name, DerAnyOwned, AlgorithmIdentifierOwned},
    x509::{SubjectPublicKeyInfo, Version},
    DerWrite,
};

use super::{controls::Controls, pop::ProofOfPossession};

derive_sequence_of!{
    /// The `CertReqMessages` type is defined in [RFC 4211 Section 3].
    ///
    /// ```text
    ///   CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
    /// ```
    ///
    /// [RFC 4211 Section 3]: https://www.rfc-editor.org/rfc/rfc4211#section-3
    CertReqMsg => CertReqMessages
}

derive_sequence! {
    /// X.501 `AttributeTypeAndValue` as defined in [RFC 5280 Appendix A.1].
    ///
    /// ```text
    /// AttributeTypeAndValue ::= SEQUENCE {
    ///   type     AttributeType,
    ///   value    AttributeValue
    /// }
    /// ```
    ///
    /// [RFC 5280 Appendix A.1]: https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1
    CertReqMsg {
        cert_req: [_] UNTAGGED REQUIRED: CertRequest,
        popo:     [_] UNTAGGED OPTIONAL: Option<ProofOfPossession>,
        reg_info: [_] UNTAGGED OPTIONAL: Option<AttributeSeq>,
    }
}

derive_sequence! {
    /// The `CertRequest` type is defined in [RFC 4211 Section 5].
    ///
    /// ```text
    ///   CertRequest ::= SEQUENCE {
    ///       certReqId     INTEGER,
    ///       -- ID for matching request and reply
    ///       certTemplate  CertTemplate,
    ///       -- Selected fields of cert to be issued
    ///       controls      Controls OPTIONAL }
    ///       -- Attributes affecting issuance
    /// ```
    ///
    /// [RFC 4211 Section 5]: https://www.rfc-editor.org/rfc/rfc4211#section-5
    CertRequest {
        cert_req_id:   [_] UNTAGGED REQUIRED: BigInt,
        cert_template: [_] UNTAGGED REQUIRED: CertTemplate,
        controls:      [_] UNTAGGED OPTIONAL: Option<Controls>,
    }
}

derive_sequence_of!{
    /// AttributeSeq corresponds to the type that is inlined in the CertReqMsg
    /// definition for the regInfo field, as shown below:
    /// ```text
    ///       regInfo   SEQUENCE SIZE(1..MAX) OF
    ///           SingleAttribute{{RegInfoSet}} OPTIONAL }
    /// ```
    Attribute<'static> => AttributeSeq
}

/// The `CertTemplate` type is defined in [RFC 4211 Section 5].
///
/// ```text
///   CertTemplate ::= SEQUENCE {
///       version      [0] Version               OPTIONAL,
///       serialNumber [1] INTEGER               OPTIONAL,
///       signingAlg   [2] AlgorithmIdentifier{SIGNATURE-ALGORITHM,
///                            {SignatureAlgorithms}}   OPTIONAL,
///       issuer       [3] Name                  OPTIONAL,
///       validity     [4] OptionalValidity      OPTIONAL,
///       subject      [5] Name                  OPTIONAL,
///       publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
///       issuerUID    [7] UniqueIdentifier      OPTIONAL,
///       subjectUID   [8] UniqueIdentifier      OPTIONAL,
///       extensions   [9] Extensions{{CertExtensions}}  OPTIONAL }
/// ```
///
/// [RFC 4211 Section 5]: https://www.rfc-editor.org/rfc/rfc4211#section-5
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertTemplate {
    pub version: Option<Version>,
    pub serial_number: Option<SerialNumber>,
    pub signing_alg: Option<AlgorithmIdentifierOwned>,
    pub issuer: Option<Name>,
    pub validity: Option<Validity>,
    pub subject: Option<Name>,
    pub subject_public_key_info: Option<SubjectPublicKeyInfo>,
    pub issuer_unique_id: Option<BitVec>,
    pub subject_unique_id: Option<BitVec>,
    pub extensions: Option<Extensions>,
}

/// TODO: fields not needed now are not fully implemented
pub type SerialNumber = BigUint;
/// TODO: fields not needed now are not fully implemented
pub type Validity = DerAnyOwned;

impl CertTemplate {
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_VERSION: u64 = 0;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_SERIAL_NUMBER: u64 = 1;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_SIGNING_ALG: u64 = 2;
    /// EXPLICIT TAG, because issuer is type of NAME which is a CHOICE
    const TAG_ISSUER: u64 = 3;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_VALIDITY: u64 = 4;
    /// EXPLICIT TAG, because subject is type of NAME which is a CHOICE
    const TAG_SUBJECT: u64 = 5;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_SUBJECT_PUBLIC_KEY_INFO: u64 = 6;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_ISSUER_UNIQUE_ID: u64 = 7;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_SUBJECT_UNIQUE_ID: u64 = 8;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_EXTENSIONS: u64 = 9;
}

impl DerWrite for CertTemplate {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            if let Some(version) = self.version.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_VERSION), |w| version.write(w))
            };
            if let Some(serial_number) = self.serial_number.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_SERIAL_NUMBER), |w| serial_number.write(w))
            };
            if let Some(signature) = self.signing_alg.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_SIGNING_ALG), |w| signature.write(w))
            };
            if let Some(issuer) = self.issuer.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_ISSUER), |w| issuer.write(w))
            };
            if let Some(validity) = self.validity.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_VALIDITY), |w| validity.write(w))
            };
            if let Some(subject) = self.subject.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_SUBJECT), |w| subject.write(w))
            };
            if let Some(spki) = self.subject_public_key_info.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_SUBJECT_PUBLIC_KEY_INFO), |w| spki.write(w))
            };

            if let Some(issuer_unique_id) = self.issuer_unique_id.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_ISSUER_UNIQUE_ID), |w| issuer_unique_id.write(w))
            };
            if let Some(subject_unique_id) = self.subject_unique_id.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_SUBJECT_UNIQUE_ID), |w| subject_unique_id.write(w))
            };
            if let Some(extensions) = self.extensions.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_EXTENSIONS), |w| extensions.write(w))
            };
        });
    }
}
impl BERDecodable for CertTemplate {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let version = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_VERSION), |reader| Version::decode_ber(reader))
            })?;
            let serial_number = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_SERIAL_NUMBER), |reader| {
                    SerialNumber::decode_ber(reader)
                })
            })?;
            let signing_alg = reader
                .read_optional(|r| r.read_tagged_implicit(Tag::context(Self::TAG_SIGNING_ALG), |reader| AlgorithmIdentifierOwned::decode_ber(reader)))?;
            let issuer =
                reader.read_optional(|r| r.read_tagged(Tag::context(Self::TAG_ISSUER), |reader| Name::decode_ber(reader)))?;
            let validity = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_VALIDITY), |reader| Validity::decode_ber(reader))
            })?;

            let subject =
                reader.read_optional(|r| r.read_tagged(Tag::context(Self::TAG_SUBJECT), |reader| Name::decode_ber(reader)))?;
            let subject_public_key_info = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_SUBJECT_PUBLIC_KEY_INFO), |reader| {
                    SubjectPublicKeyInfo::decode_ber(reader)
                })
            })?;

            let issuer_unique_id = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_ISSUER_UNIQUE_ID), |reader| BitVec::decode_ber(reader))
            })?;
            let subject_unique_id = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_SUBJECT_UNIQUE_ID), |reader| BitVec::decode_ber(reader))
            })?;
            let extensions = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_EXTENSIONS), |reader| Extensions::decode_ber(reader))
            })?;
            Ok(CertTemplate {
                version,
                serial_number,
                signing_alg,
                issuer,
                validity,
                subject,
                subject_public_key_info,
                issuer_unique_id,
                subject_unique_id,
                extensions,
            })
        })
    }
}
