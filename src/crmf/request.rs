/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! Request-related types

use bit_vec::BitVec;
use yasna::{ASN1Result, BERDecodable, BERReader, DERWriter, Tag};

use crate::{
    types::{Attribute, DerSequence, Extensions, Name, SignatureAlgorithm},
    x509::{SubjectPublicKeyInfo, Version},
    DerWrite,
};

use super::{controls::Controls, pop::ProofOfPossession};

/// The `CertReqMessages` type is defined in [RFC 4211 Section 3].
///
/// ```text
///   CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
/// ```
///
/// [RFC 4211 Section 3]: https://www.rfc-editor.org/rfc/rfc4211#section-3
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertReqMessages(pub Vec<CertReqMsg>);

impl DerWrite for CertReqMessages {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence_of(|w| {
            for cert_req_msg in &self.0 {
                cert_req_msg.write(w.next())
            }
        })
    }
}

impl BERDecodable for CertReqMessages {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(CertReqMessages(reader.collect_sequence_of(CertReqMsg::decode_ber)?))
    }
}

/// The `CertReqMsg` type is defined in [RFC 4211 Section 3].
///
/// ```text
///   CertReqMsg ::= SEQUENCE {
///       certReq   CertRequest,
///       popo       ProofOfPossession  OPTIONAL,
///       -- content depends upon key type
///       regInfo   SEQUENCE SIZE(1..MAX) OF
///           SingleAttribute{{RegInfoSet}} OPTIONAL }
/// ```
///
/// [RFC 4211 Section 3]: https://www.rfc-editor.org/rfc/rfc4211#section-3
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertReqMsg {
    pub cert_req: CertRequest,
    pub popo: Option<ProofOfPossession>,
    pub reg_info: Option<AttributeSeq>,
}

impl DerWrite for CertReqMsg {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.cert_req.write(writer.next());
            if let Some(popo) = self.popo.as_ref() {
                popo.write(writer.next());
            };
            if let Some(reg_info) = self.reg_info.as_ref() {
                writer.next().write_sequence_of(|w| {
                    for attr in reg_info {
                        attr.write(w.next())
                    }
                })
            }
        })
    }
}

impl BERDecodable for CertReqMsg {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let cert_req = <CertRequest as BERDecodable>::decode_ber(reader.next())?;
            let popo: Option<ProofOfPossession> =
                reader.read_optional(|reader| <ProofOfPossession as BERDecodable>::decode_ber(reader))?;
            let reg_info = reader.read_optional(|reader| reader.collect_sequence_of(Attribute::decode_ber))?;
            Ok(CertReqMsg {
                cert_req,
                popo,
                reg_info,
            })
        })
    }
}

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
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertRequest {
    pub cert_req_id: u32,
    pub cert_template: CertTemplate,
    pub controls: Option<Controls>,
}

impl DerWrite for CertRequest {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.cert_req_id.write(writer.next());
            self.cert_template.write(writer.next());
            if let Some(controls) = self.controls.as_ref() {
                controls.write(writer.next());
            }
        })
    }
}

impl BERDecodable for CertRequest {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let cert_req_id = <u32 as BERDecodable>::decode_ber(reader.next())?;
            let cert_template = <CertTemplate as BERDecodable>::decode_ber(reader.next())?;
            let controls = reader.read_optional(|r| Controls::decode_ber(r))?;
            Ok(CertRequest {
                cert_req_id,
                cert_template,
                controls,
            })
        })
    }
}

/// AttributeSeq corresponds to the type that is inlined in the CertReqMsg
/// definition for the regInfo field, as shown below:
/// ```text
///       regInfo   SEQUENCE SIZE(1..MAX) OF
///           SingleAttribute{{RegInfoSet}} OPTIONAL }
/// ```
pub type AttributeSeq = Vec<Attribute<'static>>;

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
pub struct CertTemplate<A: SignatureAlgorithm = DerSequence<'static>> {
    pub version: Option<Version>,
    pub serial_number: Option<SerialNumber>,
    pub signature: Option<A>,
    pub issuer: Option<Name>,
    pub validity: Option<Validity>,
    pub subject: Option<Name>,
    pub subject_public_key_info: Option<SubjectPublicKeyInfo>,
    pub issuer_unique_id: Option<BitVec>,
    pub subject_unique_id: Option<BitVec>,
    pub extensions: Option<Extensions>,
}

/// TODO: fields not needed now are not fully implemented, track ticket:
pub type SerialNumber = u32;
/// TODO: fields not needed now are not fully implemented, track ticket:
pub type Validity = DerSequence<'static>;

impl<A: SignatureAlgorithm> CertTemplate<A> {
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_VERSION: u64 = 0;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_SERIAL_NUMBER: u64 = 1;
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_SIGNATURE: u64 = 2;
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

impl<A: SignatureAlgorithm + DerWrite> DerWrite for CertTemplate<A> {
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
            if let Some(signature) = self.signature.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_SIGNATURE), |w| signature.write(w))
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
impl<A: SignatureAlgorithm + BERDecodable> BERDecodable for CertTemplate<A> {
    fn decode_ber(reader: BERReader<'_, '_>) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let version = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_VERSION), |reader| Version::decode_ber(reader))
            })?;
            let serial_number = reader.read_optional(|r| {
                r.read_tagged_implicit(Tag::context(Self::TAG_SERIAL_NUMBER), |reader| {
                    SerialNumber::decode_ber(reader)
                })
            })?;
            let signature = reader
                .read_optional(|r| r.read_tagged_implicit(Tag::context(Self::TAG_SIGNATURE), |reader| A::decode_ber(reader)))?;
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
                signature,
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
