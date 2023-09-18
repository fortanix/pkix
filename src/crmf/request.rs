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

derive_sequence! {
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
    ///
    /// Tags are IMPLICIT TAG according to [RFC4211#appendix-B](https://datatracker.ietf.org/doc/html/rfc4211#appendix-B),
    /// but `issuer` and `subject` are EXPLICIT tagged because they are ASN.1 type of `CHOICE`.
    CertTemplate {
        version:                 [0] IMPLICIT OPTIONAL: Option<Version>,
        serial_number:           [1] IMPLICIT OPTIONAL: Option<SerialNumber>,
        signing_alg:             [2] IMPLICIT OPTIONAL: Option<AlgorithmIdentifierOwned>,
        issuer:                  [3] EXPLICIT OPTIONAL: Option<Name>,
        validity:                [4] IMPLICIT OPTIONAL: Option<Validity>,
        subject:                 [5] EXPLICIT OPTIONAL: Option<Name>,
        subject_public_key_info: [6] IMPLICIT OPTIONAL: Option<SubjectPublicKeyInfo>,
        issuer_unique_id:        [7] IMPLICIT OPTIONAL: Option<BitVec>,
        subject_unique_id:       [8] IMPLICIT OPTIONAL: Option<BitVec>,
        extensions:              [9] IMPLICIT OPTIONAL: Option<Extensions>,
    }
}

/// TODO: fields not needed now are not fully implemented
pub type SerialNumber = BigUint;
/// TODO: fields not needed now are not fully implemented
pub type Validity = DerAnyOwned;
