/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use bitflags::bitflags;
use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, DERWriter, BERDecodable, Tag, tags::*};
use num_integer::Integer;
use num_bigint::{BigUint, BigInt};
use std::{borrow::Cow, convert::TryFrom};
use bit_vec::BitVec;
use oid;

use DerWrite;
use types::*;
use deserialize::FromBer;

use crate::{ToDer, oid::{certificatePolicies, ID_QT_CPS, ID_QT_UNOTICE, ANY_POLICY}};

pub type RsaPkcs15TbsCertificate<'a> = TbsCertificate<BigUint, RsaPkcs15<Sha256>, DerSequence<'a>>;
pub type RsaPkcs15Certificate<'a> = Certificate<RsaPkcs15TbsCertificate<'a>, RsaPkcs15<Sha256>, BitVec>;

pub type GenericTbsCertificate = TbsCertificate<BigUint, DerSequence<'static>, DerSequence<'static>>;

pub type GenericCertificate = Certificate<GenericTbsCertificate, DerSequence<'static>, BitVec>;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Certificate<T, A: SignatureAlgorithm, S> {
    pub tbscert: T,
    pub sigalg: A,
    pub sig: S,
}

impl<T: DerWrite, A: SignatureAlgorithm + DerWrite, S: DerWrite> DerWrite for Certificate<T, A, S> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.tbscert.write(writer.next());
            self.sigalg.write(writer.next());
            self.sig.write(writer.next());
        });
    }
}

impl<T: BERDecodable, A: SignatureAlgorithm + BERDecodable, S: BERDecodable> BERDecodable for Certificate<T, A, S> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let tbscert = T::decode_ber(r.next())?;
            let sigalg = A::decode_ber(r.next())?;
            let sig = S::decode_ber(r.next())?;

            Ok(Certificate { tbscert, sigalg, sig })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TbsCertificate<S: Integer, A: SignatureAlgorithm, K> {
    pub version: u8,
    pub serial: S,
    pub sigalg: A,
    pub issuer: Name,
    pub validity_notbefore: DateTime,
    pub validity_notafter: DateTime,
    pub subject: Name,
    pub spki: K,
    pub extensions: Vec<Extension>,
}

impl<S: Integer, A: SignatureAlgorithm, K> TbsCertificate<S, A, K> {
    /// Find the extension indicated by `oid`. If exactly one instance
    /// of the extension is present, returns it. Otherwise, returns `None`.
    pub fn get_extension(&self, oid: &ObjectIdentifier) -> Option<Extension> {
        let mut iter = self.extensions.iter().filter(|e| e.oid == *oid);

        match (iter.next(), iter.next()) {
            (Some(ext), None) => Some(ext.to_owned()),
            _ => None,
        }
    }
}

pub const TBS_CERTIFICATE_V1: u8 = 0;
pub const TBS_CERTIFICATE_V2: u8 = 1;
pub const TBS_CERTIFICATE_V3: u8 = 2;

impl<S: DerWrite + Integer, A: DerWrite + SignatureAlgorithm, K: DerWrite> DerWrite
    for TbsCertificate<S, A, K> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            if self.version != TBS_CERTIFICATE_V1 { // default value
                writer.next().write_tagged(Tag::context(0), |w| self.version.write(w));
            }
            self.serial.write(writer.next());
            self.sigalg.write(writer.next());
            self.issuer.write(writer.next());
            writer.next().write_sequence(|writer| {
                self.validity_notbefore.write(writer.next());
                self.validity_notafter.write(writer.next());
            });
            self.subject.write(writer.next());
            self.spki.write(writer.next());
            if !self.extensions.is_empty() {
                writer.next().write_tagged(Tag::context(3), |w| {
                    w.write_sequence(|writer| {
                        for ext in &self.extensions {
                            ext.write(writer.next())
                        }
                    })
                });
            }
        });
    }
}

impl<S: BERDecodable + Integer, A: BERDecodable + SignatureAlgorithm, K: BERDecodable> BERDecodable for TbsCertificate<S, A, K> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let version = r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_u8()))?.unwrap_or(0);
            match version {
                TBS_CERTIFICATE_V1 | TBS_CERTIFICATE_V2 | TBS_CERTIFICATE_V3 => { /* known version */ }
                _ => { return Err(ASN1Error::new(ASN1ErrorKind::Invalid)); }
            };
            let serial = S::decode_ber(r.next())?;
            let sigalg = A::decode_ber(r.next())?;
            let issuer = Name::decode_ber(r.next())?;
            let (validity_notbefore,
                 validity_notafter) = r.next().read_sequence(|r| {
                Ok((DateTime::decode_ber(r.next())?,
                    DateTime::decode_ber(r.next())?))
            })?;
            let subject = Name::decode_ber(r.next())?;
            let spki = K::decode_ber(r.next())?;
            let extensions = r.read_optional(|r| {
                if version != TBS_CERTIFICATE_V3 {
                    return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                }
                r.read_tagged(Tag::context(3), |r| {
                    r.read_sequence(|r| {
                        let mut extensions = Vec::<Extension>::new();

                        loop {
                            let res = r.read_optional(|r| {
                                Extension::decode_ber(r)
                            });
                            match res {
                                Ok(Some(ext)) => extensions.push(ext),
                                Ok(None) => break,
                                Err(e) => return Err(e),
                            }
                        }

                        Ok(extensions)
                    })
                })
            })?.unwrap_or(vec![]);

            Ok(TbsCertificate { version, serial, sigalg, issuer, validity_notbefore, validity_notafter,
                                subject, spki, extensions })
        })
    }
}

/// X.509 `SubjectPublicKeyInfo` (SPKI) as defined in [RFC 5280 § 4.1.2.7].
///
/// ASN.1 structure containing an [`AlgorithmIdentifier`] and public key
/// data in an algorithm specific format.
///
/// ```text
///    SubjectPublicKeyInfo  ::=  SEQUENCE  {
///         algorithm            AlgorithmIdentifier,
///         subjectPublicKey     BIT STRING  }
/// ```
///
/// [RFC 5280 § 4.1.2.7]: https://tools.ietf.org/html/rfc5280#section-4.1.2.7
/// [`AlgorithmIdentifier`]: crate::algorithms::AlgorithmIdentifier
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SubjectPublicKeyInfo<A: SignatureAlgorithm = DerSequence<'static>> {
    /// X.509 [`AlgorithmIdentifier`](crate::algorithms::AlgorithmIdentifier) for the public key type
    pub algorithm: A,

    /// Public key data
    pub subject_public_key: BitVec,
}

impl<A: SignatureAlgorithm + DerWrite> DerWrite for SubjectPublicKeyInfo<A> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.algorithm.write(writer.next());
            self.subject_public_key.write(writer.next());
        });
    }
}

impl<A: SignatureAlgorithm + BERDecodable> BERDecodable for SubjectPublicKeyInfo<A> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let algorithm = A::decode_ber(reader.next())?;
            let subject_public_key = BitVec::decode_ber(reader.next())?;
            Ok(SubjectPublicKeyInfo {
                algorithm,
                subject_public_key,
            })
        })
    }
}

define_version! {
    /// Certificate `Version` as defined in [RFC 5280 Section 4.1].
    ///
    /// ```text
    /// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    /// ```
    ///
    /// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
    Version {
        V1 = 0,
        V2 = 1,
        V3 = 2,
    }
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
    AttributeTypeAndValue {
        oid: ObjectIdentifier,
        value: TaggedDerValue,
    }
}

/// This trait can be used to indicate the value for the `critical` bit for
/// types that can be encoded as X.509 `Extension`.
pub trait IsCritical {
    fn is_critical(&self) -> bool;
}

pub trait ToExtension {
    fn to_extension(&self) -> Extension;
}

impl<T: HasOid + IsCritical + ToDer> ToExtension for T {
    fn to_extension(&self) -> Extension {
        Extension {
            oid: T::oid().clone(),
            critical: self.is_critical(),
            value: self.to_der(),
        }
    }
}

impl IsCritical for BasicConstraints {
    fn is_critical(&self) -> bool {
        true
    }
}

/// BasicConstraints type as defined in RFC 5280.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct BasicConstraints {
    ca: bool,
    path_len_constraint: Option<u64>,
}

impl BasicConstraints {
    pub fn ca(path_len_constraint: Option<u64>) -> Self {
        BasicConstraints { ca: true, path_len_constraint }
    }

    pub fn no_ca() -> Self {
        BasicConstraints { ca: false, path_len_constraint: None }
    }

    /// Returns the value of the `cA` field, as defined in RFC 5280.
    pub fn is_ca(&self) -> bool {
        self.ca
    }

    /// Returns the value of the `pathLenConstraint` field, as defined in RFC 5280.
    ///
    /// Note that the RFC states that the `pathLenConstraint` field is meaningful only if the
    /// `cA` boolean is asserted. It is up to the users of this method to enforce that statement.
    pub fn path_len_constraint(&self) -> Option<u64> {
        self.path_len_constraint
    }
}

impl HasOid for BasicConstraints {
    fn oid() -> &'static ObjectIdentifier {
        &oid::basicConstraints
    }
}

impl DerWrite for BasicConstraints {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            if self.ca { // do not write field if `ca` is equal to default value `false`
                writer.next().write_bool(true);
            }
            if let Some(path_len) = self.path_len_constraint {
                writer.next().write_u64(path_len);
            }
        });
    }
}

impl BERDecodable for BasicConstraints {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let ca = r.read_default(false, |r| r.read_bool())?;
            let path_len_constraint = r.read_optional(|r| r.read_u64())?;
            Ok(BasicConstraints { ca, path_len_constraint })
        })
    }
}

#[deprecated(since="0.1.3", note="use `SubjectAltName` instead")]
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DnsAltNames<'a> {
    pub names: Vec<Cow<'a, str>>,
}

#[allow(deprecated)]
impl<'a> DerWrite for DnsAltNames<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for name in &self.names {
                writer.next().write_tagged_implicit(Tag::context(2), |w|
                    name.as_bytes().write(w)
                )
            }
        });
    }
}

#[allow(deprecated)]
impl<'a> BERDecodable for DnsAltNames<'a> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let mut names = Vec::<Cow<'a, str>>::new();

            loop {
                let res = seq_reader.read_optional(|r| {
                    r.read_tagged_implicit(Tag::context(2), |r| {
                        String::from_utf8(r.read_bytes()?).map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))
                    })
                });
                match res {
                    Ok(Some(s)) => names.push(Cow::Owned(s)),
                    Ok(None) => break,
                    Err(e) => return Err(e),
                }
            }

            Ok(DnsAltNames { names })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SubjectAltName<'a> {
    pub names: GeneralNames<'a>,
}

impl<'a> HasOid for SubjectAltName<'a> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for SubjectAltName<'a> {
    fn write(&self, writer: DERWriter) {
        self.names.write(writer)
    }
}

impl<'a> BERDecodable for SubjectAltName<'a> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(SubjectAltName { names: GeneralNames::decode_ber(reader)? })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IssuerAltName<'a> {
    pub names: GeneralNames<'a>,
}

impl<'a> HasOid for IssuerAltName<'a> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::issuerAltName
    }
}

impl<'a> DerWrite for IssuerAltName<'a> {
    fn write(&self, writer: DERWriter) {
        self.names.write(writer)
    }
}

impl<'a> BERDecodable for IssuerAltName<'a> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(IssuerAltName { names: GeneralNames::decode_ber(reader)? })
    }
}


/// Max number of meaningful bits in the key usage bit string.
const KEY_USAGE_MAX_NUM_BITS: usize = 9;

bitflags! {
    #[repr(transparent)]
    pub struct KeyUsage: u16 {
        const DIGITAL_SIGNATURE = 0x8000;
        const NON_REPUDIATION   = 0x4000;
        const KEY_ENCIPHERMENT  = 0x2000;
        const DATA_ENCIPHERMENT = 0x1000;
        const KEY_AGREEMENT     = 0x0800;
        const KEY_CERT_SIGN     = 0x0400;
        const CRL_SIGN          = 0x0200;
        const ENCIPHER_ONLY     = 0x0100;
        const DECIPHER_ONLY     = 0x0080;
    }
}

impl HasOid for KeyUsage {
    fn oid() -> &'static ObjectIdentifier {
        &oid::keyUsage
    }
}

impl DerWrite for KeyUsage {
    fn write(&self, writer: DERWriter) {
        let bytes = self.bits().to_be_bytes();
        let bit_vec = remove_trailing_zero(&BitVec::from_bytes(&bytes));
        writer.write_bitvec(&bit_vec);
    }
}

pub(crate) fn remove_trailing_zero(bit_vec: &BitVec) -> BitVec {
    let mut ret = bit_vec.clone();
    while ret.iter().last() == Some(false) {
        ret.pop();
    }
    ret
}

impl BERDecodable for KeyUsage {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let mut bit_vec = reader.read_bitvec()?;
        if bit_vec.len() > KEY_USAGE_MAX_NUM_BITS {
            bit_vec.split_off(KEY_USAGE_MAX_NUM_BITS);
        }
        assert!(KEY_USAGE_MAX_NUM_BITS <= u16::BITS as usize);
        let mut array = [0u8; 2];
        let mut bit_bytes = bit_vec.to_bytes();
        bit_bytes.resize(2, 0);
        array.copy_from_slice(&bit_bytes[..2]);
        let flags = u16::from_be_bytes(array);
        Ok(KeyUsage::from_bits_truncate(flags))
    }
}

impl IsCritical for KeyUsage {
    fn is_critical(&self) -> bool {
        true
    }
}


derive_sequence_of!{
    /// SubjectDirectoryAttributes as defined in [RFC 5280 Section 4.2.1.8].
    ///
    /// ```text
    /// SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet
    /// ```
    ///
    /// [RFC 5280 Section 4.2.1.8]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.8
    Attribute<'a> => SubjectDirectoryAttributes<'a>
}

impl HasOid for SubjectDirectoryAttributes<'_> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectDirectoryAttributes
    }
}

impl IsCritical for SubjectDirectoryAttributes<'_> {
    fn is_critical(&self) -> bool {
        false
    }
}

derive_sequence_of! {
    /// CertificatePolicies as defined in [RFC 5280 Section 4.2.1.4].
    ///
    /// ```text
    /// CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
    /// ```
    ///
    /// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
    //  If this extension is
    //  critical, the path validation software MUST be able to interpret this
    //  extension (including the optional qualifier), or MUST reject the
    //  certificate.
    PolicyInformation => CertificatePolicies
}

impl HasOid for CertificatePolicies {
    fn oid() -> &'static ObjectIdentifier {
        &certificatePolicies
    }
}

impl CertificatePolicies {
    pub fn to_extension(&self, is_critical: bool) -> Extension {
        Extension {
            oid: Self::oid().clone(),
            critical: is_critical,
            value: self.to_der(),
        }
    }
}

/// PolicyInformation as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// PolicyInformation ::= SEQUENCE {
///     policyIdentifier   CertPolicyId,
///     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
/// }
///
/// CertPolicyId ::= OBJECT IDENTIFIER
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PolicyInformation {
    pub policy_identifier: CertPolicyId,
    pub policy_qualifiers: Option<Vec<PolicyQualifierInfo>>,
}

pub type CertPolicyId = ObjectIdentifier;

impl BERDecodable for PolicyInformation {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|policy_info_r| {
            let policy_identifier = CertPolicyId::decode_ber(policy_info_r.next())?;
            let policy_qualifiers = policy_info_r
                .read_optional(|qualifiers_r| qualifiers_r.collect_sequence_of(PolicyQualifierInfo::decode_ber))?;
            Ok(Self {
                policy_identifier,
                policy_qualifiers,
            })
        })
    }
}

impl DerWrite for PolicyInformation {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|policy_info_w| {
            self.policy_identifier.write(policy_info_w.next());
            if let Some(ref qualifiers) = self.policy_qualifiers {
                policy_info_w.next().write_sequence_of(|qualifiers_w| {
                    for qual in qualifiers {
                        qual.write(qualifiers_w.next());
                    }
                })
            }
        })
    }
}

derive_sequence! {
    /// PolicyQualifierInfo as defined in [RFC 5280 Section 4.2.1.4].
    ///
    /// ```text
    /// PolicyQualifierInfo ::= SEQUENCE {
    ///     policyQualifierId  PolicyQualifierId,
    ///     qualifier          ANY DEFINED BY policyQualifierId
    /// }
    /// ```
    ///
    /// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
    PolicyQualifierInfo {
        policyQualifierId: [_] UNTAGGED REQUIRED:  ObjectIdentifier,
        qualifier:         [_] UNTAGGED OPTIONAL:  Option<DerAnyOwned>,
    }
}

impl From<InternetPolicyQualifier> for PolicyQualifierInfo {
    fn from(value: InternetPolicyQualifier) -> Self {
        let oid: &ObjectIdentifier = value.oid();
        match value {
            InternetPolicyQualifier::CpsUri(cps_uri) => Self {
                policyQualifierId: oid.clone(),
                qualifier: Some(cps_uri.to_der().into()),
            },
            InternetPolicyQualifier::UserNotice(user_notice) => Self {
                policyQualifierId: oid.clone(),
                qualifier: Some(user_notice.to_der().into()),
            },
        }
    }
}

/// Qualifier as defined in [RFC 5280 Section 4.2.1.4].
/// ```text
/// -- policyQualifierIds for Internet policy qualifiers
///
/// id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
/// id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
/// id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
///
/// PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
///
/// Qualifier ::= CHOICE {
///      cPSuri           CPSuri,
///      userNotice       UserNotice }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum InternetPolicyQualifier {
    CpsUri(CpsUri),
    UserNotice(UserNotice),
}

impl BERDecodable for InternetPolicyQualifier {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        match reader.lookahead_tag()? {
            TAG_IA5STRING => Ok(Self::CpsUri(CpsUri::decode_ber(reader)?)),
            TAG_SEQUENCE => Ok(Self::UserNotice(UserNotice::decode_ber(reader)?)),
            _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        }
    }
}

impl DerWrite for InternetPolicyQualifier {
    fn write(&self, writer: DERWriter) {
        match self {
            InternetPolicyQualifier::CpsUri(cps_uri) => cps_uri.write(writer),
            InternetPolicyQualifier::UserNotice(user_notice) => user_notice.write(writer),
        }
    }
}

impl InternetPolicyQualifier {
    pub fn oid(&self) -> &'static ObjectIdentifier {
        match self {
            InternetPolicyQualifier::CpsUri(_) => &ID_QT_CPS,
            InternetPolicyQualifier::UserNotice(_) => &ID_QT_UNOTICE,
        }
    }
}

impl TryFrom<PolicyQualifierInfo> for InternetPolicyQualifier {
    type Error = ASN1Error;

    fn try_from(value: PolicyQualifierInfo) -> Result<Self, Self::Error> {
        if value.policyQualifierId == *ID_QT_CPS
            || value.policyQualifierId == *ID_QT_UNOTICE
            || value.policyQualifierId == *ANY_POLICY
        {
            Ok(Self::from_ber(&value.qualifier.ok_or(ASN1Error::new(ASN1ErrorKind::Eof))?)?)
        } else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    }
}

/// CpsUri as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// CPSuri ::= IA5String
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
pub type CpsUri = Ia5String;

derive_sequence! {
    /// UserNotice as defined in [RFC 5280 Section 4.2.1.4].
    ///
    /// ```text
    /// UserNotice ::= SEQUENCE {
    ///     noticeRef        NoticeReference OPTIONAL,
    ///     explicitText     DisplayText OPTIONAL
    /// }
    /// ```
    ///
    /// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
    UserNotice {
        notice_ref:    [_] UNTAGGED OPTIONAL:  Option<NoticeReference>,
        explicit_text: [_] UNTAGGED OPTIONAL:  Option<DisplayText>,
    }
}

/// NoticeReference as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// NoticeReference ::= SEQUENCE {
///      organization     DisplayText,
///      noticeNumbers    SEQUENCE OF INTEGER }
/// ```
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NoticeReference {
    pub organization: DisplayText,
    pub notice_numbers: Vec<BigInt>,
}

impl BERDecodable for NoticeReference {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|notice_ref_r| {
            let organization = DisplayText::decode_ber(notice_ref_r.next())?;
            let notice_numbers = notice_ref_r.next().collect_sequence_of(BigInt::decode_ber)?;
            Ok(Self {
                organization,
                notice_numbers,
            })
        })
    }
}

impl DerWrite for NoticeReference {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|notice_ref_w| {
            self.organization.write(notice_ref_w.next());
            notice_ref_w.next().write_sequence_of(|notice_num_w| {
                for number in &self.notice_numbers {
                    number.write(notice_num_w.next());
                }
            })
        })
    }
}

/// DisplayText as defined in [RFC 5280 Section 4.2.1.4].
///
/// ```text
/// DisplayText ::= CHOICE {
///     ia5String        IA5String      (SIZE (1..200)),
///     visibleString    VisibleString  (SIZE (1..200)),
///     bmpString        BMPString      (SIZE (1..200)),
///     utf8String       UTF8String     (SIZE (1..200))
/// }
/// ```
///
/// Only the ia5String and utf8String options are currently supported.
///
/// [RFC 5280 Section 4.2.1.4]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
// TODO: add size validation
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DisplayText {
    Ia5String(Ia5String),
    VisibleString(String),
    BmpString(String),
    Utf8String(String),
}

impl BERDecodable for DisplayText {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        match reader.lookahead_tag()? {
            TAG_IA5STRING => Ok(Self::Ia5String(Ia5String::decode_ber(reader)?)),
            TAG_VISIBLESTRING => Ok(Self::VisibleString(reader.read_visible_string()?)),
            TAG_BMPSTRING => Ok(Self::BmpString(reader.read_bmp_string()?)),
            TAG_UTF8STRING => Ok(Self::Utf8String(reader.read_utf8string()?)),
            _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        }
    }
}

impl DerWrite for DisplayText {
    fn write(&self, writer: DERWriter) {
        match self {
            DisplayText::Ia5String(s) => s.write(writer),
            DisplayText::VisibleString(s) => writer.write_visible_string(s),
            DisplayText::BmpString(s) => writer.write_bmp_string(s),
            DisplayText::Utf8String(s) => writer.write_utf8_string(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::test_encode_decode;

    #[test]
    fn basic_constraints() {
        let test_values = vec![
            (BasicConstraints { ca: false, path_len_constraint: None    }, vec![0x30, 0x00]),
            (BasicConstraints { ca: true,  path_len_constraint: None    }, vec![0x30, 0x03, 0x01, 0x01, 0xFF]),
            (BasicConstraints { ca: true,  path_len_constraint: Some(4) }, vec![0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x04]),
            // Not valid according to RFC 5280, but can still be decoded:
            (BasicConstraints { ca: false,  path_len_constraint: Some(4) }, vec![0x30, 0x03, 0x02, 0x01, 0x04]),
        ];

        for (basic_constraint, der) in test_values {
            test_encode_decode(&basic_constraint, &der);
        }
    }

    #[test]
    #[allow(deprecated)]
    fn dns_alt_names() {
        let names = DnsAltNames {
            names: vec![
                Cow::Borrowed("www.example.com"),
                Cow::Borrowed("example.com"),
            ]
        };

        let der = &[0x30, 0x1e, 0x82, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
                    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
                    0x6d, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
                    0x65, 0x2e, 0x63, 0x6f, 0x6d];

        test_encode_decode(&names, der);
    }

    #[test]
    fn subject_issuer_alt_name() {
        let subject_alt_name = SubjectAltName {
            names: GeneralNames(vec![
                GeneralName::IpAddress(vec![127,0,0,1]),
                GeneralName::RegisteredID(ObjectIdentifier::new(vec![1,2,3,4]))
            ]),
        };
        let issuer_alt_name = IssuerAltName {
            names: GeneralNames(vec![
                GeneralName::IpAddress(vec![127,0,0,1]),
                GeneralName::RegisteredID(ObjectIdentifier::new(vec![1,2,3,4]))
            ]),
        };

        let der = &[
            0x30, 0x0b, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01,
            0x88, 0x03, 0x2a, 0x03, 0x04];

        test_encode_decode(&subject_alt_name, der);
        test_encode_decode(&issuer_alt_name, der);
    }

    #[test]
    fn parse_v1_cert() {
        let der = include_bytes!("../tests/data/v1_cert.der");
        let cert = yasna::parse_der(der, |r| GenericCertificate::decode_ber(r)).unwrap();
        assert_eq!(cert.tbscert.version, TBS_CERTIFICATE_V1);
        assert_eq!(yasna::construct_der(|w| cert.write(w)), der);
    }

    #[test]
    fn parse_v3_cert() {
        let der = include_bytes!("../tests/data/v3_cert.der");
        let cert = yasna::parse_der(der, |r| GenericCertificate::decode_ber(r)).unwrap();
        assert_eq!(cert.tbscert.version, TBS_CERTIFICATE_V3);
        assert_eq!(yasna::construct_der(|w| cert.write(w)), der);
    }
}


#[cfg(test)]
mod key_usage_tests {
    use std::convert::TryInto;

    use crate::oid::{attributeTypeRole, ANY_POLICY};
    use crate::rfc3281::Role;
    use crate::yasna::tags::TAG_BITSTRING;
    use crate::{FromDer, ToDer, FromBer};

    use super::*;

    use b64_ct::{ToBase64, STANDARD};

    /// This tests "When DER encoding a named bit list, trailing zeros MUST be
    /// omitted." from https://datatracker.ietf.org/doc/html/rfc5280#appendix-B
    #[test]
    fn key_usage_can_decode_encode_short() {
        let der = [3, 2, 1, 6];
        let ret = KeyUsage::from_der(&der).expect("can decode short");
        assert_eq!(ret, (KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN), "KeyUsage not equal");
        assert_eq!(&der[..], &ret.to_der(), "KeyUsage DER not equal");
    }

    #[test]
    fn key_usage_bits() {
        struct Test {
            input: KeyUsage,
            expected_bits: Vec<u8>,
        }
        let tests = vec![
            Test {
                input: KeyUsage::DIGITAL_SIGNATURE
                    | KeyUsage::DATA_ENCIPHERMENT
                    | KeyUsage::KEY_AGREEMENT
                    | KeyUsage::KEY_CERT_SIGN,
                expected_bits: vec![
                    TAG_BITSTRING.tag_number as u8,
                    0x2,        // The length is 2 octets. 1 for the number of unused bits and 1 for the actual data.
                    0b00000010, // number of unused bits:2
                    0b10011100, // content with 2 padded zero
                ],
            },
            Test {
                input: KeyUsage::all(),
                expected_bits: vec![
                    TAG_BITSTRING.tag_number as u8,
                    0x3,        // The length is 3 octets. 1 for the number of unused bits and 2 for the actual data.
                    0b00000111, // number of unused bits:7
                    0b11111111,
                    0b10000000, // content with 7 padded zero
                ],
            },
            Test {
                input: KeyUsage::DECIPHER_ONLY,
                expected_bits: vec![
                    TAG_BITSTRING.tag_number as u8,
                    0x3,        // The length is 3 octets. 1 for the number of unused bits and 2 for the actual data.
                    0b00000111, // number of unused bits:7
                    0b00000000,
                    0b10000000, // content with 7 padded zero
                ],
            },
            Test {
                input: KeyUsage::CRL_SIGN | KeyUsage::ENCIPHER_ONLY,
                expected_bits: vec![
                    TAG_BITSTRING.tag_number as u8,
                    0x2,        // The length is 2 octets. 1 for the number of unused bits and 1 for the actual data.
                    0b00000000, // number of unused bits:0
                    0b00000011, // content with 0 padded zero
                ],
            },
        ];

        for t in tests {
            let der = t.input.to_der();
            assert_eq!(
                &der, &t.expected_bits,
                "{:?}, {:02x?} != {:02x?}",
                t.input, &der, &t.expected_bits
            );
            let echo = KeyUsage::from_der(&der).unwrap();
            assert_eq!(echo, t.input);
        }
    }

    const EXAMPLE_DER_WITH_ROLE: &[u8] = &[
        0x30, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x48, 0x31, 0x0E, 0x30, 0x0C, 0xA1, 0x0A, 0x88, 0x08, 0x2A, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09,
    ];

    #[test]
    fn subject_directory_attributes_decode_encode_with_role() {
        let example_role_oid = ObjectIdentifier::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let example_role = Role {
            role_authority: None,
            role_name: GeneralName::RegisteredID(example_role_oid),
        };
        let ret = SubjectDirectoryAttributes::from_der(EXAMPLE_DER_WITH_ROLE).expect("can decode");
        let attr = ret.0.first().expect("has one attribute");
        assert_eq!(&attr.oid, &*attributeTypeRole);
        assert_eq!(attr.value.first().unwrap().value, example_role.to_der());
        assert_eq!(ret.to_der(), EXAMPLE_DER_WITH_ROLE);
    }

    #[test]
    fn subject_directory_attributes_construct() {
        let mut attributes = vec![];
        let utf8_string = String::from("a utf8 string");
        attributes.push(Attribute {
            oid: ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1]),
            value: vec![DerSequence::from_der(
                &TaggedDerValue::from_tag_and_bytes(yasna::tags::TAG_UTF8STRING, utf8_string.clone().into_bytes())
                    .to_der(),
            )
            .unwrap()],
        });
        let example = SubjectDirectoryAttributes(attributes);
        let der = example.to_der();
        let example_decode = SubjectDirectoryAttributes::from_der(&der).expect("from der");
        assert_eq!(example_decode, example);
    }

    #[test]
    fn subject_directory_attributes_construct_with_role() {
        let mut attributes = vec![];
        let example_role_oid = ObjectIdentifier::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let example_role = Role {
            role_authority: None,
            role_name: GeneralName::RegisteredID(example_role_oid),
        };
        attributes.push(Attribute {
            oid: attributeTypeRole.clone(),
            value: vec![DerSequence::from_der(&example_role.to_der()).unwrap()],
        });
        let example = SubjectDirectoryAttributes(attributes);
        let der = example.to_der();
        assert_eq!(der, EXAMPLE_DER_WITH_ROLE);
        println!("{}", der.to_base64(STANDARD));
        let example_decode = SubjectDirectoryAttributes::from_der(&der).expect("from der");
        assert_eq!(example_decode, example);
    }

    /// A simple smoke test to ensure that we can encode CertificatePolicies
    /// struct mentioning the Fortanix Service and Key Attestation Certificate
    /// Policies, and decode the DER value to get back the same struct.
    #[test]
    fn encode_fortanix_policies_smoke_test() {
        for policy_identifier in [
            vec![1, 3, 6, 1, 4, 1, 49690, 6, 1, 3].into(),
            vec![1, 3, 6, 1, 4, 1, 49690, 6, 1, 2].into(),
        ] {
            let policies = CertificatePolicies(vec![PolicyInformation {
                policy_identifier,
                policy_qualifiers: None,
            }]);
            let der = policies.to_der();
            let decoded = CertificatePolicies::from_ber(&der).expect("DER should be valid");
            assert_eq!(policies, decoded);
        }
    }

    /// A simple smoke test to ensure that we can encode an anyPolicy policy with
    /// a policy qualifier, and decode the DER value to get back the same struct.
    #[test]
    fn encode_any_policy_smoke_test() {
        for internet_policy_qualifier in [
            InternetPolicyQualifier::CpsUri("https://example.com".to_string().into()), // not real
            InternetPolicyQualifier::UserNotice(UserNotice {
                notice_ref: Some(NoticeReference {
                    organization: DisplayText::Utf8String("Fake Corp".to_string()),
                    notice_numbers: vec![BigInt::from(1)],
                }),
                explicit_text: Some(DisplayText::Utf8String("Fake policy".to_string())),
            }),
        ] {
            let policy = PolicyInformation {
                policy_identifier: ANY_POLICY.clone(),
                policy_qualifiers: Some(vec![internet_policy_qualifier.clone().into()]),
            };
            let der = policy.to_der();
            let decoded = PolicyInformation::from_ber(&der).expect("DER should be valid");
            assert_eq!(policy, decoded);
            let decoded_internet_policy_qualifier: InternetPolicyQualifier = decoded
                .policy_qualifiers
                .unwrap()
                .first()
                .unwrap()
                .to_owned()
                .try_into()
                .unwrap();
            assert_eq!(internet_policy_qualifier, decoded_internet_policy_qualifier);
        }
    }

    #[test]
    fn encode_internet_policy_qualifiers_smoke_test() {
        for internet_policy_qualifier in [
            InternetPolicyQualifier::CpsUri("https://example.com".to_string().into()), // not real
            InternetPolicyQualifier::UserNotice(UserNotice {
                notice_ref: Some(NoticeReference {
                    organization: DisplayText::Utf8String("Fake Corp".to_string()),
                    notice_numbers: vec![BigInt::from(1)],
                }),
                explicit_text: Some(DisplayText::Utf8String("Fake policy".to_string())),
            }),
        ] {
            let policy = PolicyInformation {
                policy_identifier: internet_policy_qualifier.oid().clone(),
                policy_qualifiers: Some(vec![internet_policy_qualifier.clone().into()]),
            };
            let der = policy.to_der();
            let decoded = PolicyInformation::from_ber(&der).expect("DER should be valid");
            assert_eq!(policy, decoded);
            let decoded_internet_policy_qualifier: InternetPolicyQualifier = decoded
                .policy_qualifiers
                .unwrap()
                .first()
                .unwrap()
                .to_owned()
                .try_into()
                .unwrap();
            assert_eq!(internet_policy_qualifier, decoded_internet_policy_qualifier);
        }
    }

    /// Example [CertificatePolicies] extension extract from a `Fortanix DSM SaaS Key Attestation Authority` certificate:
    /// ```text
    /// Extension SEQUENCE (2 elem)
    /// extnID OBJECT IDENTIFIER 2.5.29.32 certificatePolicies (X.509 extension)
    /// extnValue OCTET STRING (17 byte) 300F300D060B2B0601040183841A060102
    ///   SEQUENCE (1 elem)
    ///     SEQUENCE (1 elem)
    ///       OBJECT IDENTIFIER 1.3.6.1.4.1.49690.6.1.2
    /// ```
    static EXAMPLE_CLUSTER_NODE_ENROLLMENT_POLICY_EXT: &[u8] = &[
        0x30, 0x18, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x11, 0x30, 0x0F, 0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01,
        0x83, 0x84, 0x1A, 0x06, 0x01, 0x02,
    ];

    #[test]
    fn decode_fortanix_policies_ext_test() {
        let ext = Extension::from_ber(EXAMPLE_CLUSTER_NODE_ENROLLMENT_POLICY_EXT).unwrap();
        let policies = CertificatePolicies::from_ber(&ext.value).expect("extension value should be valid");
        let expected_polices = CertificatePolicies(vec![PolicyInformation {
            policy_identifier: vec![1, 3, 6, 1, 4, 1, 49690, 6, 1, 2].into(),
            policy_qualifiers: None,
        }]);
        assert_eq!(expected_polices, policies);
        assert_eq!(ext, expected_polices.to_extension(false));
    }
}
