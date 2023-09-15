/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, DERWriter, BERDecodable, PCBit, Tag};
use yasna::tags::*;
pub use yasna::models::{ObjectIdentifier, ParseOidError, TaggedDerValue};
use std::borrow::Cow;
use std::str;
use std::fmt;
use std::ops::{Deref, DerefMut};
use chrono::{self, Utc, Datelike, Timelike, TimeZone};
use {DerWrite, FromDer, oid};
use crate::serialize::WriteIa5StringSafe;

/// Maximum length as a `u32` (256 MiB).
const MAX_U32: u32 = 0xfff_ffff;

pub trait HasOid {
    fn oid() -> &'static ObjectIdentifier;
}

pub trait SignatureAlgorithm {}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RsaPkcs15<H>(pub H);

impl<H> SignatureAlgorithm for RsaPkcs15<H> {}

impl<'a> SignatureAlgorithm for DerSequence<'a> {}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Sha256;

/// sha256WithRSAEncryption
impl DerWrite for RsaPkcs15<Sha256> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&oid::sha256WithRSAEncryption);
            writer.next().write_null();
        })
    }
}

impl BERDecodable for RsaPkcs15<Sha256> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let oid = ObjectIdentifier::decode_ber(seq_reader.next())?;
            seq_reader.next().read_null()?;
            if oid == *oid::sha256WithRSAEncryption {
                Ok(RsaPkcs15(Sha256))
            } else {
                Err(ASN1Error::new(ASN1ErrorKind::Invalid))
            }
        })
    }
}

pub struct EcdsaX962<H>(pub H);

impl<H> SignatureAlgorithm for EcdsaX962<H> {}

/// ecdsaWithSHA256
impl DerWrite for EcdsaX962<Sha256> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            writer.next().write_oid(&oid::ecdsaWithSHA256);
        })
    }
}

impl BERDecodable for EcdsaX962<Sha256> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let oid = ObjectIdentifier::decode_ber(seq_reader.next())?;
            if oid == *oid::ecdsaWithSHA256 {
                Ok(EcdsaX962(Sha256))
            } else {
                Err(ASN1Error::new(ASN1ErrorKind::Invalid))
            }
        })
    }
}

/// The GeneralName type, as defined in [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280#appendix-A.2).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum GeneralName<'a> {
    OtherName(ObjectIdentifier, TaggedDerValue),
    Rfc822Name(Cow<'a, str>),
    DnsName(Cow<'a, str>),
    // x400Address is not supported
    DirectoryName(Name),
    // ediPartyName is not supported
    UniformResourceIdentifier(Cow<'a, str>),
    IpAddress(Vec<u8>),
    RegisteredID(ObjectIdentifier),
}

impl<'a> GeneralName<'a> {
    const TAG_OTHER_NAME: u64 = 0;
    const TAG_RFC822_NAME: u64 = 1;
    const TAG_DNS_NAME: u64 = 2;
    const TAG_DIRECTORY_NAME: u64 = 4;
    const TAG_UNIFORM_RESOURCE_IDENTIFIER: u64 = 6;
    const TAG_IP_ADDRESS: u64 = 7;
    const TAG_REGISTERED_ID: u64 = 8;

    pub fn is_other_name(&self) -> bool {
        match *self {
            GeneralName::OtherName(..) => true,
            _ => false,
        }
    }

    pub fn as_other_name(&self) -> Option<(&ObjectIdentifier, &TaggedDerValue)> {
        match self {
            GeneralName::OtherName(oid, tdv) => Some((oid, tdv)),
            _ => None,
        }
    }

    pub fn into_other_name(self) -> Option<(ObjectIdentifier, TaggedDerValue)> {
        match self {
            GeneralName::OtherName(oid, tdv) => Some((oid, tdv)),
            _ => None,
        }
    }

    pub fn is_rfc822_name(&self) -> bool {
        match *self {
            GeneralName::Rfc822Name(..) => true,
            _ => false,
        }
    }

    pub fn as_rfc822_name(&self) -> Option<&Cow<'a, str>> {
        match self {
            GeneralName::Rfc822Name(name) => Some(name),
            _ => None,
        }
    }

    pub fn into_rfc822_name(self) -> Option<Cow<'a, str>> {
        match self {
            GeneralName::Rfc822Name(name) => Some(name),
            _ => None,
        }
    }

    pub fn is_dns_name(&self) -> bool {
        match *self {
            GeneralName::DnsName(..) => true,
            _ => false,
        }
    }

    pub fn as_dns_name(&self) -> Option<&Cow<'a, str>> {
        match self {
            GeneralName::DnsName(name) => Some(name),
            _ => None,
        }
    }

    pub fn into_dns_name(self) -> Option<Cow<'a, str>> {
        match self {
            GeneralName::DnsName(name) => Some(name),
            _ => None,
        }
    }

    pub fn is_directory_name(&self) -> bool {
        match *self {
            GeneralName::DirectoryName(..) => true,
            _ => false,
        }
    }

    pub fn as_directory_name(&self) -> Option<&Name> {
        match self {
            GeneralName::DirectoryName(name) => Some(name),
            _ => None,
        }
    }

    pub fn into_directory_name(self) -> Option<Name> {
        match self {
            GeneralName::DirectoryName(name) => Some(name),
            _ => None,
        }
    }

    pub fn is_uniform_resource_identifier(&self) -> bool {
        match *self {
            GeneralName::UniformResourceIdentifier(..) => true,
            _ => false,
        }
    }

    pub fn as_uniform_resource_identifier(&self) -> Option<&Cow<'a, str>> {
        match self {
            GeneralName::UniformResourceIdentifier(name) => Some(name),
            _ => None,
        }
    }

    pub fn into_uniform_resource_identifier(self) -> Option<Cow<'a, str>> {
        match self {
            GeneralName::UniformResourceIdentifier(name) => Some(name),
            _ => None,
        }
    }

    pub fn is_ip_address(&self) -> bool {
        match *self {
            GeneralName::IpAddress(..) => true,
            _ => false,
        }
    }

    pub fn as_ip_address(&self) -> Option<&Vec<u8>> {
        match self {
            GeneralName::IpAddress(ip) => Some(ip),
            _ => None,
        }
    }

    pub fn into_ip_address(self) -> Option<Vec<u8>> {
        match self {
            GeneralName::IpAddress(ip) => Some(ip),
            _ => None,
        }
    }

    pub fn is_registered_id(&self) -> bool {
        match *self {
            GeneralName::RegisteredID(..) => true,
            _ => false,
        }
    }

    pub fn as_registered_id(&self) -> Option<&ObjectIdentifier> {
        match self {
            GeneralName::RegisteredID(oid) => Some(oid),
            _ => None,
        }
    }

    pub fn into_registered_id(self) -> Option<ObjectIdentifier> {
        match self {
            GeneralName::RegisteredID(oid) => Some(oid),
            _ => None,
        }
    }
}

impl<'a> DerWrite for GeneralName<'a> {
    fn write(&self, writer: DERWriter) {
        match self {
            GeneralName::OtherName(oid, tdv) =>
                writer.write_tagged_implicit(
                    Tag::context(Self::TAG_OTHER_NAME),
                    |w| w.write_sequence(|w| {
                        oid.write(w.next());
                        w.next().write_tagged(Tag::context(0), |w| tdv.write(w));
                    })),
            GeneralName::Rfc822Name(s) =>
                writer.write_tagged_implicit(
                    Tag::context(Self::TAG_RFC822_NAME),
                    |w| w.write_ia5_string_safe(&s)
                ),
            GeneralName::DnsName(s) =>
                writer.write_tagged_implicit(
                    Tag::context(Self::TAG_DNS_NAME),
                    |w| w.write_ia5_string_safe(&s)
                ),
            GeneralName::DirectoryName(n) =>
                // explicit tagging because Name is an untagged CHOICE (X.680-0207 clause 30.6.c)
                writer.write_tagged(
                    Tag::context(Self::TAG_DIRECTORY_NAME),
                    |w| n.write(w)
                ),
            GeneralName::UniformResourceIdentifier(s) =>
                writer.write_tagged_implicit(
                    Tag::context(Self::TAG_UNIFORM_RESOURCE_IDENTIFIER),
                    |w| w.write_ia5_string_safe(&s)
                ),
            GeneralName::IpAddress(a) =>
                writer.write_tagged_implicit(
                    Tag::context(Self::TAG_IP_ADDRESS),
                    |w| a.write(w)
                ),
            GeneralName::RegisteredID(oid) =>
                writer.write_tagged_implicit(
                    Tag::context(Self::TAG_REGISTERED_ID),
                    |w| oid.write(w)
                ),
        }
    }
}

impl<'a> BERDecodable for GeneralName<'a> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let tag_number = reader.lookahead_tag()?.tag_number;
        if tag_number == Self::TAG_DIRECTORY_NAME {
            // explicit tagging because Name is an untagged CHOICE (X.680-0207 clause 30.6.c)
            reader.read_tagged(Tag::context(tag_number), |r| {
                Ok(GeneralName::DirectoryName(Name::decode_ber(r)?))
            })
        } else {
            reader.read_tagged_implicit(Tag::context(tag_number), |r| {
                match tag_number {
                    Self::TAG_OTHER_NAME => {
                        r.read_sequence(|r| {
                            let oid = ObjectIdentifier::decode_ber(r.next())?;
                            let value = r.next().read_tagged(Tag::context(0), |r| TaggedDerValue::decode_ber(r))?;
                            Ok(GeneralName::OtherName(oid, value))
                        })
                    },
                    Self::TAG_RFC822_NAME => Ok(GeneralName::Rfc822Name(r.read_ia5_string()?.into())),
                    Self::TAG_DNS_NAME => Ok(GeneralName::DnsName(r.read_ia5_string()?.into())),
                    Self::TAG_UNIFORM_RESOURCE_IDENTIFIER => Ok(GeneralName::UniformResourceIdentifier(r.read_ia5_string()?.into())),
                    Self::TAG_IP_ADDRESS => Ok(GeneralName::IpAddress(r.read_bytes()?)),
                    Self::TAG_REGISTERED_ID => Ok(GeneralName::RegisteredID(ObjectIdentifier::decode_ber(r)?)),
                    _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
                }
            })
        }
    }
}


/// GeneralNames as defined in [RFC 5280 Section 4.2.1.6].
///
/// ```text
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct GeneralNames<'a>(pub Vec<GeneralName<'a>>);

impl<'a> DerWrite for GeneralNames<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence_of(|w| {
            for general_name in &self.0 {
                general_name.write(w.next())
            }
        })
    }
}

impl<'a> BERDecodable for GeneralNames<'a> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(GeneralNames(reader.collect_sequence_of(GeneralName::decode_ber)?))
    }
}

impl<'a> Deref for GeneralNames<'a> {
    type Target = Vec<GeneralName<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> DerefMut for GeneralNames<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> From<Vec<GeneralName<'a>>> for GeneralNames<'a> {
    fn from(names: Vec<GeneralName<'a>>) -> GeneralNames<'a> {
        GeneralNames(names)
    }
}

impl<'a> From<GeneralNames<'a>> for Vec<GeneralName<'a>> {
    fn from(general_names: GeneralNames<'a>) -> Vec<GeneralName<'a>> {
        general_names.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Name {
    // The actual ASN.1 type is Vec<HashSet<(ObjectIdentifier, TaggedDerValue)>>.
    // However, having more than one element in the set is extremely uncommon.
    //
    // On deserialization, we flatten the structure. This results in
    // technically non-compliant equality testing (RFC 5280, §7.1). On
    // serialization, we always put each `AttributeTypeAndValue` in its own
    // set.
    //
    // Additional discussion in https://github.com/zmap/zlint/issues/220
    pub value: Vec<(ObjectIdentifier, TaggedDerValue)>,
}

impl Name {
    pub fn get(&self, oid: &ObjectIdentifier) -> Option<&TaggedDerValue> {
        self.value.iter().find(|v| v.0 == *oid).map(|v| &v.1)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i,v) in self.value.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }

            // print key (oid)
            if let Some(o) = oid::OID_TO_NAME.get(&v.0) {
                write!(f, "{}", o)?;
            } else {
                for (j,c) in v.0.components().iter().enumerate() {
                    if j > 0 {
                        write!(f, ".")?;
                    }
                    write!(f, "{}", c)?;
                }
            }
            write!(f, "=")?;

            // print value
            match (v.1.pcbit(), v.1.tag()) {
                (PCBit::Primitive, TAG_NUMERICSTRING) | (PCBit::Primitive, TAG_PRINTABLESTRING) | (PCBit::Primitive, TAG_IA5STRING) | (PCBit::Primitive, TAG_UTF8STRING) =>
                    write!(f, "{}", String::from_utf8_lossy(&v.1.value()))?,
                _ => for &byte in v.1.value() {
                    write!(f, "{:x}", byte)?;
                },
            }
        }
        Ok(())
    }
}

impl From<Vec<(ObjectIdentifier, TaggedDerValue)>> for Name {
    fn from(b: Vec<(ObjectIdentifier, TaggedDerValue)>) -> Name {
        Name { value: b }
    }
}

impl DerWrite for Name {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for &(ref oid, ref value) in &self.value {
                writer.next().write_set(|writer| {
                    writer.next().write_sequence(|writer| {
                        oid.write(writer.next());
                        value.write(writer.next());
                    });
                });
            }
        });
    }
}

impl BERDecodable for Name {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let mut vals = Vec::<(ObjectIdentifier, TaggedDerValue)>::new();

            loop {
                let res = seq_reader.read_optional(|r| {
                    r.read_set_of(|r| {
                        let val = r.read_sequence(|r| {
                            let oid = ObjectIdentifier::decode_ber(r.next())?;
                            let value = TaggedDerValue::decode_ber(r.next())?;
                            Ok((oid, value))
                        })?;
                        vals.push(val);
                        Ok(())
                    })
                });
                match res {
                    Ok(Some(())) => {},
                    Ok(None) => break,
                    Err(e) => return Err(e),
                }
            }

            Ok(Name { value: vals })
        })
    }
}

#[derive(Debug, Clone)]
pub enum NameComponent {
    Str(String),
    Bytes(Vec<u8>)
}

impl NameComponent {
    pub fn bytes(&self) -> Option<&[u8]> {
        match *self {
            NameComponent::Bytes(ref v) => Some(&v),
            _ => None,
        }
    }
}

impl From<String> for NameComponent {
    fn from(s: String) -> NameComponent {
        NameComponent::Str(s)
    }
}

impl From<Vec<u8>> for NameComponent {
    fn from(b: Vec<u8>) -> NameComponent {
        NameComponent::Bytes(b)
    }
}

impl From<NameComponent> for TaggedDerValue {
    fn from(nc: NameComponent) -> TaggedDerValue {
        match nc {
            NameComponent::Str(str) => TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, str.into_bytes()),
            NameComponent::Bytes(mut val) => {
                // mbedTLS does not support OCTET STRING in any name component. It does
                // support BIT STRING, however, so we always use that. The first byte of
                // a bit string is the number of unused bits. Since we start from a Vec<u8>,
                // we always have a multiple of 8 bits and hence no bits are unused.
                val.insert(0, 0);
                TaggedDerValue::from_tag_and_bytes(TAG_BITSTRING, val)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Extensions(pub Vec<Extension>);

impl DerWrite for Extensions {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence_of(|w| {
            for extension in &self.0 {
                extension.write(w.next());
            }
        });
    }
}

impl BERDecodable for Extensions {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(Extensions(reader.collect_sequence_of(Extension::decode_ber)?))
    }
}

impl Deref for Extensions {
    type Target = Vec<Extension>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Extensions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<Extension>> for Extensions {
    fn from(extensions: Vec<Extension>) -> Extensions {
        Extensions(extensions)
    }
}

impl From<Extensions> for Vec<Extension> {
    fn from(extensions: Extensions) -> Vec<Extension> {
        extensions.0
    }
}

impl Extensions {
    pub fn get_extension<T: FromDer + HasOid>(&self) -> Option<T> {
        let oid = T::oid();

        // We reject extensions that appear multiple times.
        let mut iter = self.0.iter().filter(|a| a.oid == *oid);
        match (iter.next(), iter.next()) {
            (Some(attr), None) => T::from_der(&attr.value).ok(),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Extension {
    pub oid: ObjectIdentifier,
    pub critical: bool,
    pub value: Vec<u8>,
}

impl DerWrite for Extension {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.oid.write(writer.next());
            if self.critical {
                true.write(writer.next());
            }
            self.value.write(writer.next());
        });
    }
}

impl BERDecodable for Extension {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let oid = ObjectIdentifier::decode_ber(seq_reader.next())?;
            let critical = seq_reader.read_default(false, |r| bool::decode_ber(r))?;
            let value = seq_reader.next().read_bytes()?;
            Ok(Extension { oid, critical, value })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Attribute<'a> {
    pub oid: ObjectIdentifier,
    pub value: Vec<DerSequence<'a>>,
}

impl<'a> DerWrite for Attribute<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.oid.write(writer.next());
            writer.next().write_set(|writer| {
                for value in &self.value {
                    value.write(writer.next());
                }
            });
        });
    }
}

impl<'a> BERDecodable for Attribute<'a> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let oid = ObjectIdentifier::decode_ber(seq_reader.next())?;

            let mut value = Vec::new();
            seq_reader.next().read_set_of(|r| {
                value.push(DerSequence::decode_ber(r)?);
                Ok(())
            })?;

            Ok(Attribute { oid, value })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DateTime(chrono::DateTime<Utc>);

impl From<chrono::DateTime<Utc>> for DateTime {
    fn from(datetime: chrono::DateTime<Utc>) -> Self {
        DateTime(datetime)
    }
}

impl Into<chrono::DateTime<Utc>> for DateTime {
    fn into(self) -> chrono::DateTime<Utc> {
        self.0
    }
}

impl DateTime {
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<Self> {
        Utc.with_ymd_and_hms(year.into(), month.into(), day.into(), hour.into(), minute.into(), second.into())
            .earliest()
            .map(Self)
    }

    pub fn from_seconds_since_epoch(seconds: i64) -> Option<Self> {
        Utc.timestamp_opt(seconds, 0)
            .earliest()
            .map(Self)
    }

    pub fn to_seconds_since_epoch(&self) -> i64 {
        self.0.timestamp()
    }
}

impl DerWrite for DateTime {
    fn write(&self, writer: DERWriter) {
        let offset = match self.0.year() {
            1950..=1999 => 1900,
            2000..=2049 => 2000,
            _ => 0,
        };
        if offset != 0 {
            let t = format!("{:02}{:02}{:02}{:02}{:02}{:02}Z",
                            self.0.year() - offset,
                            self.0.month(),
                            self.0.day(),
                            self.0.hour(),
                            self.0.minute(),
                            self.0.second());
            writer.write_tagged_implicit(TAG_UTCTIME, |w| t.as_bytes().write(w));
        } else {
            let t = format!("{:04}{:02}{:02}{:02}{:02}{:02}Z",
                            self.0.year(),
                            self.0.month(),
                            self.0.day(),
                            self.0.hour(),
                            self.0.minute(),
                            self.0.second());
            writer.write_tagged_implicit(TAG_GENERALIZEDTIME, |w| t.as_bytes().write(w));
        }
    }
}

impl BERDecodable for DateTime {
    /// This code only accepts dates including seconds and in UTC "Z" time zone.
    /// These restrictions are imposed by RFC5280.
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        let tv = reader.read_tagged_der()?;
        let tag = tv.tag();
        let value = tv.value();
        let (year, rest, tz) = match tag {
            TAG_UTCTIME => {
                let (date, tz) = value.split_at(12);
                let (year, rest) = date.split_at(2);

                let year = str::from_utf8(&year).ok().and_then(|s| u16::from_str_radix(s, 10).ok())
                    .ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
                let year = if year < 50 { 2000 + year } else { 1900 + year };

                (year, rest, tz)
            }
            TAG_GENERALIZEDTIME => {
                let (date, tz) = value.split_at(14);
                let (year, rest) = date.split_at(4);

                let year = str::from_utf8(&year).ok().and_then(|s| u16::from_str_radix(s, 10).ok())
                    .ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;

                (year, rest, tz)
            }
            _ => return Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        };

        if tz != b"Z" {
            return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
        }

        let mut iter = rest.chunks(2).filter_map(|v| {
            str::from_utf8(&v).ok().and_then(|s| u8::from_str_radix(s, 10).ok())
        });

        let month = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let day = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let hour = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let minute = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let second = iter.next().ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))?;

        DateTime::new(year, month, day, hour, minute, second)
            .ok_or(ASN1Error::new(ASN1ErrorKind::Invalid))
    }
}

pub type DerAnyOwned = DerSequence<'static>;
pub type DerAny<'a> = DerSequence<'a>;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DerSequence<'a> {
    pub value: Cow<'a, [u8]>,
}

impl<'a> DerWrite for DerSequence<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_der(&self.value)
    }
}

impl<'a> From<&'a [u8]> for DerSequence<'a> {
    fn from(b: &'a [u8]) -> DerSequence<'a> {
        DerSequence { value: Cow::Borrowed(b) }
    }
}

impl From<Vec<u8>> for DerSequence<'static> {
    fn from(b: Vec<u8>) -> DerSequence<'static> {
        DerSequence { value: Cow::Owned(b) }
    }
}

impl<'a> AsRef<[u8]> for DerSequence<'a> {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl<'a> BERDecodable for DerSequence<'a> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(reader.read_der()?.into())
    }
}

/// A wrapper to ensure DateTime is always encoded as GeneralizedTime
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GeneralizedTime(pub DateTime);

impl DerWrite for GeneralizedTime {
    fn write(&self, writer: DERWriter) {
        let chrono_time: chrono::DateTime<chrono::offset::Utc> = self.0.clone().into();
        let t = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            chrono_time.year(),
            chrono_time.month(),
            chrono_time.day(),
            chrono_time.hour(),
            chrono_time.minute(),
            chrono_time.second()
        );
        writer.write_tagged_implicit(TAG_GENERALIZEDTIME, |w| t.as_bytes().write(w));
    }
}

impl BERDecodable for GeneralizedTime {
    /// This code only accepts dates including seconds and in UTC "Z" time zone.
    /// These restrictions are imposed by RFC5280.
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(GeneralizedTime(DateTime::decode_ber(reader)?))
    }
}

/// ASN.1 `OCTET STRING` type: owned form..
///
/// Octet strings represent contiguous sequences of octets, a.k.a. bytes.
///
/// This type provides the same functionality as [`OctetStringRef`] but owns
/// the backing data.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct OctetString {
    /// Bitstring represented as a slice of bytes.
    inner: Vec<u8>,
}

impl OctetString {
    /// Maximum length currently supported: 256 MiB
    pub const MAX: u32 = MAX_U32;

    /// Create a new ASN.1 `OCTET STRING`.
    pub fn new(bytes: impl Into<Vec<u8>>) -> ASN1Result<Self> {
        let inner: Vec<u8> = bytes.into();
        if inner.len() > Self::MAX as usize {
            Err(ASN1Error::new(ASN1ErrorKind::IntegerOverflow))
        } else {
            Ok(Self { inner })
        }
    }

    /// Borrow the inner byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Take ownership of the octet string.
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner
    }

    /// Get the length of the inner byte slice.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Is the inner byte slice empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl DerWrite for OctetString {
    fn write(&self, writer: DERWriter) {
        writer.write_bytes(&self.inner);
    }
}

impl BERDecodable for OctetString {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        OctetString::new(reader.read_bytes()?)
    }
}

impl AsRef<[u8]> for OctetString {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::test_encode_decode;
    use yasna;
    use yasna::tags::TAG_UTF8STRING;

    #[test]
    fn name() {
        let name = Name {
            value: vec![
                (oid::commonName.clone(),
                 TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test name".to_vec())),
                (oid::description.clone(),
                 TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test description".to_vec())),
            ]
        };

        let der = vec![0x30, 0x2f, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09,
                       0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x31, 0x19, 0x30, 0x17,
                       0x06, 0x03, 0x55, 0x04, 0x0d, 0x0c, 0x10, 0x54, 0x65, 0x73, 0x74, 0x20, 0x64,
                       0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e];
        test_encode_decode(&name, &der);
    }

    #[test]
    fn name_format() {
        let name = Name {
            value: vec![
                (oid::commonName.clone(),
                 TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test name".to_vec())),
                (ObjectIdentifier::new(vec![1,2,3,4]),
                 TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Custom DN".to_vec())),
                (ObjectIdentifier::new(vec![2, 5, 4, 34]),
                 TaggedDerValue::from_tag_and_bytes(TAG_NUMERICSTRING, b"23".to_vec())),
            ]
        };

        assert_eq!(format!("{}", name), "CN=Test name, 1.2.3.4=Custom DN, seeAlso=23");
    }

    #[test]
    fn name_multi_value_rdn() {
        let ber = b"0\x82\x01\xca1\x82\x01]0\x1c\x06\x03U\x04\x0b\x13\x15opc-certtype:instance0r\x06\x03U\x04\x0b\x13kopc-instance:ocid1.instance.oc1.eu-frankfurt-1.abtheljrfsguhltfu6r2y6gwhthevlmgl2ijdl4ozpm34ejr6vgalufakjzq0f\x06\x03U\x04\x0b\x13_opc-compartment:ocid1.tenancy.oc1..aaaaaaaafruudnficveu7ajrk346ilmbdwjzumqe6zn7uoap77awgnpnjoea0a\x06\x03U\x04\x0b\x13Zopc-tenant:ocid1.tenancy.oc1..aaaaaaaafruudnficveu7ajrk346ilmbdwjzumqe6zn7uoap77awgnpnjoea1g0e\x06\x03U\x04\x03\x13^ocid1.instance.oc1.eu-frankfurt-1.abtheljrfsguhltfu6r2y6gwhthevlmgl2ijdl4ozpm34ejr6vgalufakjzq";

        let parsed = yasna::parse_ber(&ber[..], |r| Name::decode_ber(r)).unwrap();
        assert_eq!(parsed.value.len(), 5);
    }

    #[test]
    fn extensions() {
        let extensions = Extensions(vec![
            Extension {
                oid: oid::basicConstraints.clone(),
                critical: true,
                value: vec![0x30, 0x00],
            },
            Extension {
                oid: oid::keyUsage.clone(),
                critical: true,
                value: vec![0x03, 0x03, 0x07, 0x80, 0x00],
            },
        ]);

        let der = &[
            0x30, 0x1f, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d,
            0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
            0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
            0x01, 0xff, 0x04, 0x05, 0x03, 0x03, 0x07, 0x80,
            0x00];

        test_encode_decode(&extensions, der);
    }

    #[test]
    fn general_name_other_name() {
        let general_name = GeneralName::OtherName(
            ObjectIdentifier::new(vec![1,2,3,4]),
            TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test name".to_vec())
        );

        let der = &[
            0xa0, 0x12, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa0,
            0x0b, 0x0c, 0x09, 0x54, 0x65, 0x73, 0x74, 0x20,
            0x6e, 0x61, 0x6d, 0x65];

        test_encode_decode(&general_name, der);
    }

    #[test]
    fn general_name_rfc822_name() {
        let general_name = GeneralName::Rfc822Name("Test name".into());
        let der = &[
            0x81, 0x09, 0x54, 0x65, 0x73, 0x74, 0x20, 0x6e,
            0x61, 0x6d, 0x65];

        test_encode_decode(&general_name, der);
    }

    #[test]
    fn general_name_dns_name() {
        let general_name = GeneralName::DnsName("Test name".into());
        let der = &[
            0x82, 0x09, 0x54, 0x65, 0x73, 0x74, 0x20, 0x6e,
            0x61, 0x6d, 0x65];

        test_encode_decode(&general_name, der);
    }

    #[test]
    fn general_name_directory_name() {
        let general_name = GeneralName::DirectoryName(
            Name {
                value: vec![
                    (oid::commonName.clone(),
                     TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test name".to_vec())),
                    (oid::description.clone(),
                     TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Test description".to_vec())),
                ]
            }
        );

        let der = &[
            0xa4, 0x31, 0x30, 0x2f, 0x31, 0x12, 0x30, 0x10,
            0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x09, 0x54,
            0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65,
            0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04,
            0x0d, 0x0c, 0x10, 0x54, 0x65, 0x73, 0x74, 0x20,
            0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
            0x69, 0x6f, 0x6e];

        test_encode_decode(&general_name, der);
    }

    #[test]
    fn general_name_uniform_resource_identifier() {
        let general_name = GeneralName::UniformResourceIdentifier("Test name".into());
        let der = &[
            0x86, 0x09, 0x54, 0x65, 0x73, 0x74, 0x20, 0x6e,
            0x61, 0x6d, 0x65];

        test_encode_decode(&general_name, der);
    }

    #[test]
    fn general_name_ip_address() {
        let general_name = GeneralName::IpAddress(vec![127,0,0,1]);
        let der = &[0x87, 0x04, 0x7f, 0x00, 0x00, 0x01];
        test_encode_decode(&general_name, der);
    }

    #[test]
    fn general_name_registered_id() {
        let general_name = GeneralName::RegisteredID(ObjectIdentifier::new(vec![1,2,3,4]));
        let der = &[0x88, 0x03, 0x2a, 0x03, 0x04];
        test_encode_decode(&general_name, der);
    }

    #[test]
    fn general_names() {
        let general_names = GeneralNames(vec![
            GeneralName::IpAddress(vec![127,0,0,1]),
            GeneralName::RegisteredID(ObjectIdentifier::new(vec![1,2,3,4]))
        ]);

        let der = &[
            0x30, 0x0b, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01,
            0x88, 0x03, 0x2a, 0x03, 0x04];

        test_encode_decode(&general_names, der);
    }

    #[test]
    fn attribute() {
        let attr = Attribute {
            oid: oid::extensionRequest.clone(),
            value: vec![
                b"\x04\x06Hello!".to_vec().into(),
                b"\x04\x06Hello!".to_vec().into(),
            ],
        };

        let der = vec![0x30, 0x1d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
                       0x31, 0x10, 0x04, 0x06, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x04, 0x06, 0x48,
                       0x65, 0x6c, 0x6c, 0x6f, 0x21];

        test_encode_decode(&attr, &der);
    }

    #[test]
    fn datetime() {
        let datetime = DateTime::new(2017, 5, 19, 12, 34, 56).unwrap();

        let der = vec![0x17, 0x0d, 0x31, 0x37, 0x30, 0x35, 0x31, 0x39, 0x31, 0x32, 0x33, 0x34,
                       0x35, 0x36, 0x5a];

        test_encode_decode(&datetime, &der);
    }
}
