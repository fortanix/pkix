/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERReader, DERWriter, BERDecodable, Tag};
use num_integer::Integer;
use num_bigint::BigUint;
use std::borrow::Cow;
use bit_vec::BitVec;
use oid;
use FromDer;

use DerWrite;
use types::*;

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
    // version: v3
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

const TBS_CERTIFICATE_V3: u8 = 2;

impl<S: DerWrite + Integer, A: DerWrite + SignatureAlgorithm, K: DerWrite> DerWrite
    for TbsCertificate<S, A, K> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            writer.next().write_tagged(Tag::context(0), |w| TBS_CERTIFICATE_V3.write(w));
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
            let version = r.next().read_tagged(Tag::context(0), |r| r.read_u8())?;
            if version != TBS_CERTIFICATE_V3 {
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            }
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

            Ok(TbsCertificate { serial, sigalg, issuer, validity_notbefore, validity_notafter,
                                subject, spki, extensions })
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum GeneralName {
    // https://tools.ietf.org/html/rfc5280#section-4.2.1.6
    OtherName(ObjectIdentifier, TaggedDerValue),
    Rfc822Name(String),
    DnsName(String),
    DirectoryName(Name),
    UniformResourceIdentifier(String),
    IpAddress(Vec<u8>),
    RegisteredID(ObjectIdentifier),
}

impl GeneralName {
    fn get_other(reader: BERReader, tag_number: u64) -> ASN1Result<(ObjectIdentifier, TaggedDerValue)> {
        reader.read_tagged_implicit(Tag::context(tag_number), |r| {
            r.read_sequence(|r| {
                let oid = ObjectIdentifier::decode_ber(r.next())?;
                let value = r.next().read_tagged(Tag::context(0), |r| TaggedDerValue::decode_ber(r))?;
                Ok((oid, value))
            })
        })
    }

    fn get_string(reader: BERReader, tag_number: u64) -> ASN1Result<String> {
        reader.read_tagged_implicit(Tag::context(tag_number), |r| {
            String::from_utf8(r.read_bytes()?)
                .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))
        })
    }

    fn get_ip(reader: BERReader, tag_number: u64) -> ASN1Result<Vec<u8>> {
        reader.read_tagged_implicit(Tag::context(tag_number), |r| {
            r.read_bytes()
        })
    }

    fn get_oid(reader: BERReader, tag_number: u64) -> ASN1Result<ObjectIdentifier> {
        reader.read_tagged_implicit(Tag::context(tag_number), |r| {
            ObjectIdentifier::decode_ber(r)
        })
    }

    fn get_name(reader: BERReader, tag_number: u64) -> ASN1Result<Name> {
        let mut vals = Vec::<(ObjectIdentifier, TaggedDerValue)>::new();
        reader.read_tagged_implicit(Tag::context(tag_number), |r| {
            r.read_sequence_of(|r| {
                r.read_sequence_of(|r| {
                    r.read_set_of(|r| {
                        let val = r.read_sequence(|r| {
                            let oid = ObjectIdentifier::decode_ber(r.next())?;
                            let value = TaggedDerValue::decode_ber(r.next())?;
                            Ok((oid, value))
                        })?;
                        vals.push(val);
                        Ok(())
                    })
                })
            })
        })?;
        Ok(Name::from(vals))
    }

    fn get_all_general_names(reader: BERReader) -> ASN1Result<GeneralNames> {
        let mut names = Vec::<GeneralName>::new();
        reader.read_sequence_of(|seq_reader| {
            let tag_number = seq_reader.lookahead_tag()?.tag_number;
            let name = match tag_number {
                0 => {
                    let (oid, tdv) = Self::get_other(seq_reader, tag_number)?;
                    GeneralName::OtherName(oid, tdv)
                },
                1 => GeneralName::Rfc822Name(Self::get_string(seq_reader, tag_number)?),
                2 => GeneralName::DnsName(Self::get_string(seq_reader, tag_number)?),
                4 => GeneralName::DirectoryName(Self::get_name(seq_reader, tag_number)?),
                6 => GeneralName::UniformResourceIdentifier(Self::get_string(seq_reader, tag_number)?),
                7 => GeneralName::IpAddress(Self::get_ip(seq_reader, tag_number)?),
                8 => GeneralName::RegisteredID(Self::get_oid(seq_reader, tag_number)?),
                _ => return Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
            };
            names.push(name);
            Ok(())
        })?;
        Ok(GeneralNames { names })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct GeneralNames {
    pub names: Vec<GeneralName>,
}

impl<'a> HasOid for GeneralNames {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for GeneralNames {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for name in &self.names {
                match name {
                    GeneralName::OtherName(oid, tdv) =>
                        writer.next().write_tagged_implicit(Tag::context(0), |w| w.write_sequence(|ws| {
                            oid.write(ws.next());
                            ws.next().write_tagged(Tag::context(0), |w| tdv.write(w));
                        })),
                    GeneralName::Rfc822Name(s) =>
                        writer.next().write_tagged_implicit(Tag::context(1), |w| s.as_bytes().write(w)),
                    GeneralName::DnsName(s) =>
                        writer.next().write_tagged_implicit(Tag::context(2), |w| s.as_bytes().write(w)),
                    GeneralName::DirectoryName(n) =>
                        writer.next().write_tagged_implicit(Tag::context(4), |w| w.write_sequence(|ws| n.write(ws.next()))),
                    GeneralName::UniformResourceIdentifier(s) =>
                        writer.next().write_tagged_implicit(Tag::context(6), |w| s.as_bytes().write(w)),
                    GeneralName::IpAddress(a) =>
                        writer.next().write_tagged_implicit(Tag::context(7), |w| a.write(w)),
                    GeneralName::RegisteredID(oid) =>
                        writer.next().write_tagged_implicit(Tag::context(8), |w| oid.write(w)),
                }
            }
        });
    }
}

impl BERDecodable for GeneralNames {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(GeneralName::get_all_general_names(reader)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherNameAltNames {
    pub names: Vec<(ObjectIdentifier, TaggedDerValue)>,
}

impl<'a> HasOid for OtherNameAltNames {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for OtherNameAltNames {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for (oid, tdv) in &self.names {
                writer.next().write_tagged_implicit(Tag::context(0), |w|
                    w.write_sequence(|ws| {
                        oid.write(ws.next());
                        ws.next().write_tagged(Tag::context(0), |w| tdv.write(w));
                    }),
                )
            }
        });
    }
}

impl BERDecodable for OtherNameAltNames {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let names = GeneralName::get_all_general_names(reader)?
            .names
            .into_iter()
            .filter_map(|s| match s {
                GeneralName::OtherName(oid, tdv) => Some((oid, tdv)),
                _ => None,
            }).collect();
        Ok(OtherNameAltNames { names })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Rfc822NameAltNames<'a> {
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> HasOid for Rfc822NameAltNames<'a> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for Rfc822NameAltNames<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for name in &self.names {
                writer.next().write_tagged_implicit(Tag::context(1), |w|
                    name.as_bytes().write(w),
                )
            }
        });
    }
}

impl BERDecodable for Rfc822NameAltNames<'static> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let names = GeneralName::get_all_general_names(reader)?
            .names
            .into_iter()
            .filter_map(|s| match s {
                GeneralName::Rfc822Name(name) => Some(Cow::Owned(name)),
                _ => None,
            }).collect();
        Ok(Rfc822NameAltNames { names })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DnsAltNames<'a> {
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> HasOid for DnsAltNames<'a> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for DnsAltNames<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for name in &self.names {
                writer.next().write_tagged_implicit(Tag::context(2), |w|
                    name.as_bytes().write(w),
                )
            }
        });
    }
}

impl BERDecodable for DnsAltNames<'static> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let names = GeneralName::get_all_general_names(reader)?
            .names
            .into_iter()
            .filter_map(|s| match s {
                GeneralName::DnsName(name) => Some(Cow::Owned(name)),
                _ => None,
            }).collect();
        Ok(DnsAltNames { names })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DirectoryAltNames {
    pub names: Vec<Name>,
}

impl<'a> HasOid for DirectoryAltNames {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for DirectoryAltNames {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for name in &self.names {
                writer.next().write_tagged_implicit(Tag::context(4), |w|
                    w.write_sequence(|ws| name.write(ws.next())),
                )
            }
        });
    }
}

impl BERDecodable for DirectoryAltNames {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let names = GeneralName::get_all_general_names(reader)?
            .names
            .into_iter()
            .filter_map(|s| match s {
                GeneralName::DirectoryName(name) => Some(name),
                _ => None,
            }).collect();
        Ok(DirectoryAltNames { names })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct URIAltNames<'a> {
    pub names: Vec<Cow<'a, str>>,
}

impl<'a> HasOid for URIAltNames<'a> {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for URIAltNames<'a> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for name in &self.names {
                writer.next().write_tagged_implicit(Tag::context(6), |w|
                    name.as_bytes().write(w),
                )
            }
        });
    }
}

impl BERDecodable for URIAltNames<'static> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let names = GeneralName::get_all_general_names(reader)?
            .names
            .into_iter()
            .filter_map(|s| match s {
                GeneralName::UniformResourceIdentifier(name) => Some(Cow::Owned(name)),
                _ => None,
            }).collect();
        Ok(URIAltNames { names })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IpAddressAltNames {
    pub addresses: Vec<Vec<u8>>,
}

impl<'a> HasOid for IpAddressAltNames {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for IpAddressAltNames {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for address in &self.addresses {
                writer.next().write_tagged_implicit(Tag::context(7), |w|
                    address.write(w),
                )
            }
        });
    }
}

impl BERDecodable for IpAddressAltNames {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let addresses = GeneralName::get_all_general_names(reader)?
            .names
            .into_iter()
            .filter_map(|s| match s {
                GeneralName::IpAddress(ip) => Some(ip),
                _ => None,
            }).collect();
        Ok(IpAddressAltNames { addresses })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RIDAltNames {
    pub names: Vec<ObjectIdentifier>,
}

impl<'a> HasOid for RIDAltNames {
    fn oid() -> &'static ObjectIdentifier {
        &oid::subjectAltName
    }
}

impl<'a> DerWrite for RIDAltNames {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            for name in &self.names {
                writer.next().write_tagged_implicit(Tag::context(8), |w|
                    name.write(w),
                )
            }
        });
    }
}

impl BERDecodable for RIDAltNames {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let names = GeneralName::get_all_general_names(reader)?
            .names
            .into_iter()
            .filter_map(|s| match s {
                GeneralName::RegisteredID(oid) => Some(oid),
                _ => None,
            }).collect();
        Ok(RIDAltNames { names })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RequestedExtensions {
    pub extensions: Vec<Extension>,
}

impl HasOid for RequestedExtensions {
    fn oid() -> &'static ObjectIdentifier {
        &oid::extensionRequest
    }
}

impl DerWrite for RequestedExtensions {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|w| {
            for i in &self.extensions {
                i.write(w.next())
            }
        })
    }
}

impl BERDecodable for RequestedExtensions {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
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

            Ok(RequestedExtensions { extensions })
        })
    }
}

impl RequestedExtensions {
    pub fn get_singular_attribute<T: FromDer + HasOid>(&self) -> Option<T> {
        let oid = T::oid();

        let mut iter = self.extensions.iter().filter(|a| a.oid == *oid);

        // We reject CSRs where the same attribute (same OID) appears multiple times. Note that
        // this is different from the case where the attribute (OID) appears once and has
        // multiple values, that is handled by the second level of iteration below.
        match (iter.next(), iter.next()) {
            (Some(attr), None) => {
                T::from_der(&attr.value).ok()
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct IssuerAltName {
    pub names: Vec<DirectoryName>
}

impl DerWrite for IssuerAltName {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|w| {
            for dir_name in &self.names {
                dir_name.write(w.next())
            }
        })
    }
}

impl BERDecodable for IssuerAltName {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(Self { names: reader.collect_sequence_of(|r| DirectoryName::decode_ber(r))? })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct DirectoryName {
    pub name: Name,
}

impl DerWrite for DirectoryName {
    fn write(&self, writer: DERWriter) {
        writer.write_tagged(Tag::context(4), |w| self.name.write(w))
    }
}

impl BERDecodable for DirectoryName {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let name = reader.read_tagged(Tag::context(4), |r| {
            Name::decode_ber(r)
        })?;
        Ok(DirectoryName{ name })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serialize::{DerWrite, ToDer};
    use yasna;
    use yasna::{tags::{TAG_PRINTABLESTRING, TAG_UTF8STRING}};
    use std::str::FromStr;

    #[test]
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

        assert_eq!(&*yasna::construct_der(|w|names.write(w)), der);

        assert_eq!(yasna::parse_der(der, |r| DnsAltNames::decode_ber(r)).unwrap(), names);
    }

    #[test]
    fn various_alt_names() {
        let der = &[0x30, 0x82, 0x02, 0x37, 0xa0, 0x1e, 0x06, 0x03,
            0x2a, 0x03, 0x04, 0xa0, 0x17, 0x0c, 0x15, 0x73, 0x6f, 0x6d, 0x65,
            0x20, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x69, 0x64, 0x65, 0x6e,
            0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0xa0, 0x26, 0x06, 0x08, 0x2b,
            0x06, 0x01, 0x05, 0x05, 0x07, 0x08, 0x09, 0xa0, 0x1a, 0x0c, 0x18,
            0x6e, 0x6f, 0x6e, 0x61, 0x73, 0x63, 0x69, 0x69, 0x6e, 0x61, 0x6d,
            0x65, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
            0x6f, 0x6d, 0x81, 0x13, 0x73, 0x61, 0x76, 0x76, 0x61, 0x73, 0x40,
            0x66, 0x6f, 0x72, 0x74, 0x61, 0x6e, 0x69, 0x78, 0x2e, 0x63, 0x6f,
            0x6d, 0x81, 0x11, 0x68, 0x65, 0x6c, 0x70, 0x40, 0x66, 0x6f, 0x72,
            0x74, 0x61, 0x6e, 0x69, 0x78, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0f,
            0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0f, 0x66, 0x74, 0x70,
            0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
            0x6d, 0xa4, 0x39, 0x30, 0x37, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03,
            0x55, 0x04, 0x03, 0x0c, 0x0c, 0x46, 0x6f, 0x72, 0x74, 0x61, 0x6e,
            0x69, 0x78, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x0b, 0x30, 0x09, 0x06,
            0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30,
            0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x46, 0x6f, 0x72,
            0x74, 0x61, 0x6e, 0x69, 0x78, 0xa4, 0x4d, 0x30, 0x4b, 0x31, 0x0b,
            0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x4b,
            0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0f,
            0x4d, 0x79, 0x20, 0x4f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
            0x74, 0x69, 0x6f, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
            0x04, 0x0b, 0x0c, 0x07, 0x4d, 0x79, 0x20, 0x55, 0x6e, 0x69, 0x74,
            0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07,
            0x4d, 0x79, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x86, 0x48, 0x68, 0x74,
            0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a,
            0x31, 0x32, 0x33, 0x2f, 0x66, 0x6f, 0x72, 0x75, 0x6d, 0x2f, 0x71,
            0x75, 0x65, 0x73, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x3f, 0x74,
            0x61, 0x67, 0x3d, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x69,
            0x6e, 0x67, 0x26, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x3d, 0x6e, 0x65,
            0x77, 0x65, 0x73, 0x74, 0x86, 0x29, 0x6c, 0x64, 0x61, 0x70, 0x3a,
            0x2f, 0x2f, 0x5b, 0x32, 0x30, 0x30, 0x31, 0x3a, 0x64, 0x62, 0x38,
            0x3a, 0x3a, 0x37, 0x5d, 0x2f, 0x63, 0x3d, 0x47, 0x42, 0x3f, 0x6f,
            0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3f,
            0x6f, 0x6e, 0x65, 0x86, 0x1b, 0x6d, 0x61, 0x69, 0x6c, 0x74, 0x6f,
            0x3a, 0x4a, 0x6f, 0x68, 0x6e, 0x2e, 0x44, 0x6f, 0x65, 0x40, 0x65,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x86,
            0x17, 0x74, 0x65, 0x6c, 0x6e, 0x65, 0x74, 0x3a, 0x2f, 0x2f, 0x31,
            0x39, 0x32, 0x2e, 0x30, 0x2e, 0x32, 0x2e, 0x31, 0x36, 0x3a, 0x38,
            0x30, 0x2f, 0x87, 0x04, 0x7f, 0x00, 0x00, 0x01, 0x87, 0x04, 0x01,
            0x02, 0x03, 0x04, 0x87, 0x04, 0x01, 0x02, 0x03, 0x04, 0x87, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x87, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x87, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x87, 0x10, 0x88, 0x88,
            0x99, 0x99, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee,
            0xee, 0xff, 0xff, 0x88, 0x03, 0x29, 0x01, 0x01, 0x88, 0x03, 0x2a,
            0x03, 0x04, 0x88, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
            0x01, 0x0d
        ];

        assert_eq!(der, &yasna::parse_der(der, |r| GeneralNames::decode_ber(r)).unwrap().to_der()[..]);

        let other_names = OtherNameAltNames {
            names: vec![
                (ObjectIdentifier::from_str("1.2.3.4").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"some other identifier".to_vec())),
                (ObjectIdentifier::from_str("1.3.6.1.5.5.7.8.9").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"nonasciiname.example.com".to_vec())),
            ]
        };
        assert_eq!(yasna::parse_der(der, |r| OtherNameAltNames::decode_ber(r)).unwrap(), other_names);

        let rfc822_names = Rfc822NameAltNames {
            names: vec![
                Cow::Borrowed("savvas@fortanix.com"),
                Cow::Borrowed("help@fortanix.com"),
            ]
        };
        assert_eq!(yasna::parse_der(der, |r| Rfc822NameAltNames::decode_ber(r)).unwrap(), rfc822_names);

        let dns_names = DnsAltNames {
            names: vec![
                Cow::Borrowed("www.example.com"),
                Cow::Borrowed("example.com"),
                Cow::Borrowed("ftp.example.com"),
            ]
        };
        assert_eq!(yasna::parse_der(der, |r| DnsAltNames::decode_ber(r)).unwrap(), dns_names);

        let dir_names = DirectoryAltNames {
            names: vec![
                Name::from(vec![
                    (ObjectIdentifier::from_str("2.5.4.3").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Fortanix Inc".to_vec())),
                    (ObjectIdentifier::from_str("2.5.4.6").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_PRINTABLESTRING, b"US".to_vec())),
                    (ObjectIdentifier::from_str("2.5.4.10").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"Fortanix".to_vec())),
                ]),
                Name::from(vec![
                    (ObjectIdentifier::from_str("2.5.4.6").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_PRINTABLESTRING, b"UK".to_vec())),
                    (ObjectIdentifier::from_str("2.5.4.10").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"My Organization".to_vec())),
                    (ObjectIdentifier::from_str("2.5.4.11").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"My Unit".to_vec())),
                    (ObjectIdentifier::from_str("2.5.4.3").unwrap(), TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, b"My Name".to_vec())),
                ]),
            ]
        };
        assert_eq!(yasna::parse_der(der, |r| DirectoryAltNames::decode_ber(r)).unwrap(), dir_names);

        let uri_names = URIAltNames {
            names: vec![
                // fragment removed: https://www.example.com:123/forum/questions/?tag=networking&order=newest#top
                Cow::Borrowed("https://www.example.com:123/forum/questions/?tag=networking&order=newest"),
                Cow::Borrowed("ldap://[2001:db8::7]/c=GB?objectClass?one"),
                Cow::Borrowed("mailto:John.Doe@example.com"),
                Cow::Borrowed("telnet://192.0.2.16:80/"),
            ]
        };
        assert_eq!(yasna::parse_der(der, |r| URIAltNames::decode_ber(r)).unwrap(), uri_names);

        let ip_addresses = IpAddressAltNames {
            addresses: vec![
                vec![127, 0, 0, 1],
                vec![1, 2, 3, 4],
                vec![1, 2, 3, 4],
                vec![0, 0, 0, 0],
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                vec![136, 136, 153, 153, 170, 170, 187, 187, 204, 204, 221, 221, 238, 238, 255, 255],
            ]
        };
        assert_eq!(yasna::parse_der(der, |r| IpAddressAltNames::decode_ber(r)).unwrap(), ip_addresses);

        let rid_names = RIDAltNames {
            names: vec![
                ObjectIdentifier::from_str("1.1.1.1").unwrap(),
                ObjectIdentifier::from_str("1.2.3.4").unwrap(),
                ObjectIdentifier::from_str("1.2.840.113549.1.1.13").unwrap(),
            ]
        };
        assert_eq!(yasna::parse_der(der, |r| RIDAltNames::decode_ber(r)).unwrap(), rid_names);
    }
}
