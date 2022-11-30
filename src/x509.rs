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
impl BERDecodable for DnsAltNames<'static> {
    fn decode_ber<'a, 'b>(reader: BERReader<'a, 'b>) -> ASN1Result<Self> {
        reader.read_sequence(|seq_reader| {
            let mut names = Vec::<Cow<'static, str>>::new();

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

#[cfg(test)]
mod tests {
    use super::*;
    use test::test_encode_decode;

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
}
