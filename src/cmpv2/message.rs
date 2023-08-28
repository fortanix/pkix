/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! PKIMessage type

use bit_vec::BitVec;
use yasna::{ASN1Result, BERDecodable, BERReader, DERWriter, Tag};

use crate::{x509::GenericCertificate, DerWrite};

use super::{body::PkiBody, header::PkiHeader};

/// The `PKIMessage` type is defined in [RFC 4210 Section 5.1].
///
/// ```text
/// PKIMessage ::= SEQUENCE {
///     header           PKIHeader,
///     body             PKIBody,
///     protection   [0] PKIProtection OPTIONAL,
///     extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
///     OPTIONAL }
/// ```
///
/// [RFC 4210 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkiMessage<'a> {
    pub header: PkiHeader<'a>,
    pub body: PkiBody,
    pub protection: Option<PkiProtection>,
    pub extra_certs: Option<CmpCertificates>,
}

impl PkiMessage<'_> {
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_PROTECTION: u64 = 0;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_EXTRA_CERTS: u64 = 1;
}

impl DerWrite for PkiMessage<'_> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.header.write(writer.next());
            self.body.write(writer.next());
            if let Some(protection) = self.protection.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_PROTECTION), |writer| protection.write(writer))
            };
            if let Some(extra_certs) = self.extra_certs.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_EXTRA_CERTS), |writer| extra_certs.write(writer))
            };
        })
    }
}

impl BERDecodable for PkiMessage<'_> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let header = <PkiHeader as BERDecodable>::decode_ber(reader.next())?;
            let body = <PkiBody as BERDecodable>::decode_ber(reader.next())?;
            let protection: Option<PkiProtection> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_PROTECTION), |reader| {
                    <PkiProtection as BERDecodable>::decode_ber(reader)
                })
            })?;
            let extra_certs: Option<CmpCertificates> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_EXTRA_CERTS), |reader| {
                    <CmpCertificates as BERDecodable>::decode_ber(reader)
                })
            })?;
            Ok(PkiMessage {
                header,
                body,
                protection,
                extra_certs,
            })
        })
    }
}

/// The `PKIProtection` type is defined in [RFC 4210 Section 5.1.3].
///
/// ```text
///  PKIProtection ::= BIT STRING
/// ```
///
/// [RFC 4210 Section 5.1.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3
pub type PkiProtection = BitVec;

/// The `CMPCertificate` type is defined in [RFC 4210 Appendix F]
///
/// ```text
///  CMPCertificate ::= CHOICE { x509v3PKCert Certificate, ... }
/// ```
///
/// [RFC 4210 Appendix F]: https://www.rfc-editor.org/rfc/rfc4210#appendix-F
pub type CmpCertificate = GenericCertificate;

/// Represents: SEQUENCE SIZE (1..MAX) OF CMPCertificate
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CmpCertificates(pub Vec<CmpCertificate>);

impl DerWrite for CmpCertificates {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence_of(|w| {
            for cert in &self.0 {
                cert.write(w.next())
            }
        })
    }
}

impl BERDecodable for CmpCertificates {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(CmpCertificates(reader.collect_sequence_of(CmpCertificate::decode_ber)?))
    }
}

/// The `ProtectedPart` type is defined in [RFC 4210 Section 5.1.3].
///
/// ```text
/// ProtectedPart ::= SEQUENCE {
///     header    PKIHeader,
///     body      PKIBody }
/// ```
///
/// [RFC 4210 Section 5.1.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProtectedPart<'a> {
    pub header: PkiHeader<'a>,
    pub body: PkiBody,
}

impl DerWrite for ProtectedPart<'_> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|w| {
            self.header.write(w.next());
            self.body.write(w.next());
        });
    }
}

impl BERDecodable for ProtectedPart<'_> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|r| {
            let header = PkiHeader::decode_ber(r.next())?;
            let body = PkiBody::decode_ber(r.next())?;
            Ok(ProtectedPart { header, body })
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{FromDer, ToDer};
    use b64_ct::{FromBase64, ToBase64, STANDARD};

    use super::*;

    #[test]
    fn test_ftx_pki_msg_decode_encode() {
        let pki_msg_base64 = include_str!("../../tests/data/ftx_test_pki_msg.b64");
        check_pki_msg_decode_encode(pki_msg_base64);
    }

    /// Test encode/decode PKIMessage generated from openssl.
    /// Test data is generated from following command using openssl version 3.X:
    /// ```bash
    /// openssl genrsa 2048 > subjectkey.pem
    /// openssl req -x509 -days 3650 -new -newkey rsa:2048 -keyout senderkey.pem -subj /CN=sender -out sendercert.pem -nodes
    /// openssl cmp -cmd cr -reqout cr.der -newkey subjectkey.pem -subject "/CN=subject" -certout /dev/null -rspin /dev/null -recipient "/CN=recipient" -key senderkey.pem -cert sendercert.pem -extracerts sendercert.pem
    /// base64 < cr.der
    /// ```
    #[test]
    fn test_openssl_pki_msg_decode_encode() {
        let pki_msg_base64 = include_str!("../../tests/data/openssl_pki_msg.b64");
        check_pki_msg_decode_encode(pki_msg_base64);
    }

    fn check_pki_msg_decode_encode(pki_msg_base64: &str) {
        let pki_msg_data = pki_msg_base64.trim().from_base64().expect("base64 decode test pki msg");
        // decode from source
        let pki_msg = PkiMessage::from_der(&pki_msg_data).expect("DER decode test pki msg");
        // re-encode
        let pki_msg_back_to_der = pki_msg.to_der();
        // re-encoded DER should be equal to source
        assert!(
            pki_msg_data == pki_msg_back_to_der,
            "{}",
            pki_msg_back_to_der.to_base64(STANDARD)
        );
        // re-decoded object should be equal to previous decoded object
        let pki_msg2 = PkiMessage::from_der(&pki_msg_back_to_der).expect("DER decode re-encoded pki msg");
        assert_eq!(pki_msg, pki_msg2);
    }
}
