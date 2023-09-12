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

derive_sequence! {
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
    PkiMessage<'a> {
        header:      [_] UNTAGGED REQUIRED: PkiHeader<'a>,
        body:        [_] UNTAGGED REQUIRED: PkiBody,
        protection:  [0] EXPLICIT OPTIONAL: Option<PkiProtection>,
        extra_certs: [1] EXPLICIT OPTIONAL: Option<CmpCertificates>,
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

derive_sequence_of!{
    /// Represents: SEQUENCE SIZE (1..MAX) OF CMPCertificate
    CmpCertificate => CmpCertificates
}

derive_sequence! {
    /// The `ProtectedPart` type is defined in [RFC 4210 Section 5.1.3].
    ///
    /// ```text
    /// ProtectedPart ::= SEQUENCE {
    ///     header    PKIHeader,
    ///     body      PKIBody }
    /// ```
    ///
    /// [RFC 4210 Section 5.1.3]: https://www.rfc-editor.org/rfc/rfc4210#section-5.1.3
    ProtectedPart<'a> {
        header:      PkiHeader<'a>,
        body:        PkiBody,
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
