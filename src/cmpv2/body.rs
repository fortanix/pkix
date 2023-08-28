/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! PKIBody type

use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERDecodable, BERReader, DERWriter, Tag};

use crate::{crmf::request::CertReqMessages, DerWrite};

/// The `PKIBody` type is defined in [RFC 4210 Section 5.1.2]
///
/// ```text
/// PKIBody ::= CHOICE {       -- message-specific body elements
///     ir       [0]  CertReqMessages,        --Initialization Request
///     ip       [1]  CertRepMessage,         --Initialization Response
///     cr       [2]  CertReqMessages,        --Certification Request
///     cp       [3]  CertRepMessage,         --Certification Response
///     p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
///     popdecc  [5]  POPODecKeyChallContent, --pop Challenge
///     popdecr  [6]  POPODecKeyRespContent,  --pop Response
///     kur      [7]  CertReqMessages,        --Key Update Request
///     kup      [8]  CertRepMessage,         --Key Update Response
///     krr      [9]  CertReqMessages,        --Key Recovery Request
///     krp      [10] KeyRecRepContent,       --Key Recovery Response
///     rr       [11] RevReqContent,          --Revocation Request
///     rp       [12] RevRepContent,          --Revocation Response
///     ccr      [13] CertReqMessages,        --Cross-Cert. Request
///     ccp      [14] CertRepMessage,         --Cross-Cert. Response
///     ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
///     cann     [16] CertAnnContent,         --Certificate Ann.
///     rann     [17] RevAnnContent,          --Revocation Ann.
///     crlann   [18] CRLAnnContent,          --CRL Announcement
///     pkiconf  [19] PKIConfirmContent,      --Confirmation
///     nested   [20] NestedMessageContent,   --Nested Message
///     genm     [21] GenMsgContent,          --General Message
///     genp     [22] GenRepContent,          --General Response
///     error    [23] ErrorMsgContent,        --Error Message
///     certConf [24] CertConfirmContent,     --Certificate confirm
///     pollReq  [25] PollReqContent,         --Polling request
///     pollRep  [26] PollRepContent          --Polling response
/// }
/// ```
///
/// [RFC 4210 Section 5.1.2]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.2
// TODO: fields not needed now are not implemented yet
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PkiBody {
    Ir(CertReqMessages),
    // TODO: Ip(CertRepMessage<'a>),
    Cr(CertReqMessages),
    // TODO: Cp(CertRepMessage<'a>),
    // TODO: P10cr(CertReq),
    // TODO: Popdecc(PopoDecKeyChallContent),
    // TODO: Popdecr(PopoDecKeyRespContent<'a>),
    // TODO: KUr(CertReqMessages),
    // TODO: Kup(CertRepMessage<'a>),
    // TODO: Krr(CertReqMessages),
    // TODO: Krp(KeyRecRepContent<'a>),
    // TODO: Rr(RevReqContent),
    // TODO: Rp(RevRepContent<'a>),
    // TODO: Ccr(CertReqMessages),
    // TODO: Ccp(CertRepMessage<'a>),
    // TODO: Ckuann(CaKeyUpdAnnContent),
    // TODO: Cann(CertAnnContent),
    // TODO: Rann(RevAnnContent),
    // TODO: CrlAnn(CrlAnnContent),
    // TODO: PkiConf(PkiConfirmContent),
    // TODO: GenM(GenMsgContent),
    // TODO: GenP(GenRepContent),
    // TODO: Error(ErrorMsgContent<'a>),
    // TODO: CertConf(CertConfirmContent<'a>),
    // TODO: PollReq(PollRepContent<'a>),
    // TODO: PollRep(PollRepContent<'a>),
}

impl PkiBody {
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_IR: u64 = 0;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_CR: u64 = 2;
}

impl DerWrite for PkiBody {
    fn write(&self, writer: DERWriter) {
        match self {
            PkiBody::Ir(cert_req_msgs) => writer.write_tagged(Tag::context(Self::TAG_IR), |w| cert_req_msgs.write(w)),
            PkiBody::Cr(cert_req_msgs) => writer.write_tagged(Tag::context(Self::TAG_CR), |w| cert_req_msgs.write(w)),
        }
    }
}

impl BERDecodable for PkiBody {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let tag_number = reader.lookahead_tag()?.tag_number;
        match tag_number {
            Self::TAG_IR => reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Ir(CertReqMessages::decode_ber(r)?))),
            Self::TAG_CR => reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Cr(CertReqMessages::decode_ber(r)?))),
            _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        }
    }
}
