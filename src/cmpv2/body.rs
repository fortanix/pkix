/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! PKIBody type

use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERDecodable, BERReader, DERWriter, Tag};

use crate::{crmf::request::CertReqMessages, types::DerAnyOwned, DerWrite};

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
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum PkiBody {
    /// Initialization Request
    Ir(CertReqMessages),
    /// Initialization Response
    Ip(CertRepMessage),
    /// Certification Request
    Cr(CertReqMessages),
    /// Certification Response
    Cp(CertRepMessage),
    /// imported from [PKCS10](https://datatracker.ietf.org/doc/html/rfc2986)
    P10cr(CertReq),
    /// pop Challenge
    Popdecc(PopoDecKeyChallContent),
    /// pop Response
    Popdecr(PopoDecKeyRespContent),
    /// Key Update Request
    KUr(CertReqMessages),
    /// Key Update Response
    Kup(CertRepMessage),
    /// Key Recovery Request
    Krr(CertReqMessages),
    /// Key Recovery Response
    Krp(KeyRecRepContent),
    /// Revocation Request
    Rr(RevReqContent),
    /// Revocation Response
    Rp(RevRepContent),
    /// Cross-Cert. Request
    Ccr(CertReqMessages),
    /// Cross-Cert. Response
    Ccp(CertRepMessage),
    /// CA Key Update Ann.
    Ckuann(CaKeyUpdAnnContent),
    /// Certificate Ann.
    Cann(CertAnnContent),
    /// Revocation Ann.
    Rann(RevAnnContent),
    /// CRL Announcement
    CrlAnn(CrlAnnContent),
    /// Confirmation
    PkiConf(PkiConfirmContent),
    /// Nested Message
    Nested(NestedMessageContent),
    /// General Message
    GenM(GenMsgContent),
    /// General Response
    GenP(GenRepContent),
    /// Error Message
    Error(ErrorMsgContent),
    /// Certificate confirm
    CertConf(CertConfirmContent),
    /// Polling request
    PollReq(PollReqContent),
    /// Polling response
    PollRep(PollRepContent),
}

impl PkiBody {
    /// EXPLICIT TAG (rfc4210#appendix-F) for Initialization Request
    const TAG_IR: u64 = 0;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Initialization Response
    const TAG_IP: u64 = 1;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Certification Request
    const TAG_CR: u64 = 2;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Certification Response
    const TAG_CP: u64 = 3;
    /// EXPLICIT TAG (rfc4210#appendix-F) for imported from [PKCS10]
    const TAG_P10_CR: u64 = 4;
    /// EXPLICIT TAG (rfc4210#appendix-F) for pop Challenge
    const TAG_POP_DE_CC: u64 = 5;
    /// EXPLICIT TAG (rfc4210#appendix-F) for pop Response
    const TAG_POP_DE_CR: u64 = 6;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Key Update Request
    const TAG_KUR: u64 = 7;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Key Update Response
    const TAG_KUP: u64 = 8;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Key Recovery Request
    const TAG_KRR: u64 = 9;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Key Recovery Response
    const TAG_KRP: u64 = 10;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Revocation Request
    const TAG_RR: u64 = 11;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Revocation Response
    const TAG_RP: u64 = 12;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Cross-Cert. Request
    const TAG_CCR: u64 = 13;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Cross-Cert. Response
    const TAG_CCP: u64 = 14;
    /// EXPLICIT TAG (rfc4210#appendix-F) for CA Key Update Ann.
    const TAG_CKU_ANN: u64 = 15;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Certificate Ann.
    const TAG_C_ANN: u64 = 16;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Revocation Ann.
    const TAG_R_ANN: u64 = 17;
    /// EXPLICIT TAG (rfc4210#appendix-F) for CRL Announcement
    const TAG_CRL_ANN: u64 = 18;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Confirmation
    const TAG_PKI_CONF: u64 = 19;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Nested Message
    const TAG_NESTED: u64 = 20;
    /// EXPLICIT TAG (rfc4210#appendix-F) for General Message
    const TAG_GEN_M: u64 = 21;
    /// EXPLICIT TAG (rfc4210#appendix-F) for General Response
    const TAG_GEN_P: u64 = 22;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Error Message
    const TAG_ERROR: u64 = 23;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Certificate confirm
    const TAG_CERT_CONF: u64 = 24;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Polling request
    const TAG_POLL_REQ: u64 = 25;
    /// EXPLICIT TAG (rfc4210#appendix-F) for Polling response
    const TAG_POLL_REP: u64 = 26;

    fn tag(&self) -> Tag {
        match self {
            PkiBody::Ir(_) => Tag::context(Self::TAG_IR),
            PkiBody::Ip(_) => Tag::context(Self::TAG_IP),
            PkiBody::Cr(_) => Tag::context(Self::TAG_CR),
            PkiBody::Cp(_) => Tag::context(Self::TAG_CP),
            PkiBody::P10cr(_) => Tag::context(Self::TAG_P10_CR),
            PkiBody::Popdecc(_) => Tag::context(Self::TAG_POP_DE_CC),
            PkiBody::Popdecr(_) => Tag::context(Self::TAG_POP_DE_CR),
            PkiBody::KUr(_) => Tag::context(Self::TAG_KUR),
            PkiBody::Kup(_) => Tag::context(Self::TAG_KUP),
            PkiBody::Krr(_) => Tag::context(Self::TAG_KRR),
            PkiBody::Krp(_) => Tag::context(Self::TAG_KRP),
            PkiBody::Rr(_) => Tag::context(Self::TAG_RR),
            PkiBody::Rp(_) => Tag::context(Self::TAG_RP),
            PkiBody::Ccr(_) => Tag::context(Self::TAG_CCR),
            PkiBody::Ccp(_) => Tag::context(Self::TAG_CCP),
            PkiBody::Ckuann(_) => Tag::context(Self::TAG_CKU_ANN),
            PkiBody::Cann(_) => Tag::context(Self::TAG_C_ANN),
            PkiBody::Rann(_) => Tag::context(Self::TAG_R_ANN),
            PkiBody::CrlAnn(_) => Tag::context(Self::TAG_CRL_ANN),
            PkiBody::PkiConf(_) => Tag::context(Self::TAG_PKI_CONF),
            PkiBody::Nested(_) => Tag::context(Self::TAG_NESTED),
            PkiBody::GenM(_) => Tag::context(Self::TAG_GEN_M),
            PkiBody::GenP(_) => Tag::context(Self::TAG_GEN_P),
            PkiBody::Error(_) => Tag::context(Self::TAG_ERROR),
            PkiBody::CertConf(_) => Tag::context(Self::TAG_CERT_CONF),
            PkiBody::PollReq(_) => Tag::context(Self::TAG_POLL_REQ),
            PkiBody::PollRep(_) => Tag::context(Self::TAG_POLL_REP),
        }
    }
}

impl DerWrite for PkiBody {
    #[rustfmt::skip]
    fn write(&self, writer: DERWriter) {
        match self {
            PkiBody::Ir(body)       => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Ip(body)       => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Cr(body)       => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Cp(body)       => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::P10cr(body)    => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Popdecc(body)  => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Popdecr(body)  => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::KUr(body)      => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Kup(body)      => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Krr(body)      => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Krp(body)      => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Rr(body)       => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Rp(body)       => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Ccr(body)      => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Ccp(body)      => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Ckuann(body)   => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Cann(body)     => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Rann(body)     => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::CrlAnn(body)   => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::PkiConf(body)  => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Nested(body)   => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::GenM(body)     => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::GenP(body)     => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::Error(body)    => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::CertConf(body) => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::PollReq(body)  => writer.write_tagged(self.tag(), |w| body.write(w)),
            PkiBody::PollRep(body)  => writer.write_tagged(self.tag(), |w| body.write(w)),
        }
    }
}

impl BERDecodable for PkiBody {
    #[rustfmt::skip]
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let tag_number = reader.lookahead_tag()?.tag_number;
        match tag_number {
            Self::TAG_IR =>        reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Ir(CertReqMessages::decode_ber(r)?))),
            Self::TAG_IP =>        reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Ip(CertRepMessage::decode_ber(r)?))),
            Self::TAG_CR =>        reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Cr(CertReqMessages::decode_ber(r)?))),
            Self::TAG_CP =>        reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Cp(CertRepMessage::decode_ber(r)?))),
            Self::TAG_P10_CR =>    reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::P10cr(CertReq::decode_ber(r)?))),
            Self::TAG_POP_DE_CC => reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Popdecc(PopoDecKeyChallContent::decode_ber(r)?))),
            Self::TAG_POP_DE_CR => reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Popdecr(PopoDecKeyRespContent::decode_ber(r)?))),
            Self::TAG_KUR =>       reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::KUr(CertReqMessages::decode_ber(r)?))),
            Self::TAG_KUP =>       reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Kup(CertRepMessage::decode_ber(r)?))),
            Self::TAG_KRR =>       reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Krr(CertReqMessages::decode_ber(r)?))),
            Self::TAG_KRP =>       reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Krp(KeyRecRepContent::decode_ber(r)?))),
            Self::TAG_RR =>        reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Rr(RevReqContent::decode_ber(r)?))),
            Self::TAG_RP =>        reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Rp(RevRepContent::decode_ber(r)?))),
            Self::TAG_CCR =>       reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Ccr(CertReqMessages::decode_ber(r)?))),
            Self::TAG_CCP =>       reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Ccp(CertRepMessage::decode_ber(r)?))),
            Self::TAG_CKU_ANN =>   reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Ckuann(CaKeyUpdAnnContent::decode_ber(r)?))),
            Self::TAG_C_ANN =>     reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Cann(CertAnnContent::decode_ber(r)?))),
            Self::TAG_R_ANN =>     reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Rann(RevAnnContent::decode_ber(r)?))),
            Self::TAG_CRL_ANN =>   reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::CrlAnn(CrlAnnContent::decode_ber(r)?))),
            Self::TAG_PKI_CONF =>  reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::PkiConf(PkiConfirmContent::decode_ber(r)?))),
            Self::TAG_NESTED =>    reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Nested(NestedMessageContent::decode_ber(r)?))),
            Self::TAG_GEN_M =>     reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::GenM(GenMsgContent::decode_ber(r)?))),
            Self::TAG_GEN_P =>     reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::GenP(GenRepContent::decode_ber(r)?))),
            Self::TAG_ERROR =>     reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::Error(ErrorMsgContent::decode_ber(r)?))),
            Self::TAG_CERT_CONF => reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::CertConf(CertConfirmContent::decode_ber(r)?))),
            Self::TAG_POLL_REQ =>  reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::PollReq(PollReqContent::decode_ber(r)?))),
            Self::TAG_POLL_REP =>  reader.read_tagged(Tag::context(tag_number), |r| Ok(PkiBody::PollRep(PollRepContent::decode_ber(r)?))),
            _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        }
    }
}

/// TODO: not yet implemented, tracking issue: #23
type CertRepMessage = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type CertReq = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type PopoDecKeyChallContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type PopoDecKeyRespContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type KeyRecRepContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type RevReqContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type RevRepContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type CaKeyUpdAnnContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type CertAnnContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type RevAnnContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type CrlAnnContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type PkiConfirmContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type NestedMessageContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type GenMsgContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type GenRepContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type ErrorMsgContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type CertConfirmContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type PollReqContent = DerAnyOwned;
/// TODO: not yet implemented, tracking issue: #23
type PollRepContent = DerAnyOwned;
