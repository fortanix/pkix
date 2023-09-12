/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! PKIHeader type

use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERDecodable, BERReader, DERWriter, Tag};

use crate::{
    types::{DerSequence, GeneralName, GeneralizedTime, OctetString, SignatureAlgorithm},
    DerWrite,
};

use super::gen::GeneralInfo;

/// The `PKIHeader` type is defined in [RFC 4210 Section 5.1.1].
///
/// ```text
///     PKIHeader ::= SEQUENCE {
///     pvno                INTEGER     { cmp1999(1), cmp2000(2) },
///     sender              GeneralName,
///     -- identifies the sender
///     recipient           GeneralName,
///     -- identifies the intended recipient
///     messageTime     [0] GeneralizedTime         OPTIONAL,
///     -- time of production of this message (used when sender
///     -- believes that the transport will be "suitable"; i.e.,
///     -- that the time will still be meaningful upon receipt)
///     protectionAlg   [1] AlgorithmIdentifier{ALGORITHM, {...}}
///     OPTIONAL,
///     -- algorithm used for calculation of protection bits
///     senderKID       [2] KeyIdentifier           OPTIONAL,
///     recipKID        [3] KeyIdentifier           OPTIONAL,
///     -- to identify specific keys used for protection
///     transactionID   [4] OCTET STRING            OPTIONAL,
///     -- identifies the transaction; i.e., this will be the same in
///     -- corresponding request, response, certConf, and PKIConf
///     -- messages
///     senderNonce     [5] OCTET STRING            OPTIONAL,
///     recipNonce      [6] OCTET STRING            OPTIONAL,
///     -- nonces used to provide replay protection, senderNonce
///     -- is inserted by the creator of this message; recipNonce
///     -- is a nonce previously inserted in a related message by
///     -- the intended recipient of this message
///     freeText        [7] PKIFreeText             OPTIONAL,
///     -- this may be used to indicate context-specific instructions
///     -- (this field is intended for human consumption)
///     generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
///     InfoTypeAndValue     OPTIONAL
///     -- this may be used to convey context-specific information
///     -- (this field not primarily intended for human consumption)
///     }
/// ```
///
/// [RFC 4210 Section 5.1.1]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.1
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkiHeader<'a, A: SignatureAlgorithm = DerSequence<'static>> {
    pub pvno: Pvno,
    pub sender: GeneralName<'a>,
    pub recipient: GeneralName<'a>,
    pub message_time: Option<GeneralizedTime>,
    pub protection_alg: Option<A>,
    pub sender_kid: Option<OctetString>,
    pub recip_kid: Option<OctetString>,
    pub trans_id: Option<OctetString>,
    pub sender_nonce: Option<OctetString>,
    pub recip_nonce: Option<OctetString>,
    pub free_text: Option<PkiFreeText>,
    pub general_info: Option<GeneralInfo>,
}

impl<A: SignatureAlgorithm> PkiHeader<'_, A> {
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_MESSAGE_TIME: u64 = 0;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_PROTECTION_ALG: u64 = 1;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_SENDER_KID: u64 = 2;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_RECIP_KID: u64 = 3;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_TRANS_ID: u64 = 4;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_SENDER_NONCE: u64 = 5;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_RECIP_NONCE: u64 = 6;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_FREE_TEXT: u64 = 7;
    /// EXPLICIT TAG (rfc4210#appendix-F)
    const TAG_GENERAL_INFO: u64 = 8;
}

impl<A: SignatureAlgorithm + DerWrite> DerWrite for PkiHeader<'_, A> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            self.pvno.write(writer.next());
            self.sender.write(writer.next());
            self.recipient.write(writer.next());
            if let Some(message_time) = self.message_time.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_MESSAGE_TIME), |writer| message_time.write(writer))
            };
            if let Some(protection_alg) = self.protection_alg.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_PROTECTION_ALG), |writer| protection_alg.write(writer))
            };
            if let Some(sender_kid) = self.sender_kid.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_SENDER_KID), |writer| sender_kid.write(writer))
            };
            if let Some(recip_kid) = self.recip_kid.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_RECIP_KID), |writer| recip_kid.write(writer))
            };
            if let Some(trans_id) = self.trans_id.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_TRANS_ID), |writer| trans_id.write(writer))
            };
            if let Some(sender_nonce) = self.sender_nonce.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_SENDER_NONCE), |writer| sender_nonce.write(writer))
            };
            if let Some(recip_nonce) = self.recip_nonce.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_RECIP_NONCE), |writer| recip_nonce.write(writer))
            };
            if let Some(free_text) = self.free_text.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_FREE_TEXT), |writer| free_text.write(writer))
            };
            if let Some(general_info) = self.general_info.as_ref() {
                writer
                    .next()
                    .write_tagged(Tag::context(Self::TAG_GENERAL_INFO), |writer| general_info.write(writer))
            };
        })
    }
}

impl<A: SignatureAlgorithm + BERDecodable> BERDecodable for PkiHeader<'_, A> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let pvno = <Pvno as BERDecodable>::decode_ber(reader.next())?;
            let sender = <GeneralName as BERDecodable>::decode_ber(reader.next())?;
            let recipient = <GeneralName as BERDecodable>::decode_ber(reader.next())?;
            let message_time: Option<GeneralizedTime> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_MESSAGE_TIME), |reader| {
                    <GeneralizedTime as BERDecodable>::decode_ber(reader)
                })
            })?;
            let protection_alg: Option<A> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_PROTECTION_ALG), |reader| {
                    <A as BERDecodable>::decode_ber(reader)
                })
            })?;
            let sender_kid: Option<OctetString> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_SENDER_KID), |reader| {
                    <OctetString as BERDecodable>::decode_ber(reader)
                })
            })?;

            let recip_kid: Option<OctetString> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_RECIP_KID), |reader| {
                    <OctetString as BERDecodable>::decode_ber(reader)
                })
            })?;
            let trans_id: Option<OctetString> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_TRANS_ID), |reader| {
                    <OctetString as BERDecodable>::decode_ber(reader)
                })
            })?;
            let sender_nonce: Option<OctetString> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_SENDER_NONCE), |reader| {
                    <OctetString as BERDecodable>::decode_ber(reader)
                })
            })?;
            let recip_nonce: Option<OctetString> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_RECIP_NONCE), |reader| {
                    <OctetString as BERDecodable>::decode_ber(reader)
                })
            })?;
            let free_text: Option<PkiFreeText> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_FREE_TEXT), |reader| {
                    <PkiFreeText as BERDecodable>::decode_ber(reader)
                })
            })?;
            let general_info: Option<GeneralInfo> = reader.read_optional(|reader| {
                reader.read_tagged(Tag::context(Self::TAG_GENERAL_INFO), |reader| {
                    <GeneralInfo as BERDecodable>::decode_ber(reader)
                })
            })?;

            Ok(PkiHeader {
                pvno,
                sender,
                recipient,
                message_time,
                protection_alg,
                sender_kid,
                recip_kid,
                trans_id,
                sender_nonce,
                recip_nonce,
                free_text,
                general_info,
            })
        })
    }
}

define_version! {
    /// The `PKIHeader` type defined in [RFC 4210 Section 5.1.1] features an inline
    /// INTEGER definition that is implemented as the Pvno enum.
    ///
    /// ```text
    ///     pvno                INTEGER     { cmp1999(1), cmp2000(2) },
    /// ```
    ///
    /// [RFC 4210 Section 5.1.1]: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.1
    Pvno {
        Cmp1999 = 1,
        Cmp2000 = 2,
    }
}

/// TODO: not implemented yet
pub type PkiFreeText = DerSequence<'static>;
