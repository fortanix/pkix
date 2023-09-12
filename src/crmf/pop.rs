/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! Proof of possession (POP)-related types

use bit_vec::BitVec;
use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERDecodable, BERReader, DERWriter, Tag};

use crate::{
    types::{DerAnyOwned, DerSequence, SignatureAlgorithm},
    DerWrite,
};

/// The `ProofOfPossession` type is defined in [RFC 4211 Section 4].
///
/// ```text
///   ProofOfPossession ::= CHOICE {
///       raVerified        [0] NULL,
///       -- used if the RA has already verified that the requester is in
///       -- possession of the private key
///       signature         [1] POPOSigningKey,
///       keyEncipherment   [2] POPOPrivKey,
///       keyAgreement      [3] POPOPrivKey }
/// ```
///
/// [RFC 4211 Section 4]: https://www.rfc-editor.org/rfc/rfc4211#section-4
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofOfPossession {
    RaVerified(()),
    Signature(PopoSigningKey),
    KeyEncipherment(POPOPrivKey),
    KeyAgreement(POPOPrivKey),
}

impl ProofOfPossession {
    /// IMPLICIT TAG (rfc4211#appendix-B) for RaVerified
    const TAG_RA_VERIFIED: u64 = 0;
    /// IMPLICIT TAG (rfc4211#appendix-B) for Signature
    const TAG_SIGNATURE: u64 = 1;
    /// IMPLICIT TAG (rfc4211#appendix-B) for KeyEncipherment
    const TAG_KEY_ENCIPHERMENT: u64 = 2;
    /// IMPLICIT TAG (rfc4211#appendix-B) for KeyAgreement
    const TAG_KEY_AGREEMENT: u64 = 3;

    fn tag(&self) -> Tag {
        match self {
            ProofOfPossession::RaVerified(_) => Tag::context(Self::TAG_RA_VERIFIED),
            ProofOfPossession::Signature(_) => Tag::context(Self::TAG_SIGNATURE),
            ProofOfPossession::KeyEncipherment(_) => Tag::context(Self::TAG_KEY_ENCIPHERMENT),
            ProofOfPossession::KeyAgreement(_) => Tag::context(Self::TAG_KEY_AGREEMENT),
        }
    }
}

impl DerWrite for ProofOfPossession {
    fn write(&self, writer: DERWriter) {
        match self {
            ProofOfPossession::RaVerified(()) => writer.write_tagged_implicit(self.tag(), |w| w.write_null()),
            ProofOfPossession::Signature(key) => writer.write_tagged_implicit(self.tag(), |w| key.write(w)),
            ProofOfPossession::KeyEncipherment(key) => writer.write_tagged_implicit(self.tag(), |w| key.write(w)),
            ProofOfPossession::KeyAgreement(key) => writer.write_tagged_implicit(self.tag(), |w| key.write(w)),
        }
    }
}

impl BERDecodable for ProofOfPossession {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let tag_number = reader.lookahead_tag()?.tag_number;
        reader.read_tagged_implicit(Tag::context(tag_number), |r| match tag_number {
            Self::TAG_RA_VERIFIED => Ok(ProofOfPossession::RaVerified(r.read_null()?)),
            Self::TAG_SIGNATURE => Ok(ProofOfPossession::Signature(PopoSigningKey::decode_ber(r)?)),
            Self::TAG_KEY_ENCIPHERMENT => Ok(ProofOfPossession::KeyEncipherment(POPOPrivKey::decode_ber(r)?)),
            Self::TAG_KEY_AGREEMENT => Ok(ProofOfPossession::KeyAgreement(POPOPrivKey::decode_ber(r)?)),
            _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
        })
    }
}

/// The `POPOPrivKey` type is defined in [RFC 4211 Section 4.2].
///
/// ```text
///   POPOPrivKey ::= CHOICE {
///       thisMessage       [0] BIT STRING,         -- Deprecated
///       subsequentMessage [1] SubsequentMessage,
///       dhMAC             [2] BIT STRING,         -- Deprecated
///       agreeMAC          [3] PKMACValue,
///       encryptedKey      [4] EnvelopedData }
/// ```
///
/// [RFC 4211 Section 4.2]: https://www.rfc-editor.org/rfc/rfc4211#section-4.2
/// TODO: not yet implemented, tracking issue: #23
type POPOPrivKey = DerAnyOwned;

/// The `POPOSigningKey` type is defined in [RFC 4211 Section 4.1].
///
/// ```text
///   POPOSigningKey ::= SEQUENCE {
///       poposkInput           [0] POPOSigningKeyInput OPTIONAL,
///       algorithmIdentifier   AlgorithmIdentifier{SIGNATURE-ALGORITHM,
///                                 {SignatureAlgorithms}},
///       signature             BIT STRING }
/// ```
///
/// [RFC 4211 Section 4.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PopoSigningKey<A: SignatureAlgorithm = DerSequence<'static>> {
    pub poposk_input: Option<PopoSigningKeyInput>,
    pub alg_id: A,
    pub signature: BitVec,
}

impl<A: SignatureAlgorithm> PopoSigningKey<A> {
    /// IMPLICIT TAG (rfc4211#appendix-B)
    const TAG_POPOSK_INPUT: u64 = 0;
}

impl<A: SignatureAlgorithm + DerWrite> DerWrite for PopoSigningKey<A> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|writer| {
            if let Some(poposk_input) = self.poposk_input.as_ref() {
                writer
                    .next()
                    .write_tagged_implicit(Tag::context(Self::TAG_POPOSK_INPUT), |w| poposk_input.write(w))
            };
            self.alg_id.write(writer.next());
            self.signature.write(writer.next());
        });
    }
}

impl<A: SignatureAlgorithm + BERDecodable> BERDecodable for PopoSigningKey<A> {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        // <ProofOfPossession as BERDecodable>::decode_ber(reader.next())
        reader.read_sequence(|reader| {
            let poposk_input: Option<PopoSigningKeyInput> = reader.read_optional(|reader| {
                let tag_number = reader.lookahead_tag()?.tag_number;
                reader.read_tagged_implicit(Tag::context(tag_number), |reader| match tag_number {
                    Self::TAG_POPOSK_INPUT => Ok(PopoSigningKeyInput::decode_ber(reader)?),
                    _ => Err(ASN1Error::new(ASN1ErrorKind::Invalid)),
                })
            })?;
            let alg_id = A::decode_ber(reader.next())?;
            let signature = BitVec::decode_ber(reader.next())?;
            Ok(PopoSigningKey {
                poposk_input,
                alg_id,
                signature,
            })
        })
    }
}

/// The `POPOSigningKeyInput` type is defined in [RFC 4211 Section 4.1].
///
/// ```text
///   POPOSigningKeyInput ::= SEQUENCE {
///       authInfo            CHOICE {
///        sender              [0] GeneralName,
///        publicKeyMAC        PKMACValue },
///       publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
/// ```
///
/// [RFC 4211 Section 4.1]: https://www.rfc-editor.org/rfc/rfc4211#section-4.1
/// TODO: not implemented yet
pub type PopoSigningKeyInput = DerSequence<'static>;
