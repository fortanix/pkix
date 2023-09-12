/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! PKIHeader type

use yasna::{ASN1Error, ASN1ErrorKind, ASN1Result, BERDecodable, BERReader, DERWriter, Tag};

use crate::{
    types::{GeneralName, GeneralizedTime, OctetString, AlgorithmIdentifierOwned, DerAnyOwned},
    DerWrite,
};

use super::gen::GeneralInfo;

derive_sequence! {
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
    PkiHeader<'a> {
        pvno:           [_] UNTAGGED REQUIRED:  Pvno,
        sender:         [_] UNTAGGED REQUIRED:  GeneralName<'a>,
        recipient:      [_] UNTAGGED REQUIRED:  GeneralName<'a>,
        message_time:   [0] EXPLICIT OPTIONAL:  Option<GeneralizedTime>,
        protection_alg: [1] EXPLICIT OPTIONAL:  Option<AlgorithmIdentifierOwned>,
        sender_kid:     [2] EXPLICIT OPTIONAL:  Option<OctetString>,
        recip_kid:      [3] EXPLICIT OPTIONAL:  Option<OctetString>,
        trans_id:       [4] EXPLICIT OPTIONAL:  Option<OctetString>,
        sender_nonce:   [5] EXPLICIT OPTIONAL:  Option<OctetString>,
        recip_nonce:    [6] EXPLICIT OPTIONAL:  Option<OctetString>,
        free_text:      [7] EXPLICIT OPTIONAL:  Option<PkiFreeText>,
        general_info:   [8] EXPLICIT OPTIONAL:  Option<GeneralInfo>,
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
pub type PkiFreeText = DerAnyOwned;
