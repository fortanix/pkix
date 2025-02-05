/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate pkix;
extern crate mbedtls;

use pkix::pem::*;
use pkix::types::*;
use pkix::x509::*;
use pkix::{oid, DerWrite};
use pkix::{yasna, num_bigint, bit_vec};
use num_bigint::BigUint;
use bit_vec::BitVec;
use yasna::tags::*;

use mbedtls::{pk::Pk, hash::Md, rng::Rdrand};

pub(crate) fn sign_sha256(pkey: &mut Pk, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut hash = [0u8; 32];
    Md::hash(mbedtls::hash::Type::Sha256, data, &mut hash).map_err(|e| {
        format!("RSA req_info failure, {}", e)
    })?;

    let mut signature = vec![0u8; (pkey.len() + 7) / 8];
    let len = pkey.sign(mbedtls::hash::Type::Sha256, &hash, &mut signature, &mut Rdrand)
        .map_err(|e| format!("Data Signing Err {:?}", e))?;
    signature.truncate(len);
    Ok(signature)
}

fn main() {
    const EXPONENT: u32 = 3;

    let mut pk = Pk::generate_rsa(&mut Rdrand, 2048, EXPONENT).unwrap();
    
    let oid_rsa_encryption = ObjectIdentifier::from(vec![1, 2, 840, 113549, 1, 1, 1]);

    let rsapubkey = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // modulus
            writer.next().write_biguint(&BigUint::from_bytes_be(&pk.rsa_public_modulus().unwrap().to_binary().unwrap()));
            // public exponent
            writer.next().write_u8(EXPONENT as _);
        })
    });

    let dn = Name::from(vec![(
        ObjectIdentifier::from(vec![1, 3, 6, 1, 4, 1, 49690, 1, 1, 7]),
        TaggedDerValue::from_tag_and_bytes(TAG_BITSTRING, b"\x00\x01".to_vec())
    )]);

    let tbs_cert = TbsCertificate {
        version: TBS_CERTIFICATE_V3,
        serial: 1,
        sigalg: RsaPkcs15(Sha256),
        issuer: dn.clone(),
        validity_notbefore: DateTime::new(1970, 1, 1, 0, 0, 0).unwrap(),
        validity_notafter: DateTime::new(1970, 1, 1, 0, 0, 0).unwrap(),
        subject: dn,
        spki: DerSequence::from(yasna::construct_der(|w|
            w.write_sequence(|writer| {
                writer.next().write_sequence(|writer| {
                    oid_rsa_encryption.write(writer.next());
                    writer.next().write_null();
                });
                BitVec::from_bytes(&rsapubkey).write(writer.next());
            })
        )),
        extensions: vec![Extension {
            oid: oid::basicConstraints.clone(),
            critical: true,
            value: vec![0x30, 0],
        }],
    };

    let tbs_cert_der = yasna::construct_der(|writer| tbs_cert.write(writer));
    let signature = sign_sha256(&mut pk, &tbs_cert_der).unwrap();

    let cert = Certificate {
        tbscert: tbs_cert,
        sigalg: RsaPkcs15(Sha256),
        sig: BitVec::from_bytes(&signature),
    };

    let cert_der = yasna::construct_der(|writer| cert.write(writer));

    println!("{}{}", pk.write_private_pem_string().unwrap(), der_to_pem(&cert_der, PEM_CERTIFICATE));
}
