/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate pkix;

use pkix::pem::pem_to_der;
use pkix::types::ObjectIdentifier;
use pkix::x509::{CertificatePolicies, ExtKeyUsageSyntax, GenericCertificate, KeyUsage};
use pkix::FromBer;

/// Leaf certificate of usa.gov, last taken on 2 October 2023.
static USA_GOV_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIE4zCCA8ugAwIBAgISA9moPtUUW6hJ9wNdqksbB5biMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzA4MDQyMzE5MzdaFw0yMzExMDIyMzE5MzZaMBYxFDASBgNVBAMT
C3d3dy51c2EuZ292MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuCl0
Yt3Kw6yDc5nYO03kjpS7rYFQ0a6GNonrXiQ8M37Tn+si+YhC16DIXlYoR15rPC+m
XrbpSeQdQbrx6jh5qyjLtPM67GUVHrecIrDKVVt0PaKXqBzyKnp6Gna660oqOp7+
4DJyw4QwceDpFLKDnHBaDU26vAK3ZLUDI1LGUfRw2adQZkiJ7SF7jKIZ3+eafuu+
D8sWYBafHJad3TwzRb0FnUGbELCdpoyu5uzc0eWNfREv5HPvd2VgZe9xK7PkHcKT
VZ85eIVaIWuYU6uHQgmtnTsdCsGzIcDzodRUmxYSYoaEy8rkY6Dj3H1kNsR50gKz
E8i/0fUKRVQmgb+1AQIDAQABo4ICDTCCAgkwDgYDVR0PAQH/BAQDAgWgMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBSY+W2ERHzorAy97kJCFCG16BTLLTAfBgNVHSMEGDAWgBQULrMXt1hWy65QCUDm
H6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGGFWh0dHA6Ly9yMy5v
LmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmkubGVuY3Iub3JnLzAW
BgNVHREEDzANggt3d3cudXNhLmdvdjATBgNVHSAEDDAKMAgGBmeBDAECATCCAQQG
CisGAQQB1nkCBAIEgfUEgfIA8AB1ALc++yTfnE26dfI5xbpY9Gxd/ELPep81xJ4d
CYEl7bSZAAABicMQYDEAAAQDAEYwRAIgUdIZOKtoLFuAf8/ZAf0YxvsF0lD5ry8N
ADqoQpIjmpkCIA8gbEyhTew9IAQj3fu2HeCT78kzNQ4YjrNQ18AWbq1sAHcAejKM
VNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61IAAAGJwxBgUAAABAMASDBGAiEA
i3+tgLT/IO7tRb/Qx0ibmdW84y/NKQwaee5605AgXVICIQC1lx1FTjRmuhYOokdV
B1wXHFS1OIFsrZaFJ89uJmWJXzANBgkqhkiG9w0BAQsFAAOCAQEAZzDobZLz+Azk
rir77BDz8opdir5GKG8iHEIGTQMnVGARn7eYkBaI4dw1QeBfWJNFvnlar9zJ3Tzz
lmj+rMPYo9pA2EJq8u5jXTpCuZjwar2o7e0JB/4I9j9jI+PKIiZbfOUW/08FEIRO
w/SgEeqKV57nPP01JilEebRkmQ8k9za6kwgZqpVR5Z16fPQ0tlrYo2D31fcLtIpA
45gWtazlFYjZG9TScMNbqM8sE2VbiAKsC5QozOtWX77Aa/lO5LpqSvqzbEwlBNMG
NmO6vjR7jukhLG9iMExyX0Kkldnqlrs/JwSdKa7SKFuaJ3Pft/1yoBjs/BKc9Jq6
NLk8qlY5JQ==
-----END CERTIFICATE-----
";

lazy_static::lazy_static! {
    /// OID for CA/Browser Forum policy domain-validated
    static ref DOMAIN_VALIDATED: ObjectIdentifier = vec![2, 23, 140, 1, 2, 1].into();
}

/// Validate that the certificate from usa.gov meets the following
/// requirements:
/// - Key Usage contains digitalSignature and keyEncipherment
/// - Certificate policies contain a single policy with OID 2.23.140.1.2.1
///   (CA/Browser Forum domain-validated)
/// - Extended Key Usage contains TLS server auth and client auth
/// (I manually verified these properties by viewing the certificate
/// details in OpenSSL)
#[test]
fn validate_usa_gov_cert() {
    let der_cert = pem_to_der(USA_GOV_CERT, None).expect("USA cert should be valid");
    let cert = GenericCertificate::from_ber(&der_cert).expect("USA cert should be valid");

    // Check that Key Usage is good
    let key_usage_ext = cert
        .tbscert
        .get_extension(&pkix::oid::keyUsage)
        .expect("key usage should be present");
    let key_usage = KeyUsage::from_ber(&key_usage_ext.value).expect("key usage extension should be valid");
    assert!(key_usage.contains(KeyUsage::DIGITAL_SIGNATURE));
    assert!(key_usage.contains(KeyUsage::KEY_ENCIPHERMENT));

    // Check certificate policies
    let policies_ext = cert
        .tbscert
        .get_extension(&pkix::oid::certificatePolicies)
        .expect("certificate policies should be present");
    let mut policies = CertificatePolicies::from_ber(&policies_ext.value).expect("certificate policies should be valid");
    assert!(policies.0.len() == 1);
    let policy = policies.0.pop().expect("should be at least one policy");
    assert!(policy.policy_qualifiers.is_none());
    assert_eq!(policy.policy_identifier, *DOMAIN_VALIDATED);

    // Check extended key usage
    let eku_ext = cert
        .tbscert
        .get_extension(&pkix::oid::extKeyUsage)
        .expect("extended key usage should be present");
    let eku = ExtKeyUsageSyntax::from_ber(&eku_ext.value).expect("EKU extension should be valid");
    assert!(eku.0.contains(&pkix::oid::ID_KP_CLIENT_AUTH));
    assert!(eku.0.contains(&pkix::oid::ID_KP_SERVER_AUTH));
}
