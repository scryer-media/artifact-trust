//! Public-key signature verification over AWS-LC.
//!
//! The algorithm is chosen from the key's own SubjectPublicKeyInfo, never from
//! the signature or any caller-supplied hint.
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P521_SHA512_ASN1, ED25519,
    RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey, VerificationAlgorithm,
};
use base64::Engine;
use x509_cert::{
    der::{Decode, asn1::ObjectIdentifier},
    spki::SubjectPublicKeyInfoOwned,
};

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP_256_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const SECP_384_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const SECP_521_R_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const ID_ED_25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

pub(crate) struct VerificationKey {
    algorithm: &'static dyn VerificationAlgorithm,
    // DER SubjectPublicKeyInfo, which AWS-LC parses directly.
    public_key: Vec<u8>,
}

impl VerificationKey {
    /// Parses a DER SubjectPublicKeyInfo and fixes the verification algorithm
    /// from its algorithm identifier.
    pub(crate) fn try_from_spki_der(der: &[u8]) -> Result<Self, String> {
        let spki = SubjectPublicKeyInfoOwned::from_der(der)
            .map_err(|error| format!("cannot parse SubjectPublicKeyInfo: {error}"))?;
        let algorithm: &'static dyn VerificationAlgorithm = match spki.algorithm.oid {
            ID_EC_PUBLIC_KEY => {
                let parameters = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .ok_or_else(|| "EC key is missing its curve identifier".to_string())?;
                let curve: ObjectIdentifier = parameters
                    .decode_as()
                    .map_err(|error| format!("cannot parse EC curve identifier: {error}"))?;
                match curve {
                    SECP_256_R_1 => &ECDSA_P256_SHA256_ASN1,
                    SECP_384_R_1 => &ECDSA_P384_SHA384_ASN1,
                    SECP_521_R_1 => &ECDSA_P521_SHA512_ASN1,
                    other => return Err(format!("unsupported EC curve {other}")),
                }
            }
            RSA_ENCRYPTION => &RSA_PKCS1_2048_8192_SHA256,
            ID_ED_25519 => &ED25519,
            other => return Err(format!("unsupported public key algorithm {other}")),
        };
        Ok(Self {
            algorithm,
            public_key: der.to_vec(),
        })
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        UnparsedPublicKey::new(self.algorithm, &self.public_key)
            .verify(message, signature)
            .map_err(|_| "signature does not match the public key".to_string())
    }

    /// `signature` is standard, padded base64.
    pub(crate) fn verify_base64(&self, message: &[u8], signature: &str) -> Result<(), String> {
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .map_err(|error| format!("invalid base64 signature: {error}"))?;
        self.verify(message, &signature)
    }

    #[cfg(test)]
    pub(crate) fn ecdsa_p256_from_uncompressed_point(point: &[u8]) -> Self {
        Self {
            algorithm: &ECDSA_P256_SHA256_ASN1,
            public_key: point.to_vec(),
        }
    }
}
