//! The subset of the Sigstore bundle protobuf schema this crate verifies, read
//! with the proto3 JSON mapping: camelCase or original field names, `int64` as
//! a string or number, `bytes` as base64, enums by name or number, and `null`
//! as the field default. Unknown fields are rejected.
use std::fmt;

use base64::{
    DecodeError, Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, IgnoredAny, Visitor},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Bundle {
    #[serde(
        default,
        alias = "media_type",
        rename = "mediaType",
        deserialize_with = "or_default"
    )]
    pub(crate) media_type: String,
    #[serde(
        default,
        alias = "verification_material",
        rename = "verificationMaterial"
    )]
    pub(crate) verification_material: Option<VerificationMaterial>,
    #[serde(default, alias = "message_signature", rename = "messageSignature")]
    pub(crate) message_signature: Option<MessageSignature>,
    /// The other arm of the bundle's `content` oneof. Never verified here; kept
    /// so its presence is a recognised field rather than a parse error.
    #[serde(default, alias = "dsse_envelope", rename = "dsseEnvelope")]
    pub(crate) dsse_envelope: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerificationMaterial {
    #[serde(default)]
    pub(crate) certificate: Option<X509Certificate>,
    /// The other arms of the verification-material `content` oneof.
    #[serde(default, alias = "public_key", rename = "publicKey")]
    pub(crate) public_key: Option<IgnoredAny>,
    #[serde(
        default,
        alias = "x509_certificate_chain",
        rename = "x509CertificateChain"
    )]
    pub(crate) x509_certificate_chain: Option<IgnoredAny>,
    #[serde(
        default,
        alias = "tlog_entries",
        rename = "tlogEntries",
        deserialize_with = "or_default"
    )]
    pub(crate) tlog_entries: Vec<TransparencyLogEntry>,
    #[serde(
        default,
        alias = "timestamp_verification_data",
        rename = "timestampVerificationData"
    )]
    pub(crate) timestamp_verification_data: Option<TimestampVerificationData>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct X509Certificate {
    #[serde(
        default,
        alias = "raw_bytes",
        rename = "rawBytes",
        deserialize_with = "bytes"
    )]
    pub(crate) raw_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TimestampVerificationData {
    #[serde(
        default,
        alias = "rfc3161_timestamps",
        rename = "rfc3161Timestamps",
        deserialize_with = "or_default"
    )]
    pub(crate) rfc3161_timestamps: Vec<Rfc3161SignedTimestamp>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rfc3161SignedTimestamp {
    #[serde(
        default,
        alias = "signed_timestamp",
        rename = "signedTimestamp",
        deserialize_with = "bytes"
    )]
    pub(crate) signed_timestamp: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MessageSignature {
    #[serde(default, alias = "message_digest", rename = "messageDigest")]
    pub(crate) message_digest: Option<HashOutput>,
    #[serde(default, deserialize_with = "bytes")]
    pub(crate) signature: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HashOutput {
    #[serde(default)]
    pub(crate) algorithm: HashAlgorithm,
    #[serde(default, deserialize_with = "bytes")]
    pub(crate) digest: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransparencyLogEntry {
    #[serde(
        default,
        alias = "log_index",
        rename = "logIndex",
        deserialize_with = "int64"
    )]
    pub(crate) log_index: i64,
    #[serde(default, alias = "log_id", rename = "logId")]
    pub(crate) log_id: Option<LogId>,
    #[serde(default, alias = "kind_version", rename = "kindVersion")]
    pub(crate) kind_version: Option<KindVersion>,
    #[serde(
        default,
        alias = "integrated_time",
        rename = "integratedTime",
        deserialize_with = "int64"
    )]
    pub(crate) integrated_time: i64,
    #[serde(default, alias = "inclusion_promise", rename = "inclusionPromise")]
    pub(crate) inclusion_promise: Option<InclusionPromise>,
    #[serde(default, alias = "inclusion_proof", rename = "inclusionProof")]
    pub(crate) inclusion_proof: Option<InclusionProof>,
    #[serde(
        default,
        alias = "canonicalized_body",
        rename = "canonicalizedBody",
        deserialize_with = "bytes"
    )]
    pub(crate) canonicalized_body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogId {
    #[serde(
        default,
        alias = "key_id",
        rename = "keyId",
        deserialize_with = "bytes"
    )]
    pub(crate) key_id: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KindVersion {
    #[serde(default, deserialize_with = "or_default")]
    pub(crate) kind: String,
    #[serde(default, deserialize_with = "or_default")]
    pub(crate) version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InclusionPromise {
    #[serde(
        default,
        alias = "signed_entry_timestamp",
        rename = "signedEntryTimestamp",
        deserialize_with = "bytes"
    )]
    pub(crate) signed_entry_timestamp: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InclusionProof {
    #[serde(
        default,
        alias = "log_index",
        rename = "logIndex",
        deserialize_with = "int64"
    )]
    pub(crate) log_index: i64,
    #[serde(
        default,
        alias = "root_hash",
        rename = "rootHash",
        deserialize_with = "bytes"
    )]
    pub(crate) root_hash: Vec<u8>,
    #[serde(
        default,
        alias = "tree_size",
        rename = "treeSize",
        deserialize_with = "int64"
    )]
    pub(crate) tree_size: i64,
    #[serde(default, deserialize_with = "bytes_list")]
    pub(crate) hashes: Vec<Vec<u8>>,
    #[serde(default)]
    pub(crate) checkpoint: Option<Checkpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    #[serde(default, deserialize_with = "or_default")]
    pub(crate) envelope: String,
}

/// proto3 JSON lets any field be `null`, meaning its default.
fn or_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    Ok(Base64Bytes::deserialize(deserializer)?.0)
}

fn bytes_list<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error> {
    let list: Vec<Base64Bytes> = or_default(deserializer)?;
    Ok(list.into_iter().map(|item| item.0).collect())
}

fn int64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    Ok(Int64::deserialize(deserializer)?.0)
}

/// A proto `bytes` field.
#[derive(Default)]
struct Base64Bytes(Vec<u8>);

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor;

        impl Visitor<'_> for BytesVisitor {
            type Value = Base64Bytes;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a base64-encoded string")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                // The proto3 JSON mapping accepts both alphabets, padded or not.
                const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true)
                    .with_decode_padding_mode(DecodePaddingMode::Indifferent);
                const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
                const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG);

                match STANDARD.decode(value) {
                    Ok(bytes) => Ok(Base64Bytes(bytes)),
                    Err(DecodeError::InvalidByte(_, b'-' | b'_')) => URL_SAFE
                        .decode(value)
                        .map(Base64Bytes)
                        .map_err(|error| E::custom(format!("invalid base64: {error}"))),
                    Err(error) => Err(E::custom(format!("invalid base64: {error}"))),
                }
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(Base64Bytes::default())
            }
        }

        deserializer.deserialize_any(BytesVisitor)
    }
}

/// A proto `int64` field.
#[derive(Default)]
struct Int64(i64);

impl<'de> Deserialize<'de> for Int64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Int64Visitor;

        impl Visitor<'_> for Int64Visitor {
            type Value = Int64;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a 64-bit signed integer or a string holding one")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                value
                    .parse()
                    .map(Int64)
                    .map_err(|_| E::custom(format!("invalid int64 '{value}'")))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(Int64(value))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                i64::try_from(value)
                    .map(Int64)
                    .map_err(|_| E::custom(format!("int64 out of range: {value}")))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(Int64::default())
            }
        }

        deserializer.deserialize_any(Int64Visitor)
    }
}

/// `dev.sigstore.common.v1.HashAlgorithm`. Only SHA2-256 is ever accepted, so
/// every other known or unknown value collapses to `Other`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum HashAlgorithm {
    #[default]
    Unspecified,
    Sha2_256,
    Other,
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AlgorithmVisitor;

        impl Visitor<'_> for AlgorithmVisitor {
            type Value = HashAlgorithm;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a HashAlgorithm name or number")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(match value {
                    "HASH_ALGORITHM_UNSPECIFIED" => HashAlgorithm::Unspecified,
                    "SHA2_256" => HashAlgorithm::Sha2_256,
                    "SHA2_384" | "SHA2_512" | "SHA3_256" | "SHA3_384" => HashAlgorithm::Other,
                    other => return Err(E::custom(format!("unknown HashAlgorithm '{other}'"))),
                })
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(match value {
                    0 => HashAlgorithm::Unspecified,
                    1 => HashAlgorithm::Sha2_256,
                    _ => HashAlgorithm::Other,
                })
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                self.visit_i64(i64::try_from(value).unwrap_or(i64::MAX))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(HashAlgorithm::default())
            }
        }

        deserializer.deserialize_any(AlgorithmVisitor)
    }
}

impl Bundle {
    pub(crate) fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        let bundle: Bundle = serde_json::from_str(text)?;
        // A oneof may carry at most one arm.
        if bundle.message_signature.is_some() && bundle.dsse_envelope.is_some() {
            return Err(serde_json::Error::custom(
                "bundle sets more than one content field",
            ));
        }
        if let Some(material) = &bundle.verification_material {
            let arms = usize::from(material.certificate.is_some())
                + usize::from(material.public_key.is_some())
                + usize::from(material.x509_certificate_chain.is_some());
            if arms > 1 {
                return Err(serde_json::Error::custom(
                    "verification material sets more than one content field",
                ));
            }
        }
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V03_BUNDLE: &str = include_str!("../test-fixtures/fanzub-catalog-v2.1.0.sigstore.json");

    #[test]
    fn real_bundle_parses_with_every_verified_field_populated() {
        let bundle = Bundle::from_json(V03_BUNDLE).expect("parse fixture bundle");
        let material = bundle.verification_material.expect("verification material");
        assert!(
            !material
                .certificate
                .expect("certificate")
                .raw_bytes
                .is_empty()
        );
        let [entry] = material.tlog_entries.as_slice() else {
            panic!("fixture has exactly one tlog entry");
        };
        assert!(entry.log_index > 0 && entry.integrated_time > 0);
        assert_eq!(entry.log_id.as_ref().expect("log id").key_id.len(), 32);
        assert!(!entry.canonicalized_body.is_empty());
        let signature = bundle.message_signature.expect("message signature");
        let digest = signature.message_digest.expect("message digest");
        assert_eq!(digest.algorithm, HashAlgorithm::Sha2_256);
        assert_eq!(digest.digest.len(), 32);
    }

    #[test]
    fn proto3_json_scalar_forms_are_equivalent() {
        let parse = |json: &str| serde_json::from_str::<InclusionProof>(json).expect("parse proof");
        let strings = parse(r#"{"logIndex":"7","treeSize":"9","rootHash":"-_8=","hashes":["AQ"]}"#);
        let numbers = parse(r#"{"log_index":7,"tree_size":9,"root_hash":"+/8","hashes":["AQ=="]}"#);
        for proof in [&strings, &numbers] {
            assert_eq!((proof.log_index, proof.tree_size), (7, 9));
            assert_eq!(proof.root_hash, [0xfb, 0xff]);
            assert_eq!(proof.hashes, [vec![1_u8]]);
        }
        let nulls = parse(r#"{"logIndex":null,"rootHash":null,"hashes":null,"checkpoint":null}"#);
        assert_eq!(nulls.log_index, 0);
        assert!(nulls.root_hash.is_empty() && nulls.hashes.is_empty());
        assert!(nulls.checkpoint.is_none());
    }

    #[test]
    fn malformed_documents_are_rejected() {
        for json in [
            r#"{"mediaType":"x","unexpected":1}"#,
            r#"{"verificationMaterial":{"tlogEntries":[{"logIndex":"1","extra":true}]}}"#,
            r#"{"mediaType":"x","media_type":"y"}"#,
            r#"{"messageSignature":{"signature":"AA=="},"dsseEnvelope":{}}"#,
            r#"{"verificationMaterial":{"certificate":{"rawBytes":"AA=="},"publicKey":{}}}"#,
            r#"{"messageSignature":{"signature":"not base64!"}}"#,
            r#"{"messageSignature":{"messageDigest":{"algorithm":"SHA9"}}}"#,
            r#"{"verificationMaterial":{"tlogEntries":[{"logIndex":"9223372036854775808"}]}}"#,
            r#"{"verificationMaterial":{"tlogEntries":[{"logIndex":1.5}]}}"#,
        ] {
            assert!(Bundle::from_json(json).is_err(), "must reject {json}");
        }
    }
}
