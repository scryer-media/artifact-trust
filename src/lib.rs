//! Verification of signed artifact bytes against explicit GitHub signer requirements.
//! Network trust refresh requires the host to initialize its TLS crypto provider.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequiredSigner {
    pub github_repository: String,
    #[serde(default)]
    pub github_workflow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_ref: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation: {0}")]
    Validation(String),
    #[error("repository: {0}")]
    Repository(String),
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "verification")]
mod sigstore_bundle;
#[cfg(feature = "verification")]
mod tuf_refresh;
#[cfg(feature = "verification")]
mod verification;
#[cfg(feature = "verification")]
mod verification_key;
#[cfg(feature = "verification")]
pub use verification::{prime_sigstore_trust_roots, verify_signed_blob};
