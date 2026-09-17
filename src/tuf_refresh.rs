//! Fetches `trusted_root.json` from the Sigstore public-good TUF repository.
//!
//! `tough` walks the root chain forward from the embedded root, enforces
//! metadata expiry, and checks the target's length and hash against the signed
//! targets metadata, so the returned bytes are TUF-verified.
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_core::Stream;
use tough::{
    Bytes, ExpirationEnforcement, IntoVec, RepositoryLoader, TargetName, Transport, TransportError,
    TransportErrorKind, TransportStream, async_trait,
};
use url::Url;

const SIGSTORE_TUF_METADATA_BASE: &str = "https://tuf-repo-cdn.sigstore.dev";
const SIGSTORE_TUF_TARGET_BASE: &str = "https://tuf-repo-cdn.sigstore.dev/targets";
const TRUSTED_ROOT_TARGET: &str = "trusted_root.json";
/// The TUF trust anchor. Any later root must chain from this one.
const EMBEDDED_SIGSTORE_TUF_ROOT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/trust/sigstore-tuf-root.json"
));

pub(crate) async fn fetch_trusted_root_json() -> Result<Vec<u8>, String> {
    let metadata_base = Url::parse(SIGSTORE_TUF_METADATA_BASE)
        .map_err(|error| format!("invalid Sigstore TUF metadata URL: {error}"))?;
    let target_base = Url::parse(SIGSTORE_TUF_TARGET_BASE)
        .map_err(|error| format!("invalid Sigstore TUF target URL: {error}"))?;

    // `Client::new` panics when the host has not installed a TLS provider.
    let client = reqwest::Client::builder()
        .build()
        .map_err(|error| format!("failed to build the Sigstore TUF HTTP client: {error}"))?;
    let repository = RepositoryLoader::new(&EMBEDDED_SIGSTORE_TUF_ROOT, metadata_base, target_base)
        .transport(HttpsTransport { client })
        .expiration_enforcement(ExpirationEnforcement::Safe)
        .load()
        .await
        .map_err(|error| format!("failed to load the Sigstore TUF repository: {error}"))?;

    let target = TargetName::new(TRUSTED_ROOT_TARGET)
        .map_err(|error| format!("invalid Sigstore TUF target name: {error}"))?;
    repository
        .read_target(&target)
        .await
        .map_err(|error| format!("failed to read Sigstore TUF target: {error}"))?
        .ok_or_else(|| format!("Sigstore TUF repository has no {TRUSTED_ROOT_TARGET} target"))?
        .into_vec()
        .await
        .map_err(|error| format!("failed to download Sigstore TUF target: {error}"))
}

#[derive(Clone, Debug)]
struct HttpsTransport {
    client: reqwest::Client,
}

#[async_trait]
impl Transport for HttpsTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        if url.scheme() != "https" {
            return Err(TransportError::new(
                TransportErrorKind::UnsupportedUrlScheme,
                url,
            ));
        }
        let response = self
            .client
            .get(url.as_str())
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| {
                // TUF probes for the next root version and treats "not found"
                // as the end of the chain, so the kind matters.
                let kind = match error.status() {
                    Some(
                        reqwest::StatusCode::NOT_FOUND
                        | reqwest::StatusCode::FORBIDDEN
                        | reqwest::StatusCode::GONE,
                    ) => TransportErrorKind::FileNotFound,
                    _ => TransportErrorKind::Other,
                };
                TransportError::new_with_cause(kind, url.clone(), error)
            })?;
        Ok(Box::pin(ResponseStream {
            inner: Box::pin(response.bytes_stream()),
            url,
        }))
    }
}

struct ResponseStream {
    inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send + Sync>>,
    url: Url,
}

impl Stream for ResponseStream {
    type Item = Result<Bytes, TransportError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx).map(|next| {
            next.map(|chunk| {
                chunk.map_err(|error| {
                    TransportError::new_with_cause(
                        TransportErrorKind::Other,
                        self.url.clone(),
                        error,
                    )
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Talks to the real Sigstore TUF CDN.
    #[tokio::test]
    #[ignore = "network"]
    async fn live_refresh_returns_a_tuf_verified_trusted_root() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let raw = fetch_trusted_root_json()
            .await
            .expect("fetch TUF-verified trusted_root.json");
        let document: serde_json::Value =
            serde_json::from_slice(&raw).expect("trusted root is JSON");
        assert!(
            document["mediaType"]
                .as_str()
                .expect("trusted root media type")
                .starts_with("application/vnd.dev.sigstore.trustedroot")
        );
    }

    #[tokio::test]
    async fn transport_refuses_plain_http() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let transport = HttpsTransport {
            client: reqwest::Client::new(),
        };
        let error = transport
            .fetch(Url::parse("http://tuf-repo-cdn.sigstore.dev/1.root.json").expect("url"))
            .await
            .err()
            .expect("plain http must be refused");
        assert_eq!(error.kind(), TransportErrorKind::UnsupportedUrlScheme);
    }
}
