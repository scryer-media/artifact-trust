# artifact-trust

Shared verification of signed artifact bytes. Extracted from Scryer commit
`383ca43c4a0fe724e7c4bfdde740e6ff12871be2`, retaining the source license and
verification fixtures. This repository is local; no remote is configured.

The default `verification` feature supports Cosign legacy blob bundles and
Sigstore v0.3 message-signature bundles, signer repository/workflow/ref matching,
certificate chains, transparency evidence, and trusted signing timestamps.
`default-features = false` exposes only signer requirements and error types.

```rust,no_run
# async fn example(bytes: Vec<u8>, bundle: Vec<u8>) -> artifact_trust::Result<()> {
artifact_trust::verify_signed_blob(bytes, bundle, artifact_trust::RequiredSigner {
    github_repository: "example/application".into(),
    github_workflow: Some(".github/workflows/build.yml".into()),
    github_ref: Some("refs/tags/v1.2.3".into()),
}).await
# }
```

The caller supplies trusted signer requirements; do not derive them from the
artifact being verified. Verification uses the embedded trust snapshot without
requiring a network refresh. `prime_sigstore_trust_roots` refreshes through
Sigstore's TUF verification and retains the current snapshot on failure. Hosts
initialize their TLS crypto provider before requesting a network refresh.

`trust/` includes the snapshot and its source/digest provenance. The snapshot was
materialized by Scryer's signature-verifying built-in preparation workflow.
Signed test fixtures are retained byte-for-byte; their Scryer/plugin identities
are intentional cryptographic evidence, not default signer policy.

## Local consumption

Before a remote dependency is configured, a sibling application can use:

```toml
artifact-trust = { path = "../artifact-trust" }
```

The Scryer extraction worktree declares the crate by version and uses a local
Cargo patch for validation, avoiding machine-specific paths in tracked files:

```sh
cargo check -p scryer-application --features runtime-plugin-trust \
  --config 'patch.crates-io.artifact-trust.path="/absolute/path/to/artifact-trust"'
```

Use the same `--config` override for Scryer's focused Nextest checks. The local
crate's dependency versions are carried over from the source lockfile.

## Validation

Run `cargo nextest run --locked --no-fail-fast` for the verifier and offline
certificate-binding fixtures, and `cargo check --locked --no-default-features`
for the signer-policy-only API. No live application instance is required.
