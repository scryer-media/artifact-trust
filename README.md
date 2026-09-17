# artifact-trust

First-party Sigstore verification for signed release and plugin artifacts in
[Scryer](https://github.com/scryer-media/scryer) and the other
[scryer-media](https://github.com/scryer-media) first-party applications.

**This library is built only for scryer-media's own applications. Any other use is unsupported.
Your mileage may vary (YMMV).** APIs may change to meet first-party needs without
third-party compatibility guarantees. External support and feature requests
are not accepted.

## What it provides

- Keyless (Fulcio + Rekor) verification of signed blobs from their bytes and a
  bundle, in both shapes Cosign writes: the Cosign v2 legacy bundle and the
  Sigstore v0.3 bundle that Cosign v3 emits. `verify_signed_blob` picks the path
  from the bundle's shape.
- Signer policy: GitHub repository, workflow path and ref are matched against
  the Fulcio certificate. The caller supplies them; never derive them from the
  artifact being verified.
- Certificate chain, embedded SCT, Rekor inclusion (signed entry timestamp or
  inclusion proof with checkpoint) and RFC 3161 timestamp checks against the
  Sigstore trusted root.
- An embedded trusted-root snapshot, so verification needs no network, and an
  optional TUF-verified refresh (`prime_sigstore_trust_roots`) that keeps the
  current snapshot when the refresh fails.
- `default-features = false` exposes only the signer requirements and error
  types, with none of the verification dependencies.

Rekor v2 log entries are not supported and are rejected.

```rust,no_run
# async fn example(bytes: Vec<u8>, bundle: Vec<u8>) -> artifact_trust::Result<()> {
artifact_trust::verify_signed_blob(bytes, bundle, artifact_trust::RequiredSigner {
    github_repository: "example/application".into(),
    github_workflow: Some(".github/workflows/build.yml".into()),
    github_ref: Some("refs/tags/v1.2.3".into()),
}).await
# }
```

Verification runs on AWS-LC through `aws-lc-rs`; it does not depend on the
`sigstore` crate. The host application owns TLS: it installs the rustls crypto
provider before asking for a network refresh, and a refresh without one returns
an error.

## Trust material

`trust/sigstore-trusted-root.json` is the embedded snapshot of the Sigstore
public-good trusted root, and `trust/sigstore-tuf-root.json` is the TUF root
(version 12) that anchors refreshes. Each has a `.provenance.json` beside it
recording its source and SHA-256. The refresh uses `tough`, walks the root chain
forward from that anchor, and fetches over HTTPS only.

The signed files under `test-fixtures/` are real release signatures kept
byte-for-byte. The identities inside them are cryptographic evidence for the
tests, not a default signer policy.

## Consumption

First-party applications consume this repository through **signed version tags**.
It is not published to crates.io; the manifest sets `publish = false`.

```toml
[dependencies]
artifact-trust = { git = "https://github.com/scryer-media/artifact-trust.git", tag = "v0.1.0" }
```

Tags are signed, annotated, and immutable: never move an existing version tag.
Commit the consumer's `Cargo.lock` so it records the exact resolved commit.
Do not track a moving branch.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo nextest run --locked --no-fail-fast
cargo check --locked --no-default-features
```

The default test run is offline. Two `#[ignore]`d tests perform a live TUF
refresh against the Sigstore public-good repository; run them with
`cargo test -- --ignored`. No application instance is required.

## License

GPL-3.0-only (GNU General Public License version 3). See [LICENSE](LICENSE).
The unsupported-use policy does not restrict rights granted by that license.
