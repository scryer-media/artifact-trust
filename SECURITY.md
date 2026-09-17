# Security

This crate is supported only as used by scryer-media's own applications. Report vulnerabilities
privately through the affected first-party application's GitHub Security
Advisories. Do not post vulnerability details in public issues or pull requests.

The embedding application is the trust boundary: it decides which signer
(repository, workflow and ref) an artifact must come from, and what happens to
bytes once they verify. This crate only answers whether the supplied bytes were
signed by that signer according to the Sigstore trusted root.
