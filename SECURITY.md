# Security policy

GlyphGuard is a security tool, so a bug in it can leave someone else exposed. Thank you for
reporting responsibly.

## Supported versions

GlyphGuard is pre-alpha. Security fixes go into the next release, built from `main`; only
the latest release on [PyPI](https://pypi.org/project/glyphguard/) is supported.

| Version | Supported |
|---|---|
| Latest 0.x release | Yes |
| Older releases | No; please upgrade |

## Reporting a vulnerability

Please report privately using GitHub's private vulnerability reporting:
<https://github.com/NicPWNs/GlyphGuard/security/advisories/new>. Don't open a public
issue, pull request or discussion for anything in the "in scope" list below.

Include the input as escaped code points (for example the output of
`glyphguard inspect --format json`), the API or command you ran, what you expected, and
what happened. A proof of concept against your own system is welcome; please don't test
against systems you don't own.

## Disclosure timeline

| Step | Target |
|---|---|
| Acknowledge your report | within 7 days |
| Confirm the issue and agree on severity | within 14 days |
| Release a fix | within 90 days, sooner for critical issues |
| Publish a GitHub security advisory (and request a CVE if warranted) | when the fix is released |

We'll keep you updated along the way and agree on the disclosure date with you. Reporters
are credited in the advisory and the changelog unless they prefer otherwise. If a fix
needs more than 90 days, we'll explain why and agree on a new date before then.

## In scope

- **Sanitizer bypasses:** input that still carries hidden content (an injection, a
  payload, reordering) after `sanitize()` with the `llm-input`, `llm-output`,
  `display-name` or `strict` profile.
- **Detection bypasses:** a variant of a technique in the catalog that GlyphGuard
  misses, for example a new encoding of tag or variation-selector smuggling.
- **Output injection:** anything that makes GlyphGuard's own CLI or reports emit raw
  escape sequences, bidi controls or other hidden characters.
- **Denial of service:** inputs that make detection or sanitization take super-linear
  time or memory, or crash.

## Out of scope

- Techniques that aren't in the catalog yet (for example lookalike confusables before
  v0.2). Please open a feature request.
- False positives. Please open a regular issue.

## Verifying releases

Every release is built by GitHub Actions from a tagged commit, and uploaded to PyPI with
Trusted Publishing (PyPI also stores its own attestations). Releases from v0.1.3 on carry
three independent proofs; v0.1.0 to v0.1.2 carry Sigstore signatures, added after
checking the files against PyPI.

```console
# GitHub build-provenance attestation
gh attestation verify glyphguard-0.1.3-py3-none-any.whl --repo NicPWNs/GlyphGuard

# Sigstore signature (the .sigstore.json file attached to the GitHub Release)
python -m pip install sigstore
python -m sigstore verify github glyphguard-0.1.3-py3-none-any.whl \
  --bundle glyphguard-0.1.3-py3-none-any.whl.sigstore.json --repository NicPWNs/GlyphGuard

# SLSA level 3 provenance (the .intoto.jsonl file attached to the GitHub Release)
slsa-verifier verify-artifact glyphguard-0.1.3-py3-none-any.whl \
  --provenance-path glyphguard-0.1.3.intoto.jsonl \
  --source-uri github.com/NicPWNs/GlyphGuard --source-tag v0.1.3
```
