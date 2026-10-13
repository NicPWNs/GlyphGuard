# Security policy

GlyphGuard is a security tool, so a bug in it can leave someone else exposed. Thank you for
reporting responsibly.

## Supported versions

GlyphGuard is pre-alpha. Only the latest commit on `main` receives fixes.

## Reporting a vulnerability

Please report privately through GitHub:
**Security > Report a vulnerability** on this repository. Don't open a public issue for
anything in the "in scope" list below.

Include the input as escaped code points (for example the output of
`glyphguard inspect --format json`), the API or command you ran, what you expected, and
what happened. A proof of concept against your own system is welcome; please don't test
against systems you don't own.

You'll get an acknowledgment within a week. Fixes for confirmed issues are prioritized
over feature work, and reporters are credited in the changelog unless they prefer
otherwise.

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
