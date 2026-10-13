# Changelog

All notable changes to GlyphGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Package and Marketplace metadata for search:
  - The PyPI summary says what GlyphGuard does.
  - More keywords and classifiers.
  - Documentation, repository and GitHub Action links.
  - A Marketplace description that fits the listing.
- A much shorter README. Recipes, the full CLI and Python reference, CI setup,
  sanitization profiles and performance moved to [docs/guide.md](docs/guide.md), whose
  examples run in the test suite like the README's.
- A shorter repository root. The fuzz target moved to `tests/fuzz/`, where it is now
  type-checked, and the hash-pinned CI tool locks moved to `.github/requirements/`.

## [0.3.0] - 2026-10-13

### Added

- `glyphguard scan`: scans a repository (git's tracked and untracked, non-ignored files
  by default, or the files and directories given). It judges AI agent instruction files
  more strictly: `AGENTS.md`, `CLAUDE.md`, `.claude/`, skills, Gemini, Cursor, Windsurf,
  Cline, Roo, Copilot, Junie, Kiro, Augment, Continue, OpenHands and Aider files, MCP
  configs and `llms.txt`. Medium findings in those files become high, and every finding
  there says which kind of file it is in. `--agents-only` and `--list-agent-files` are
  also available, as is the `glyphguard.scan` module (`agent_config_kind`, `escalate`,
  `scan_text`).
- `glyphguard mcp pin` and `glyphguard mcp check` catch MCP tool poisoning and rug
  pulls.
  - Every string in every tool definition (descriptions, parameter names and
    descriptions, enums) is scanned, and findings are escalated as agent instructions.
  - `pin` records the definitions in `glyphguard-mcp.lock` and refuses tools with
    hidden text unless given `--force`.
  - `check` fails when a tool is added, removed or changed, and shows the fields before
    and after.
  - GlyphGuard never starts servers: it reads each server's `tools/list` result as JSON.
  - Library: `glyphguard.mcp`.
- `scan` decodes Unicode escape sequences in JSON files and reports what they hide. An
  MCP tool description can carry tag smuggling as plain-ASCII escapes that a raw scan
  can't see. Findings point at the escapes in the file. `--escapes all` extends this to
  every file, and `--escapes none` turns it off. The decoder is
  `glyphguard.escapes.detect_escaped()`.
- `glyphguard.net`: `check_hostname()` and `check_url()` find deceptive domains.
  - Punycode is decoded the way browsers display it, and each label is judged on its own.
  - Flagged: mixed scripts, words whose every letter has an ASCII lookalike, styled or
    fullwidth letters, invisible characters, characters not allowed in identifiers,
    punycode that decodes to ASCII, and invalid punycode.
  - With `protect=[...]`, it reports hostnames that pass for a protected domain or start
    with one (`paypal.com.verify.example`).
  - It catches `https://paypal.com@evil.example/` user-name tricks.
  - New command: `glyphguard url`.
- Conformance vectors modeled on published incidents: the Rules File Backdoor
  (tag-smuggled and bidi-reordered instructions in rules files) and GlassWorm (JavaScript
  hidden in variation selectors).

### Changed

- The GitHub Action and the pre-commit hook run `glyphguard scan`, so agent instruction
  files get the stricter treatment.

## [0.2.0] - 2026-10-13

### Security

- Terminal escape findings could include raw characters from the input's OSC command
  field in their message, so `glyphguard detect` could print hidden or bidi characters to
  the terminal. The field is now escaped. Found by the new fuzz target.

### Added

- Lookalike detection, a new CONF family of four techniques built on UTS #39 data
  (`confusables.txt`, `IdentifierStatus.txt`):
  - GG-CONF-001: letters from another script hiding in a word.
  - GG-CONF-002: whole words spelled in a lookalike script inside Latin text.
  - GG-CONF-003: styled letters (mathematical, fullwidth and so on).
  - GG-CONF-004: numbers that mix digit systems.

  Russian, Greek, Japanese and other native text is not flagged. Neither are IPA,
  mathematical notation, or fullwidth forms in East Asian text, which are info-level
  at most.
- A `fold` sanitize action, used for CONF by the `llm-input`, `llm-output`,
  `display-name` and `strict` profiles. It turns lookalike letters back into what they
  pass for, judged by the script of the word around them. `reveal` now escapes every
  character of a lookalike word.
- `glyphguard.Guard`: protected-term matching that survives lookalike letters, styled
  letters, accents, leetspeak, separators, repeated letters and invisible characters.
  - Modes: `word`, `contains` and `exact`, plus an allowlist.
  - Each match reports its exact span and per-character evidence of the tricks used.
  - Matching stays linear on adversarial input.
- New functions: `glyphguard.canonicalize()` (a comparison key for names),
  `skeleton()`, `is_confusable()` and `restriction_level()`, plus the
  `glyphguard.confusables` module (script sets, mixed-script tests, lookalike lookups).
- New commands: `glyphguard check`, `glyphguard skeleton` and `glyphguard confusable`.
- `glyphguard detect --exclude GLOB` and a matching `exclude` input on the GitHub Action.
- Python 3.15 support, tested in CI on Linux, macOS and Windows.
- Coverage-guided fuzzing with ClusterFuzzLite and Atheris (`fuzz/`): short runs on every
  pull request and a weekly batch run.
- Signed releases: each GitHub Release gets SLSA level 3 provenance (`.intoto.jsonl`) and
  Sigstore signatures (`.sigstore.json`), checked against the files on PyPI before
  signing. See "Verifying releases" in SECURITY.md.

### Changed

- CI and release tooling (pytest, hypothesis, ruff, mypy, build, twine) is installed from
  hash-pinned locks in `requirements/`, kept current by Dependabot.
- The security policy links private vulnerability reporting directly and states a
  disclosure timeline.

## [0.1.2] - 2026-10-13

### Added

- SARIF 2.1.0 output: `glyphguard detect --format sarif`, or `--sarif FILE` alongside any
  other format. Every catalog technique is a rule with CWE tags and a GitHub
  `security-severity` score, and every finding has an exact line and column range.
- GitHub Action inputs `upload-sarif`, `sarif-file` and `category`, to report findings to
  GitHub code scanning (the Security tab), plus a `sarif-file` output.
- `glyphguard detect` scans directories recursively, skipping `.git`, `.hg` and `.svn`.

### Fixed

- The README and CHANGELOG said the catalog has 27 techniques; it has 25. A test now
  checks the README against the catalog.

## [0.1.1] - 2026-10-13

### Fixed

- Images and links in the PyPI project description. They were repository-relative paths
  that only resolve on GitHub; the build now rewrites them to absolute URLs, and CI fails
  if a relative one slips through.

## [0.1.0] - 2026-10-13

First release: the detection, decoding and sanitization core.

### Added

- Technique catalog of 25 techniques in five families (INV, SMUG, BIDI, CTRL, MARK), with
  stable IDs, severities, CWE and MITRE ATLAS references.
- `detect()`, `payloads()` and `inspect()`, with exact spans. Hidden payloads are decoded
  from tag characters, variation selectors, zero-width binary and terminal escapes (OSC 8
  links, OSC 52 clipboard writes).
- `sanitize()` with the `llm-input`, `llm-output`, `display-name`, `strict` and `reveal`
  profiles, plus `reveal()`. Every change is recorded.
- `glyphguard.stego` encoders and decoders for the smuggling channels.
- CLI commands: `inspect`, `detect` (file:line:col output and exit codes), `sanitize`,
  `catalog`. `detect` skips binary files, reads NUL-separated file lists with
  `--files0-from`, and emits GitHub annotations with `--format github`.
- GitHub Action (`uses: NicPWNs/GlyphGuard@v0.1.0`) that annotates findings inline on
  pull requests, and a pre-commit hook.
- Vendored Unicode 18.0.0 tables generated by `scripts/gen_data.py`.
- Conformance vectors, a multilingual benign corpus, property-based tests, and a
  repo-hygiene test that runs GlyphGuard on its own sources.

[Unreleased]: https://github.com/NicPWNs/GlyphGuard/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/NicPWNs/GlyphGuard/releases/tag/v0.3.0
[0.2.0]: https://github.com/NicPWNs/GlyphGuard/releases/tag/v0.2.0
[0.1.2]: https://github.com/NicPWNs/GlyphGuard/releases/tag/v0.1.2
[0.1.1]: https://github.com/NicPWNs/GlyphGuard/releases/tag/v0.1.1
[0.1.0]: https://github.com/NicPWNs/GlyphGuard/releases/tag/v0.1.0
