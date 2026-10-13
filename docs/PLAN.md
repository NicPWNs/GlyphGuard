# GlyphGuard: Research & Build Plan

*Drafted 2026-10-13; v0.1 built the same day (see section 11). Revision 2 broadens the scope from a protected-name matcher to a
general Unicode security toolkit, with AI and red-team work as a main focus.*

## 1. Vision

**GlyphGuard is the go-to toolkit for the character layer of security.** That layer is
the gap between what a person *sees*, what a program *compares*, and what a model
*reads*.

Reserved-name checks, keyword filters and prompt-injection guardrails all compare code
points, while people and models respond to what the text *looks like* or *tokenizes to*.
`аdmin` with a Cyrillic `а` passes a check for `admin`; a zero-width space hides a
keyword from a filter. That bug class now shows up across most of the stack:

| Domain | Examples |
|---|---|
| **Identity** | Impersonating usernames, display names, bot and webhook names, brand names |
| **Content** | Moderation and keyword-filter evasion. A 2026 phishing campaign sent millions of emails per day that split keywords with invisible tag characters. |
| **AI / LLM** | Invisible prompt injection (tag-character "ASCII smuggling", variation-selector smuggling), imperceptible jailbreaks, guardrail evasion, poisoned MCP tool descriptions and agent rules/skills files, data exfiltration through hidden output, ANSI escape injection into terminals |
| **Code & supply chain** | Trojan Source (bidi), confusable identifiers, GlassWorm (malware payloads hidden as variation selectors and Private Use Area characters in VS Code extensions), the Rules File Backdoor |
| **Network** | IDN homograph domains, lookalike URLs and email addresses |
| **Parsing** | Normalization and transcoding attacks: NFKC after validation, Windows "best-fit" mapping (WorstFit), case-mapping collisions, malformed UTF-8 |

**One engine, many surfaces.** A single catalog of techniques drives everything. Each
technique has a stable ID and four capabilities:

- **detect**: find it, with spans and evidence
- **neutralize**: sanitize or canonicalize it under a profile
- **generate**: produce attack variants, for red teams
- **explain**: produce human-readable evidence, for moderators, reviewers and SOC analysts

Every user-facing surface draws on that catalog: library, CLI, CI scanner, LLM
middleware, MCP server, red-team adapters and the benchmark.

## 2. Threat taxonomy: the technique catalog

This catalog is the project's core asset. Each entry gets an ID (e.g. `GG-INV-003`),
character data, test vectors, a default severity, and mappings to OWASP LLM Top 10 /
MITRE ATLAS where relevant.

| Family | Techniques |
|---|---|
| **CONF: Confusables** | Cross-script homoglyphs (Cyrillic, Greek, Cherokee...); whole-script spoofs (all-Cyrillic `раураl`); compatibility forms (math alphanumerics, fullwidth, circled, squared, superscript); small caps and IPA letters; upside-down text; regional-indicator and negative-squared emoji letters; multi-character confusables (`rn`/`m`, `cl`/`d`, `vv`/`w`); mixed-number systems |
| **INV: Invisibles** | Zero-width characters (ZWSP, ZWNJ, ZWJ, WJ, BOM); invisible math operators U+2061–2064; soft hyphen; Mongolian vowel separator; blank-rendering fillers (U+3164, U+115F, U+2800); exotic spaces; noncharacters; unassigned code points |
| **SMUG: Smuggling / steganography** | Tag-block ASCII smuggling (U+E0000–E007F); variation-selector byte smuggling (VS1–256, the Butler technique); zero-width binary encodings; Private Use Area payloads (GlassWorm); whitespace-variant steganography |
| **BIDI** | Overrides and isolates (Trojan Source); stray RLM/LRM/ALM marks; visual-reorder spoofing (`\u202Edrocsid`); mirrored brackets |
| **MARK: Combining marks** | Zalgo stacking; overlay strokes (U+0335/U+0338); diacritic perturbation aimed at OCR and vision models |
| **CTRL: Control & terminal** | C0/C1 controls; backspace/DEL "deletion" attacks; ANSI/OSC escape sequences in LLM output headed for terminals (hidden text, hyperlinks, clipboard writes) |
| **OBF: Text obfuscation** | Leetspeak; separator insertion; letter repetition; case alternation; token-boundary perturbation (TokenBreak-style) |
| **NORM: Normalization & transcoding** | Characters that change meaning after NFKC/casefold (`＜script＞` → `<script>`, `ﬁ` → `fi`); Windows best-fit and ANSI mapping (fullwidth quotes becoming `"`, which enables argument injection); case-mapping collisions (`ı`, `ß`, `K` Kelvin sign); overlong or invalid UTF-8; lone surrogates |

GlyphGuard owns the **character and representation layer**. It does **not** try to judge
whether "ignore previous instructions" is malicious; semantic classifiers do that. Its
job is to make sure those classifiers, filters and humans all see the *true* text, and
to flag the representational tricks themselves.

## 3. Prior art

### Standards

| Source | Use | Limits |
|---|---|---|
| **UTS #39** Security Mechanisms (v18.0, Aug 2026) | Skeleton algorithm (`skeleton`/`bidiSkeleton`), mixed-script detection, restriction levels, Identifier_Status/Type. Data: `confusables.txt`, `intentional.txt`, `IdentifierStatus.txt`, `IdentifierType.txt` | Skeletons are for comparison only and are unstable across versions. It tests whole-string equality only. It is purely visual: no leetspeak, no spacing. |
| **UTS #55** (source code), **UTS #36** (security considerations), **UTS #51** (emoji, tag sequences) | Threat guidance; legitimate uses of tags (subdivision flags) and variation selectors (emoji presentation) | Guidance only |
| **UAX #15** (NFKC), **UAX #9** (bidi), **UAX #29** (graphemes) | Building blocks | NFKC alone gives no homoglyph defense |
| **PRECIS** (RFC 8264/8265/8266), **UTS #46** / IDNA2008 | Username, nickname and domain profiles | No confusables |

### Unicode-security libraries

| Project | Status (checked Oct 2026) | Notes |
|---|---|---|
| ICU `SpoofChecker` (via **PyICU**) | Active | Closest to the standard. In Python it is a heavy native dependency and painful on Windows. Whole-string only. |
| **confusable_homoglyphs** / **confusables** / **homoglyphs** | Archived (2024) / last release 2021 / archived (2020) | Python's legacy options. All effectively dead. |
| **Unidecode** / **anyascii** | Active | *Phonetic*, so the wrong tool. Reported to make invisible-character attacks worse. Unidecode is GPL. |
| **decancer** (Rust, ~130★) | Active | `cure`, `contains`, `censor`, leetspeak, zalgo, bidi. Python support is only the unofficial `decancer_py`. Custom mapping, no explanations. |
| **disarm** (Rust core + Python) | New (2026), ~2★ | General canonicalization, TR39 folding, hostname checks, LLM/RAG pipelines. The most similar in spirit. Worth watching and using for differential testing. |
| `unicode-security` crate, rustc confusable lints, Chromium `IDNSpoofChecker` | Active | Reference designs. Chromium's design (skeleton against a protected list) is the model for GlyphGuard's protected-term matching. |

### AI security and red-team tooling

| Project | Side | Unicode coverage | Gap |
|---|---|---|---|
| **PyRIT** (Microsoft, v1.1, Sep 2026) | Attack | Converters: `UnicodeConfusable`, `ZeroWidth`, `Zalgo`, `Leetspeak`, `CharacterSpace`, `UnicodeSubstitution`, ANSI escapes | Generation only. No defense, no detection. |
| **garak** (NVIDIA, v0.17, Sep 2026) | Attack | `badchars` probe (invisible, homoglyph, reorder, deletion, after Boucher et al.), `smuggling`, encoding probes incl. variation-selector ASCII smuggling and leetspeak | Same as PyRIT |
| **promptfoo** | Attack | `homoglyph`, `leetspeak` strategies; `ascii-smuggling` plugin | Same as PyRIT |
| **LLM Guard** (ProtectAI) | Defense | `InvisibleText` scanner | Last release May 2025. Narrow: no confusables, no decoding, no bidi reorder. |
| **prompt-canon** / **casefold-fuzz** | Defense / attack | Pure-stdlib canonicalizer and mutation fuzzer | Brand new (Aug 2026), single author, small scope. Validates demand. |
| **Unsmuggle** (TS), **symbi-invis-strip** (Rust) | Defense | Tag and invisible stripping | Single-purpose, not Python |
| Azure Prompt Shield, Prompt Guard, NeMo, Lakera... | Defense (classifiers) | Mostly none at the character layer | Shown to be evadable by character injection. See §4. |
| **nickboucher/imperceptible**, Mindgard evasion dataset, Imperceptible Jailbreaking code | Research | Attack corpora | Not packaged as a toolkit |

**The overall gap.** Red-team tools *generate* Unicode attacks, and defenses are scattered
single-purpose strippers. **No project ships matched attack/defense pairs from one
catalog, decodes smuggled payloads for forensics, audits tokenizers, scans
repos/MCP/agent configs, and publishes a benchmark proving its effect.** That is the
space GlyphGuard should own.

## 4. AI injection and red-teaming research

### Key findings

- **Guardrail evasion.** Hackett et al., *Bypassing Prompt Injection and Jailbreak
  Detection in LLM Guardrails* (Mindgard / Lancaster, arXiv 2504.11168), tested six
  guardrails including Azure Prompt Shield and Meta Prompt Guard. Character injection
  (emoji/variation-selector smuggling, tag smuggling, zero-width characters, homoglyphs,
  diacritics) reached **up to 100% evasion** in some cases.
- **Imperceptible jailbreaks.** Gao et al. (arXiv 2510.05025, Oct 2025) append *invisible
  variation selectors*, optimized by a search, to a harmful prompt. The text renders
  identically but tokenizes differently, giving high attack success on four open models.
  It also generalizes to prompt injection.
- **Variation-selector smuggling.** Paul Butler (Feb 2025) showed arbitrary bytes can
  ride on one emoji via VS1–256, and that tokenizers preserve them.
- **ASCII smuggling.** Goodside, then Rehberger (2024): Tags-block text is invisible to
  people and readable by models. Rehberger used it for M365 Copilot exfiltration (since
  mitigated). He later used hidden Unicode against coding agents in 2025–2026: Google
  Jules, and skills files in several agent platforms (CSA research note, Mar 2026).
  Vendors sanitize inconsistently, and that changes over time, so it needs continuous
  testing.
- **Crossover to phishing.** Microsoft, *ASCII smuggling crosses over from AI prompt
  injection to phishing evasion* (Sep 2026): around 2.3M emails per day at peak (Feb–May
  2026) used tag characters to split keywords.
- **Agent supply chain:**
  - The **Rules File Backdoor** (Pillar Security, Mar 2025) hid instructions in Cursor
    and Copilot rules files. GitHub now warns about hidden Unicode in files.
  - **MCP tool poisoning** (Invariant Labs, Apr 2025) hides instructions in tool
    descriptions, sometimes with zero-width or tag characters, plus "rug pulls" where a
    description changes after approval.
  - **GlassWorm** (Koi Security, Oct 2025) is self-propagating VS Code extension malware
    with code hidden in variation selectors and PUA characters.
- **Tokenizer-level evasion.** HiddenLayer's **TokenBreak** (arXiv 2506.07948): single
  inserted characters flip BPE/WordPiece-based protection classifiers while the target
  LLM still understands the text. Unigram tokenizers resisted it.
- **Classical NLP.** Boucher et al., *Bad Characters* (arXiv 2106.09898): invisibles,
  homoglyphs, reorderings and deletions break translation, search and classifiers with
  one to three injections. *Trojan Source* (same group) applies this to code.
- **Detector evasion.** *SilverSpeak* (GenAIDetect 2025): a 5–20% Cyrillic homoglyph swap
  drives AI-text detectors to roughly chance (MCC 0.64 → −0.01). Perspective API and
  toxicity models fall to homoglyphs and segmentation (Hosseini 2017; arXiv 1801.01828).
- **Normalization defense works, if done right.** Meta's *Adversarial Text Normalization*
  (arXiv 2206.04137) restores accuracy cheaply. The "Fire Extinguishers Full of Gasoline"
  benchmark (seen second-hand; verify against the primary paper) reports that
  NFC/NFKC/casefold give **zero** homoglyph defense, that Unidecode *hurts*, and that
  folding native-script text toward Latin damages non-Latin users. **Canonicalization
  must be visual, case-aware and script-aware, not just "make it ASCII".**

### How GlyphGuard helps defenders (blue team)

1. **Canonicalize before you guard.** Classifiers (Prompt Guard, Prompt Shield, custom
   models) and keyword filters run on GlyphGuard's *canonical view*, while the original
   text stays available for display and logging.
2. **Detect smuggling channels on every ingress point:** user input, tool and function
   outputs, RAG documents at *ingestion* time, emails, web pages, and file uploads.
3. **Decode and report hidden payloads.** `glyphguard decode` extracts tag-ASCII,
   variation-selector bytes, zero-width binary and PUA blobs. It shows the analyst *what
   was hidden*, not just that something was.
4. **Dual view.** A *rendered view* (what a person sees) and a *model view* (what the model
   reads), diffed side by side. This makes invisible injection obvious in review UIs and
   incident reports.
5. **Agent and supply-chain scanning.** Scan `.cursor/rules`, `CLAUDE.md`, `AGENTS.md`,
   skills folders, MCP server manifests and tool descriptions, prompt templates, and
   source code (bidi, confusable identifiers, GlassWorm-style payloads). Output SARIF for
   GitHub code scanning, plus a pre-commit hook. **Pin and diff MCP tool descriptions**
   to catch rug pulls.
6. **Output hygiene.** Strip tags and invisibles from model output before it is rendered
   or turned into a link, to block exfiltration through hidden text. Neutralize
   ANSI/OSC escapes before output reaches a terminal.
7. **Tokenizer exposure audit.** For a given tokenizer (tiktoken, Hugging Face
   `tokenizers`, SentencePiece), report which invisible and confusable classes *survive
   as distinct tokens*. Those are the classes a model can be smuggled through, which
   tells you what your sanitizer must cover for that model.

### How GlyphGuard helps attackers-for-hire (red team)

1. **Mutators with the same catalog IDs as the detectors.** Composable transforms
   (`conf.cross_script`, `smug.tag`, `smug.vs`, `bidi.rlo`, `mark.zalgo`, `obf.leet`,
   `obf.tokenbreak`...) with seeds and intensity control, so runs are reproducible.
2. **Framework adapters:**
   - `glyphguard.integrations.pyrit` (custom `PromptConverter`s)
   - garak buffs/probes
   - a promptfoo custom strategy
   - a corpus exporter for anyone else
3. **Guardrail robustness scoring.** Run a seed set of attacks × mutators against a
   guardrail or classifier. Report the evasion rate per technique *with and without*
   GlyphGuard preprocessing, giving a "Unicode robustness score".
4. **Coverage map.** Show which techniques a system under test detects, neutralizes or
   misses. This doubles as a regression suite as vendors change sanitization.
5. **Responsible-use guardrails.** Document the generators for testing systems you own or
   are authorized to test. Don't ship new zero-days; follow published techniques and cite
   them.

## 5. Empirical check: TR39 alone isn't enough

Run locally against `confusables.txt` dated 2026-08-06, target `admin`:

| Obfuscation | NFKC + casefold | TR39 skeleton (raw) | NFKC then skeleton |
|---|---|---|---|
| Cyrillic `a` (`\u0430dmin`) | no | yes | yes |
| Math bold / fullwidth | yes | yes | yes |
| Circled / squared / superscript | yes | no | yes |
| Negative squared, regional indicators | no | no | no |
| Small caps | no | no | no |
| Leetspeak `4dm1n` | no | no (`1` maps to `l`) | no |
| Combining overlay `ad\u0335min` | no | no | no |
| Zero-width `ad\u200Bmin` | no | yes (spec strips ignorables) | yes |
| Separators / repetition (`a.d.m.i.n`, `aadmiin`) | no | no | no |
| Bidi override `\u202Enimda` | no | needs `bidiSkeleton` | needs `bidiSkeleton` |
| `rn` for `m` (`adrnin`) | no | yes | yes |

Takeaways:

- Normalization order matters: NFKC must come before the skeleton.
- TR39 leaves about half of the realistic evasions open.
- **Version drift is real.** The test machine's Python 3.11 `unicodedata` is Unicode
  14.0, while the security data is 18.0.

## 6. Product surfaces

| Surface | What |
|---|---|
| **Core library** `glyphguard` | `inspect`, `detect`, `sanitize`/`canonicalize`, `confusable` (skeleton, compare, `Guard` for protected terms), `stego` (detect and decode), `net` (hostnames, URLs, emails), `redteam` (mutators, corpora), `tokenizers` (exposure audit) |
| **CLI** | `glyphguard inspect / detect / sanitize / decode / diff / scan / check / fuzz / audit-tokenizer / bench` |
| **CI & dev** | Pre-commit hook, GitHub Action (SARIF), configurable rules (`glyphguard.toml`), inline suppressions |
| **LLM middleware** | Wrappers for the Anthropic and OpenAI SDKs, LangChain and LlamaIndex callbacks, an ASGI/FastAPI middleware, an output sanitizer |
| **MCP** | `glyphguard-mcp` server, so agents can call inspect/sanitize/decode themselves. An MCP manifest and tool-description scanner with pinning and diffing. |
| **App integrations** | `pydantic` types (`SafeDisplayName`, `SafeIdentifier`), Django/FastAPI validators, discord.py helper, Python `logging` filter (log-injection and bidi defense) |
| **GlyphBench** | Public dataset and harness: attack variants per technique, plus a benign multilingual corpus. Scores detection recall, false-positive rate, canonicalization recovery, and guardrail evasion with and without preprocessing. Compares against ICU, NFKC, Unidecode, decancer, disarm, prompt-canon and LLM Guard. |
| **Playground** | Browser page (Pyodide, later WASM) that pastes text and shows the dual view, findings and decoded payloads. Good for adoption and demos. |
| **Later** | Rust core with PyO3 bindings (speed, plus JS/WASM/Go reach), VS Code extension (highlight hidden characters and confusables), font-aware confusable builder (render in a target font and diff glyphs, after ShamFinder) |

### API sketch

```python
import glyphguard as gg

# Inspect: char-by-char truth
report = gg.inspect("Pay\u0430l\u200b\U000E0049\U000E0047\U000E004E")
report.rendered        # what a human sees
report.model_view      # what a tokenizer receives (escaped)
report.findings        # [Finding(id="GG-CONF-001", span=(3,4), severity=HIGH, ...),
                       #  Finding(id="GG-INV-001", ...), Finding(id="GG-SMUG-001", payload="IGN", ...)]

# Sanitize: profile-driven
gg.sanitize(text, profile="llm-input")     # strip smuggling channels, bidi controls, zalgo; keep native scripts
gg.sanitize(text, profile="display-name")  # PRECIS-like + blank-name rejection
gg.canonicalize(text)                      # visual canonical view for classifiers and filters

# Decode hidden payloads (forensics)
for p in gg.stego.decode(text): print(p.channel, p.span, p.data)

# Confusables & protected terms (one feature among many)
gg.skeleton("𝐚𝐝𝐦𝐢𝐧") == gg.skeleton("admin")
guard = gg.Guard(protected=["admin", "support"], policy="strict")
guard.check("а.dm1n").verdict            # BLOCK, with spans and evidence

# Red team
from glyphguard.redteam import mutate, Mutator
mutate("ignore previous instructions", [Mutator.SMUG_TAG, Mutator.CONF_CROSS_SCRIPT], seed=7)

# Tokenizer exposure
gg.tokenizers.audit("cl100k_base")       # which invisible/confusable classes survive tokenization
```

## 7. Architecture

```
glyphguard/
  catalog/            # technique definitions (TOML): id, family, chars, severity, refs, ATLAS/OWASP tags
  _data/              # generated tables from unicode.org + catalog (versioned, hashed)
  engine/
    pipeline.py       # staged transforms with offset maps: (text, offsets) -> (text, offsets, evidence)
    findings.py       # Finding / Evidence / Severity / Span models; JSON + SARIF serializers
  ucd/                # Script/Script_Extensions, Identifier_Status/Type, bidi classes (stdlib lacks these)
  inspect.py  detect.py  sanitize.py  profiles/
  confusable/         # skeleton, bidiSkeleton, mixed-script, restriction levels, Guard + matcher
  stego/              # tag, VS, zero-width binary, PUA, whitespace channels: detect + decode
  net/                # IDN / URL / email
  redteam/            # mutators, corpora, robustness harness
  tokenizers/         # exposure audit (optional extras: tiktoken, tokenizers, sentencepiece)
  integrations/       # pyrit, garak, promptfoo, anthropic, openai, langchain, llamaindex, fastapi, pydantic, logging
  mcp/                # MCP server + manifest scanner
  cli/
scripts/gen_data.py   # regenerate _data for a pinned Unicode version
bench/                # GlyphBench harness + datasets
```

Design rules:

- **Data-driven.** Techniques, mappings and profiles are data, not code. This makes
  community contributions easy and a later Rust port mechanical. Test vectors live in a
  language-neutral format, so every port must pass the same conformance suite.
- **Offset fidelity.** Every transform keeps a map back to the original string, so
  findings point at real spans and grapheme clusters.
- **Never destroy information silently.** Sanitizers return what they removed or changed.
  Detection and sanitization are separate calls.
- **Script-respectful.** Native Cyrillic, Arabic, Devanagari and other text passes by
  default. Risk comes from *mixing* scripts, *confusing* text against something, and
  *invisible* content, not from being non-Latin.
- **Pinned Unicode version.** Data is vendored with `UNICODE_VERSION`. The library warns
  when the stdlib `unicodedata` is older, or can optionally use `unicodedata2`. Stored
  skeletons must be recomputed on upgrade, and this is documented.
- **Fast path.** An ASCII-only or already-clean string returns in about the time of a
  regex check. Zero required dependencies; integrations are extras.
- **Extensible.** Entry-point plugins for custom techniques, mappings, profiles and
  integrations.

## 8. Hard problems

| Problem | Approach |
|---|---|
| False positives vs. legitimate text: emoji ZWJ sequences, flag tag sequences (🏴󠁧󠁢󠁳󠁣󠁴󠁿 uses tags), VS16 emoji presentation, ZWNJ in Persian, combining marks in Indic scripts, RTL marks in Arabic/Hebrew UIs | Grapheme- and context-aware rules: a tag sequence is *valid* only after U+1F3F4 and must end with U+E007F, a VS is valid only after its standardized base, and ZWNJ is valid between joining letters. Severity tiers instead of binary verdicts. Every rule gets a benign-corpus test. |
| Substring and evasion matching against protected terms | Offset-mapped skeleton with term-side expansion (leet classes, optional fillers, repetition). Aho-Corasick fast path, regex/NFA slow path. Per-term mode: `contains` / `word` / `exact`. |
| Bidi correctness | Implement UBA levels for `bidiSkeleton` and the dual view. Vendor a minimal UBA or use the `python-bidi` extra. |
| Unicode version drift | Pinned data, a generation script, a CI job that diffs each new Unicode release, and a published changelog of the catalog per version |
| Tokenizer and vendor drift | The tokenizer audit and red-team harness double as scheduled regression jobs, with results published in GlyphBench |
| Performance at scale (RAG ingestion, email) | Precompiled tables, per-character `lru_cache`, ASCII fast path. Benchmark-driven decision on the Rust core. |
| Dual-use concerns | Publish only documented techniques, keep a clear responsible-use policy, and pair every mutator with a detector |

## 9. Roadmap

Ordered for fastest real-world value. The AI-input and code-scanning use cases need the
invisible/bidi/smuggling layer first; the confusable matcher builds on the same engine.

| Release | Scope | Exit criteria |
|---|---|---|
| **v0.1 — Foundation** | Project scaffold (hatchling, ruff, mypy strict, pytest + hypothesis, CI on 3.11–3.14 × Linux/Win/mac); `gen_data.py`; catalog format; pipeline with offset maps; `inspect`; INV / SMUG / BIDI / CTRL / MARK detection; `sanitize` with `llm-input`, `display-name` and `strict` profiles; CLI `inspect`, `detect`, `sanitize` | All INV/SMUG/BIDI techniques detected with correct spans. Benign corpus (emoji ZWJ, flags, Persian, Indic, Arabic) produces zero high-severity findings. |
| **v0.2 — Confusables** | TR39 skeleton/bidiSkeleton, mixed-script, restriction levels, `canonicalize`, extended maps beyond TR39, `Guard` protected-term matcher, `net` hostname checks | Differential agreement with PyICU on a large corpus. Every row of §5 caught under `strict`. |
| **v0.3 — Forensics & scanning** | `stego.decode` for all channels, dual view, `scan` for files and repos, SARIF, pre-commit hook, GitHub Action, agent-config presets (rules, skills, CLAUDE.md, AGENTS.md, MCP manifests) | Detects published samples: Rules File Backdoor, GlassWorm-style payloads, Trojan Source, tag-smuggling phishing |
| **v0.4 — Red team** | `redteam` mutators (one per catalog technique), PyRIT/garak/promptfoo adapters, corpus export, robustness harness, tokenizer exposure audit | Reproduces the published evasion classes against open guardrails (e.g. Prompt Guard), measured with and without GlyphGuard |
| **v0.5 — AI integrations** | Anthropic/OpenAI wrappers, LangChain/LlamaIndex, ASGI middleware, output sanitizer (tags, ANSI/OSC), `glyphguard-mcp` server, MCP tool-description pin/diff | End-to-end examples: RAG ingestion, agent tool output, terminal output |
| **v0.6 — GlyphBench** | Public dataset and leaderboard, write-up or paper, playground page | Reproducible comparison against ICU, NFKC, Unidecode, decancer, disarm, prompt-canon and LLM Guard |
| **v1.0** | API freeze, docs site, `SECURITY.md`, catalog versioning policy | Stable semver |
| **Post-1.0** | Rust core and WASM/JS package, VS Code extension, font-aware confusable builder, more languages | Driven by benchmarks and demand |

## 10. Decisions

Made while building v0.1 (2026-10-13); revisit any of them deliberately.

| Decision | Choice | Why |
|---|---|---|
| Implementation language | Python reference implementation first; Rust core later | Prove the design before paying the port cost. The catalog (`catalog.toml`), profiles (`profiles.toml`) and conformance vectors (`tests/vectors/*.toml`) are language-neutral, so a port inherits them. |
| License | Apache-2.0 | Patent grant, enterprise-friendly. Unicode data notice is in `NOTICE`. Easy to change before the first release. |
| Minimum Python | 3.11 | 3.10 reaches end of life this month. 3.11 brings `tomllib`. |
| Unicode data | Vendored UCD 18.0.0 tables, pinned and checksummed, with no `unicodedata2` dependency | The stdlib has no Script property and lags in version (the test machine's 3.11 is Unicode 14). `unicodedata` is only used for character names. |
| Performance | One precompiled scan for "interesting" code points; marks found by linear-time seed patterns | 0.8 to 7-15 M code points/s on non-ASCII text, and about 600 M/s on ASCII. Revisit with the Rust core. |

Still open:

1. **Mutator distribution.** Ship the red-team mutators in the core package, or as
   `glyphguard[redteam]`.

## 11. Progress

**v0.1 Foundation: done, apart from publishing.**

- Catalog of 25 techniques: INV x10, SMUG x4, BIDI x4, CTRL x4, MARK x3.
- `detect`, `payloads`, `inspect`, `sanitize` (5 profiles), `reveal`.
- `stego` encoders and decoders: tags, variation selectors, zero-width binary.
- CLI: `inspect`, `detect`, `sanitize`, `catalog`.
- `scripts/gen_data.py`; CI workflow; pre-commit hook definition.
- 311 tests: conformance vectors, a benign multilingual corpus, Hypothesis property
  tests (idempotent sanitization, valid spans, stego round trips), CLI tests, and a
  repo-hygiene test that runs GlyphGuard on its own sources.

Lesson from building it: the tooling that wrote these files silently turned Unicode escape
sequences into literal characters, including RLO overrides and zero-width spaces. The
hygiene test caught every case. That is the strongest argument yet for the `scan` and
pre-commit surfaces in v0.3.

Public-release prep: brand identity (glitch wordmark, mark, social card, terminal demo
via scripts/make_brand.py), README with executable examples, CONTRIBUTING, SECURITY,
CHANGELOG, issue forms for missed attacks and false positives, binary-file skipping in
`detect`.

Not yet done from v0.1's list: PyPI publishing (the name `glyphguard` was still available
on 2026-10-13).

Next: **v0.2 Confusables**. TR39 skeleton/bidiSkeleton, mixed-script detection,
restriction levels, `canonicalize`, extended maps, and the `Guard` protected-term matcher.
