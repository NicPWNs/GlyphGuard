"""Coverage-guided fuzz target for GlyphGuard (Atheris, run by ClusterFuzzLite).

Feeds arbitrary Unicode text to detection, sanitization, reveal, SARIF output, protected
term matching, skeletons, hostname checks and escape decoding, and checks the invariants
the rest of the toolkit relies on. Any exception is a finding.

Run locally (Linux or macOS): pip install atheris && python fuzz/fuzz_glyphguard.py
"""

from __future__ import annotations

import json
import sys

try:
    import atheris
except ImportError:  # the invariants are also exercised by tests/test_fuzz_harness.py
    atheris = None

if atheris is not None:
    with atheris.instrument_imports():
        import glyphguard as gg
        from glyphguard import stego
        from glyphguard.catalog import Severity
        from glyphguard.escapes import detect_escaped
        from glyphguard.sarif import Located, to_sarif
else:
    import glyphguard as gg
    from glyphguard import stego
    from glyphguard.catalog import Severity
    from glyphguard.escapes import detect_escaped
    from glyphguard.sarif import Located, to_sarif

PROFILES = tuple(gg.profiles())
GUARDS = tuple(gg.Guard(["admin", "pay pal"], mode=mode) for mode in ("word", "contains", "exact"))


def check(text: str) -> None:
    """Assert GlyphGuard's invariants for one input."""
    findings = gg.detect(text)
    assert findings == sorted(findings, key=lambda f: (f.start, f.end, f.technique_id))
    for f in findings:
        assert 0 <= f.start < f.end <= len(text), (f.technique_id, f.start, f.end, len(text))
        assert f.codepoints == tuple(ord(c) for c in text[f.start : f.end])
        assert f.message.isascii(), f.message

    for profile in PROFILES:
        once = gg.sanitize(text, profile).text
        assert gg.sanitize(once, profile).text == once, profile

    revealed = gg.reveal(text)
    assert not [f for f in gg.detect(revealed) if f.severity >= Severity.LOW], revealed

    located = [Located("fuzz.txt", f, 1, 1, 1, 2) for f in findings]
    json.dumps(to_sarif(located, version="0"))

    stego.decode_tags(text)
    stego.decode_variation_selectors(text)
    stego.decode_binary(text[:256])

    for guard in GUARDS:
        for m in guard.check(text).matches:
            assert 0 <= m.start < m.end <= len(text), (m.term, m.start, m.end, len(text))
            assert all(m.start <= e.index < m.end for e in m.evidence), m
    key = gg.canonicalize(text)
    assert gg.canonicalize(key) == key
    skeleton = gg.skeleton(text)
    assert gg.skeleton(skeleton) == skeleton
    gg.restriction_level(text)
    for f in detect_escaped(text):
        assert 0 <= f.start < f.end <= len(text), (f.technique_id, f.start, f.end, len(text))
        assert f.message.isascii(), f.message
    for value in (text[:253], "https://" + text[:200]):
        json.dumps(gg.net.check_url(value, protect=["example.com"]).to_dict())
        if value:
            json.dumps(gg.net.check_hostname(value).to_dict())


def test_one_input(data: bytes) -> None:
    provider = atheris.FuzzedDataProvider(data)
    check(provider.ConsumeUnicode(4096))


def main() -> None:
    if atheris is None:
        raise SystemExit("pip install atheris to run the fuzzer")
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
