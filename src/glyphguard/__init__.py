"""GlyphGuard: see what the machine sees.

Unicode security for humans, filters, and models. GlyphGuard finds, explains and
neutralizes the characters that make text look different to people than it does to
programs and language models: invisible characters, smuggled payloads, bidirectional
reordering, terminal escapes and stacked combining marks.

    >>> import glyphguard as gg
    >>> [f.technique_id for f in gg.detect("pay\\u200bpal")]
    ['GG-INV-001']
    >>> gg.sanitize("pay\\u200bpal").text
    'paypal'
"""

from importlib import metadata as _metadata

from glyphguard import stego
from glyphguard.catalog import Severity, Technique, techniques
from glyphguard.detect import Options, detect, payloads
from glyphguard.findings import Finding, Payload
from glyphguard.report import CharInfo, Report, inspect
from glyphguard.sanitize import Change, Profile, SanitizeResult, profiles, reveal, sanitize
from glyphguard.ucd import UNICODE_VERSION

try:
    __version__ = _metadata.version("glyphguard")
except _metadata.PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0.0.0"

__all__ = [
    "UNICODE_VERSION",
    "Change",
    "CharInfo",
    "Finding",
    "Options",
    "Payload",
    "Profile",
    "Report",
    "SanitizeResult",
    "Severity",
    "Technique",
    "__version__",
    "detect",
    "inspect",
    "payloads",
    "profiles",
    "reveal",
    "sanitize",
    "stego",
    "techniques",
]
