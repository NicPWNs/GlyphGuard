"""Deceptive hostnames and URLs: lookalike domains, punycode, and userinfo tricks.

Browsers show internationalized hostnames in Unicode, so ``xn--80ak6aa92e.com`` can appear
as an all-Cyrillic word that reads as ``apple.com``. This module decodes punycode and
judges each label the way UTS #39 and browser IDN policies do.

    >>> from glyphguard.net import check_hostname
    >>> result = check_hostname("xn--80ak6aa92e.com")
    >>> result.deceptive, result.reads_as
    (True, 'apple.com')
    >>> check_hostname("m\\N{LATIN SMALL LETTER U WITH DIAERESIS}nchen.de").deceptive
    False
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from glyphguard import ucd
from glyphguard.confusables import (
    RestrictionLevel,
    ascii_lookalike,
    is_mixed_script,
    restriction_level,
    scripts_used,
)
from glyphguard.guard import canonicalize

_DOTS = str.maketrans(
    dict.fromkeys(
        "\N{IDEOGRAPHIC FULL STOP}\N{FULLWIDTH FULL STOP}\N{HALFWIDTH IDEOGRAPHIC FULL STOP}",
        ".",
    )
)


@dataclass(frozen=True, slots=True)
class LabelCheck:
    label: str
    """The label as displayed (punycode decoded)."""
    ascii: str
    """The label as sent over the wire (punycode encoded if needed)."""
    scripts: tuple[str, ...]
    restriction_level: RestrictionLevel
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "ascii": self.ascii,
            "scripts": list(self.scripts),
            "restriction_level": str(self.restriction_level),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class HostnameCheck:
    hostname: str
    """The hostname as given."""
    unicode: str
    """What a browser displays: punycode labels decoded, lowercased."""
    ascii: str
    """What is sent over the wire: non-ASCII labels punycode encoded."""
    reads_as: str
    """What the hostname passes for: every lookalike letter replaced by its ASCII twin."""
    labels: tuple[LabelCheck, ...]
    reasons: tuple[str, ...] = ()
    lookalike_of: tuple[str, ...] = field(default=())
    """Protected domains this hostname impersonates (see ``protect``)."""

    @property
    def deceptive(self) -> bool:
        return bool(self.reasons or self.lookalike_of)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "unicode": self.unicode,
            "ascii": self.ascii,
            "reads_as": self.reads_as,
            "deceptive": self.deceptive,
            "reasons": list(self.reasons),
            "lookalike_of": list(self.lookalike_of),
            "labels": [label.to_dict() for label in self.labels],
        }


def _decode_label(label: str) -> tuple[str, str, list[str]]:
    """(display form, wire form, problems) for one label."""
    problems: list[str] = []
    if label.lower().startswith("xn--"):
        try:
            shown = label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return label, label, ["invalid punycode"]
        if shown.isascii():
            problems.append("punycode that decodes to plain ASCII")
        return shown.lower(), label.lower(), problems
    shown = unicodedata.normalize("NFC", label).lower()
    try:
        wire = "xn--" + shown.encode("punycode").decode("ascii") if not shown.isascii() else shown
    except UnicodeError:
        wire = shown
    return shown, wire, problems


def _reads_as(text: str) -> str:
    return "".join(
        (ascii_lookalike(c) or c).lower() for c in text if not ucd.is_default_ignorable(ord(c))
    )


def check_label(label: str) -> LabelCheck:
    shown, wire, reasons = _decode_label(label)
    scripts = tuple(scripts_used(shown))
    level = restriction_level(shown)
    if not shown.isascii():
        letters = [c for c in shown if unicodedata.category(c)[0] == "L"]
        if any(ucd.is_default_ignorable(ord(c)) for c in shown):
            reasons.append("invisible characters")
        disallowed = [
            c
            for c in shown
            if not c.isascii()
            and not ucd.is_identifier_allowed(ord(c))
            and not ucd.is_default_ignorable(ord(c))
            and ascii_lookalike(c) is None
        ]
        if disallowed:
            labels = ", ".join(ucd.label(ord(c)) for c in dict.fromkeys(disallowed))
            reasons.append(f"characters UTS #39 does not allow in identifiers: {labels}")
        if is_mixed_script(shown) and level > RestrictionLevel.HIGHLY_RESTRICTIVE:
            reasons.append(f"mixes {' and '.join(scripts)} letters")
        elif (
            letters
            and "Latin" not in scripts
            and all(ascii_lookalike(c) is not None for c in letters)
        ):
            reasons.append(f"every {'/'.join(scripts)} letter has an ASCII lookalike")
        if any(
            unicodedata.normalize("NFKC", c) != c and ascii_lookalike(c) is not None for c in shown
        ):
            reasons.append("styled or fullwidth letters")
    return LabelCheck(shown, wire, scripts, level, tuple(dict.fromkeys(reasons)))


def check_hostname(hostname: str, *, protect: Iterable[str] = ()) -> HostnameCheck:
    """Judge a hostname: decode punycode, check each label, compare to ``protect``.

    ``protect`` lists domains to defend (``["paypal.com"]``). A hostname that isn't one
    of them (or a subdomain) is reported in ``lookalike_of`` when it passes for one, or
    for a subdomain of one, or when it starts with one (``paypal.com.evil.example``).
    """
    host = hostname.translate(_DOTS).rstrip(".")
    labels = tuple(check_label(label) for label in host.split(".") if label)
    unicode_host = ".".join(label.label for label in labels)
    ascii_host = ".".join(label.ascii for label in labels)
    reads_as = _reads_as(unicode_host)
    reasons = [f"label {label.label!r} {r}" for label in labels for r in label.reasons]
    lookalike_of = []
    key = canonicalize(unicode_host)
    for domain in protect:
        target = domain.lower().rstrip(".")
        if unicode_host == target or unicode_host.endswith("." + target):
            continue  # the real thing
        target_key = canonicalize(target)
        passes_for = key == target_key or key.endswith("." + target_key)
        if passes_for or ("." + key).find("." + target_key + ".") != -1:
            lookalike_of.append(domain)
    return HostnameCheck(
        hostname, unicode_host, ascii_host, reads_as, labels, tuple(reasons), tuple(lookalike_of)
    )


@dataclass(frozen=True, slots=True)
class URLCheck:
    url: str
    host: HostnameCheck | None
    reasons: tuple[str, ...] = ()

    @property
    def deceptive(self) -> bool:
        return bool(self.reasons) or (self.host is not None and self.host.deceptive)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "deceptive": self.deceptive,
            "reasons": list(self.reasons),
            "host": self.host.to_dict() if self.host else None,
        }


def check_url(url: str, *, protect: Iterable[str] = ()) -> URLCheck:
    """Judge a URL's hostname, plus tricks in the rest of its authority.

    ``https://paypal.com@evil.example/`` sends you to ``evil.example``: everything before
    the ``@`` is a user name. A user name that looks like a hostname is reported.
    """
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
    except ValueError as exc:  # e.g. an unclosed "[" around an IPv6 address
        return URLCheck(url, None, (f"malformed URL: {exc}",))
    reasons: list[str] = []
    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0]
        if "." in userinfo:
            reasons.append(
                f"user name {userinfo!r} looks like a hostname; the real host follows the @"
            )
    return URLCheck(url, check_hostname(host, protect=protect) if host else None, tuple(reasons))
