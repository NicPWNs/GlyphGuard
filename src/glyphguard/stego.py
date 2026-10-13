"""Encoders and decoders for invisible-text smuggling channels.

The decoders let defenders see *what* was hidden, not just that something was. The
encoders exist so detectors and sanitizers can be tested against real payloads; only use
them on systems you own or are authorized to test.
"""

from __future__ import annotations

from collections import Counter

TAG_BASE = 0xE0000
TAG_CANCEL = 0xE007F
_VS_LOW = 0xFE00  # VS1..VS16 carry bytes 0..15
_VS_HIGH = 0xE0100  # VS17..VS256 carry bytes 16..255

DEFAULT_CARRIER = "\N{SMILING FACE WITH SMILING EYES}"
DEFAULT_ZERO = "\u200b"  # ZERO WIDTH SPACE
DEFAULT_ONE = "\u200c"  # ZERO WIDTH NON-JOINER


# --- Unicode tags (ASCII smuggling) -------------------------------------------------


def encode_tags(text: str, *, wrap: bool = False) -> str:
    """Encode printable ASCII as invisible tag characters.

    With ``wrap=True`` the result is bracketed by LANGUAGE TAG and CANCEL TAG, as some
    published proofs of concept do.
    """
    if not all(0x20 <= ord(c) <= 0x7E for c in text):
        raise ValueError("tag smuggling only carries printable ASCII")
    body = "".join(chr(TAG_BASE + ord(c)) for c in text)
    return f"\U000e0001{body}\U000e007f" if wrap else body


def decode_tags(text: str) -> bytes:
    """Recover the ASCII carried by tag characters in ``text``, ignoring everything else."""
    return bytes(ord(c) - TAG_BASE for c in text if TAG_BASE + 0x20 <= ord(c) <= TAG_BASE + 0x7E)


# --- Variation selectors (one byte per selector) ---------------------------------------


def byte_to_variation_selector(byte: int) -> str:
    return chr(_VS_LOW + byte) if byte < 16 else chr(_VS_HIGH + byte - 16)


def variation_selector_to_byte(cp: int) -> int | None:
    if _VS_LOW <= cp <= _VS_LOW + 15:
        return cp - _VS_LOW
    if _VS_HIGH <= cp <= _VS_HIGH + 239:
        return cp - _VS_HIGH + 16
    return None


def encode_variation_selectors(data: bytes | str, carrier: str = DEFAULT_CARRIER) -> str:
    """Append ``data`` to ``carrier`` as a run of variation selectors (Butler, 2025)."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return carrier + "".join(byte_to_variation_selector(b) for b in raw)


def decode_variation_selectors(text: str) -> bytes:
    """Recover bytes from every variation selector in ``text``, ignoring everything else."""
    out = bytearray()
    for c in text:
        byte = variation_selector_to_byte(ord(c))
        if byte is not None:
            out.append(byte)
    return bytes(out)


# --- Invisible binary (zero-width steganography) ----------------------------------------


def encode_binary(data: bytes | str, zero: str = DEFAULT_ZERO, one: str = DEFAULT_ONE) -> str:
    """Encode ``data`` as 8 bits per byte, most significant bit first."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return "".join(one if (byte >> bit) & 1 else zero for byte in raw for bit in range(7, -1, -1))


def decode_binary(run: str) -> bytes | None:
    """Best-effort decode of a run of invisible characters used as bits.

    Tries the common layouts: two symbols as 0/1 in 8-bit groups, and two symbols plus a
    third used as a separator between variable-length groups. Returns the most plausible
    decoding, or ``None`` if nothing decodes to mostly printable UTF-8.
    """
    symbols = [s for s, _ in Counter(run).most_common()]
    candidates: list[bytes] = []
    if len(symbols) == 2:
        for one in symbols:
            bits = "".join("1" if c == one else "0" for c in run)
            if len(bits) >= 8:
                usable = len(bits) - len(bits) % 8
                candidates.append(bytes(int(bits[i : i + 8], 2) for i in range(0, usable, 8)))
    elif len(symbols) == 3:
        for separator in symbols:
            for o in (s for s in symbols if s != separator):
                groups = [g for g in run.split(separator) if g]
                values = [int("".join("1" if c == o else "0" for c in g), 2) for g in groups]
                if values and all(0 < v <= 0x10FFFF and not 0xD800 <= v <= 0xDFFF for v in values):
                    candidates.append("".join(chr(v) for v in values).encode("utf-8"))
    best = max(candidates, key=plausibility, default=None)
    if best is not None and printable_ratio(best) >= 0.9:
        return best
    return None


def plausibility(data: bytes) -> tuple[float, int]:
    """Rank candidate decodings: most printable first, then most characters.

    The tiebreak matters because a wrong bit assignment can still form valid multibyte
    UTF-8 (inverted ``;S`` is ``\\u012c``), but it yields fewer characters.
    """
    ratio = printable_ratio(data)
    return ratio, len(data.decode("utf-8")) if ratio else 0


def printable_ratio(data: bytes) -> float:
    """Fraction of characters in ``data`` (as UTF-8) that are printable or common whitespace."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isprintable() or c in "\t\n\r")
    return good / len(text)
