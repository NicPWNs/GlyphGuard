from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from glyphguard import stego

printable_ascii = st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E))


@given(printable_ascii, st.booleans())
def test_tags_round_trip(text: str, wrap: bool) -> None:
    assert stego.decode_tags(stego.encode_tags(text, wrap=wrap)) == text.encode()


def test_tags_reject_non_ascii() -> None:
    with pytest.raises(ValueError, match="printable ASCII"):
        stego.encode_tags("caf\u00e9")


@given(st.binary())
def test_variation_selectors_round_trip(data: bytes) -> None:
    encoded = stego.encode_variation_selectors(data)
    assert encoded.startswith(stego.DEFAULT_CARRIER)
    assert stego.decode_variation_selectors(encoded) == data


@given(st.text(min_size=1, alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E)))
def test_binary_round_trip(text: str) -> None:
    assert stego.decode_binary(stego.encode_binary(text)) == text.encode()


def test_binary_with_separator_symbol() -> None:
    zero, one, sep = "\u200b", "\u200c", "\u200d"
    run = sep.join(format(ord(c), "b").replace("0", zero).replace("1", one) for c in "Hi!")
    assert stego.decode_binary(run) == b"Hi!"


def test_binary_rejects_noise() -> None:
    assert stego.decode_binary("\u200b\u200c\u200d\u2060" * 4) is None
