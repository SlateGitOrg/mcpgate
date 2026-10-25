from __future__ import annotations

import json
import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mcpgate.canonical import canonical_json, digest, loads

json_scalars = st.none() | st.booleans() | st.integers(-(2**63), 2**63) | st.text(max_size=20)
json_values = st.recursive(
    json_scalars | st.floats(allow_nan=False, allow_infinity=False),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=20,
)


def test_sorted_keys_and_no_whitespace() -> None:
    assert canonical_json({"b": 1, "a": [1, 2, {"d": None, "c": True}]}) == '{"a":[1,2,{"c":true,"d":null}],"b":1}'


def test_floats_follow_jcs_shapes() -> None:
    assert canonical_json(1.0) == "1"
    assert canonical_json(-0.0) == "0"
    assert canonical_json(0.5) == "0.5"
    assert canonical_json(1e21) == "1e+21"
    assert canonical_json(1e-7) == "1e-7"


def test_string_escapes() -> None:
    assert canonical_json('a"b\\c\n\x01é') == '"a\\"b\\\\c\\n\\u0001é"'


def test_utf16_key_order() -> None:
    # U+FB01 sorts after U+1F600 in code points but before it in UTF-16 code units (JCS 3.2.3).
    assert canonical_json({"\U0001f600": 1, "ﬁ": 2}) == '{"\U0001f600":1,"ﬁ":2}'


def test_rejects_nan_and_non_string_keys() -> None:
    with pytest.raises(ValueError):
        canonical_json(math.nan)
    with pytest.raises(TypeError):
        canonical_json({1: "x"})
    with pytest.raises(TypeError):
        canonical_json({"x": object()})
    with pytest.raises(ValueError):
        loads('{"a": NaN}')


def test_rejects_excessive_depth() -> None:
    value: list[object] = []
    for _ in range(300):
        value = [value]
    with pytest.raises(ValueError):
        canonical_json(value)


@given(json_values)
def test_roundtrip_is_stable(value: object) -> None:
    text = canonical_json(value)
    assert canonical_json(json.loads(text)) == text


@given(st.dictionaries(st.text(max_size=6), json_scalars, max_size=8))
def test_digest_independent_of_insertion_order(value: dict[str, object]) -> None:
    reordered = dict(reversed(list(value.items())))
    assert digest(value) == digest(reordered)
    assert digest(value).startswith("sha256:")
