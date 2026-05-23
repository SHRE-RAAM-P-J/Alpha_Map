"""Tests for alphamap.semantic — BitWriter/BitReader and AlphaMap dictionary."""

import pytest
from alphamap.semantic.bitpacking import BitWriter, BitReader
from alphamap.semantic.dictionary import AlphaMap, tokenize, bits_required
from alphamap.core.errors import DictionaryError, TokenTooLongError


# ---------------------------------------------------------------------------
# tokenize
# ---------------------------------------------------------------------------

def test_tokenize_roundtrip():
    texts = [
        "Hello, world!",
        "  leading spaces",
        "trailing spaces  ",
        "multiple   interior   spaces",
        "one",
        "",
    ]
    for t in texts:
        assert "".join(tokenize(t)) == t


def test_tokenize_empty():
    assert tokenize("") == []


def test_tokenize_whitespace_tokens_preserved():
    tokens = tokenize("a b")
    assert " " in tokens


# ---------------------------------------------------------------------------
# bits_required
# ---------------------------------------------------------------------------

def test_bits_required():
    assert bits_required(0) == 1
    assert bits_required(1) == 1
    assert bits_required(2) == 2
    assert bits_required(3) == 2
    assert bits_required(4) == 3
    assert bits_required(4095) == 12
    assert bits_required(4096) == 13


# ---------------------------------------------------------------------------
# BitWriter / BitReader
# ---------------------------------------------------------------------------

def test_bitwriter_bitreader_roundtrip_simple():
    writer = BitWriter()
    writer.write_bits(0b101, 3)
    writer.write_bits(0b11, 2)
    data = writer.flush()

    reader = BitReader(data)
    assert reader.read_bits(3) == 0b101
    assert reader.read_bits(2) == 0b11


def test_bitwriter_flush_resets():
    writer = BitWriter()
    writer.write_bits(7, 3)
    data1 = writer.flush()
    data2 = writer.flush()
    assert data2 == b""
    assert len(data1) == 1


def test_bitreader_underflow():
    reader = BitReader(b"\xff")
    reader.read_bits(8)
    with pytest.raises(ValueError):
        reader.read_bits(1)


def test_bitreader_has_data():
    reader = BitReader(b"\x00")
    assert reader.has_data()
    reader.read_bits(8)
    assert not reader.has_data()


def test_bitpacking_multiple_values():
    """Pack 100 12-bit values and verify round-trip."""
    values = list(range(100))
    writer = BitWriter()
    for v in values:
        writer.write_bits(v, 12)
    data = writer.flush()

    reader = BitReader(data)
    recovered = [reader.read_bits(12) for _ in values]
    assert recovered == values


# ---------------------------------------------------------------------------
# AlphaMap dictionary
# ---------------------------------------------------------------------------

SAMPLE_TEXT = (
    "the quick brown fox jumps over the lazy dog "
    "the fox was very quick and the dog was very lazy "
    "a quick brown dog jumps over the lazy fox "
) * 10


def test_train_creates_vocabulary():
    am = AlphaMap()
    am.train(SAMPLE_TEXT)
    assert len(am.word_to_id) > 0
    assert len(am.id_to_word) == len(am.word_to_id)


def test_train_common_words_have_low_ids():
    am = AlphaMap()
    am.train(SAMPLE_TEXT)
    # "the" is the most common word — should have a low ID (fast to encode)
    assert am.word_to_id.get("the", 9999) < 10


def test_encode_decode_roundtrip():
    am = AlphaMap()
    am.train(SAMPLE_TEXT)
    tokens = tokenize(SAMPLE_TEXT)
    encoded = am.encode_tokens(tokens)
    decoded = am.decode_tokens(encoded, len(tokens))
    assert decoded == tokens


def test_encode_decode_with_oov():
    am = AlphaMap()
    am.train("hello world foo bar baz")
    tokens = tokenize("hello world XYZNONEXISTENT123")
    encoded = am.encode_tokens(tokens)
    decoded = am.decode_tokens(encoded, len(tokens))
    assert "".join(decoded) == "hello world XYZNONEXISTENT123"


def test_case_encoding_roundtrip():
    am = AlphaMap()
    am.train("hello world")
    for word, expected_case in [("hello", 0), ("Hello", 1), ("HELLO", 2)]:
        case = am.encode_case(word)
        assert case == expected_case
        restored = am.apply_case("hello", case)
        assert restored.lower() == word.lower()


def test_case_apply_lower():
    assert AlphaMap.apply_case("hello", 0) == "hello"


def test_case_apply_title():
    assert AlphaMap.apply_case("hello", 1) == "Hello"


def test_case_apply_upper():
    assert AlphaMap.apply_case("hello", 2) == "HELLO"


def test_save_and_load(tmp_path):
    am = AlphaMap()
    am.train(SAMPLE_TEXT)
    path = str(tmp_path / "dict.json")
    am.save(path)

    am2 = AlphaMap()
    am2.load(path)
    assert am2.word_to_id == am.word_to_id


def test_load_wrong_version(tmp_path):
    import json
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": 999, "limit": 4096, "words": {}}))
    am = AlphaMap()
    with pytest.raises(DictionaryError):
        am.load(str(bad))


def test_compression_is_smaller_than_original():
    """Semantic encoding should produce fewer bytes than raw UTF-8 on repetitive text."""
    am = AlphaMap()
    am.train(SAMPLE_TEXT)
    tokens = tokenize(SAMPLE_TEXT)
    encoded = am.encode_tokens(tokens)
    raw = SAMPLE_TEXT.encode("utf-8")
    assert len(encoded) < len(raw), (
        f"Expected encoding ({len(encoded)}) < raw ({len(raw)})"
    )


def test_token_too_long_raises(monkeypatch):
    from alphamap.core import constants
    monkeypatch.setattr(constants, "MAX_TOKEN_BYTES", 3)
    # Reload module to pick up patched constant
    import importlib
    import alphamap.semantic.dictionary as d
    importlib.reload(d)
    am = d.AlphaMap()
    am.train("hi")
    with pytest.raises(Exception):  # TokenTooLongError or ValueError
        am.encode_tokens(["toolongtoken"])
    importlib.reload(d)  # restore


def test_dict_limit_respected():
    am = AlphaMap(dict_limit=10)
    am.train("a b c d e f g h i j k l m n o p q r s t u v w x y z " * 5)
    assert len(am.word_to_id) <= 10
