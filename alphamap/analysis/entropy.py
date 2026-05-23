"""
Shannon entropy estimation for byte sequences.

Used by the file profiler to determine whether data is worth compressing,
and which compression strategy is most likely to succeed.

entropy() returns bits per byte in the range [0.0, 8.0]:
    0.0 — every byte is identical (maximum compressibility)
    8.0 — perfectly random / already compressed (incompressible)
"""

import math
from collections import Counter


def entropy(data: bytes) -> float:
    """Return the Shannon entropy of *data* in bits per byte.

    Returns 0.0 for empty input.

    This is a fast single-pass implementation using a Counter.
    For large files, call on a representative sample (see SAMPLE_BYTES).
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def repetition_score(data: bytes) -> float:
    """Return a [0.0, 1.0] score for byte-level repetition.

    1.0 means every byte is the same; 0.0 means every byte is unique.
    Used as a fast secondary signal — high repetition means the semantic
    or zlib backends will do well.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    most_common_count = counts.most_common(1)[0][1]
    return most_common_count / len(data)
