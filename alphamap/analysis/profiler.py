"""
File profiler: combines type detection and entropy analysis into a
single :class:`~alphamap.core.types.FileProfile` dataclass.

The profiler reads only the first ``SAMPLE_BYTES`` of the file,
so it stays fast even on large inputs.  The strategy selector
consumes FileProfile to choose the best compression backend.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from .detector import detect_bytes_type, is_utf8, mime_hint
from .entropy import entropy as compute_entropy, repetition_score
from ..core.constants import SAMPLE_BYTES
from ..core.types import FileProfile, FileType


def profile_file(path: Union[str, Path]) -> FileProfile:
    """Profile the file at *path* and return a :class:`FileProfile`.

    Reads at most ``SAMPLE_BYTES`` bytes — fast for any file size.
    """
    path = Path(path)
    try:
        with open(path, "rb") as fh:
            sample = fh.read(SAMPLE_BYTES)
    except OSError:
        return FileProfile()

    return profile_bytes(sample, mime_hint=mime_hint(path))


def profile_bytes(
    sample: bytes,
    mime_hint: str = "",
) -> FileProfile:
    """Profile *sample* (a leading slice of file content).

    Useful when the data is already in memory (e.g. piped stdin).
    """
    if not sample:
        return FileProfile()

    file_type = detect_bytes_type(sample)
    utf8 = is_utf8(sample)
    ent = compute_entropy(sample)
    rep = repetition_score(sample)

    # Semantic score: how likely is it that our token dictionary will help?
    #   - Must be valid UTF-8 text
    #   - Low entropy → repetitive vocabulary
    #   - File type is text-like
    semantic = 0.0
    if utf8 and file_type in (FileType.TEXT, FileType.JSON, FileType.CSV, FileType.SOURCE):
        # Normalise entropy to [0, 1] where 1 = maximally compressible text
        # 8.0 bits/byte is maximum; 3.0 is typical natural language prose
        entropy_factor = max(0.0, (6.0 - ent) / 6.0)
        type_bonus = 0.3 if file_type == FileType.TEXT else 0.1
        semantic = min(1.0, entropy_factor + type_bonus)

    return FileProfile(
        file_type=file_type,
        entropy=round(ent, 4),
        repetition_score=round(rep, 4),
        semantic_score=round(semantic, 4),
        sample_size=len(sample),
        is_utf8=utf8,
        mime_type=mime_hint,
    )
