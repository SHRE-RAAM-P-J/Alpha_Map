"""
Benchmark runner: measures compression ratio, speed, and memory for all
registered backends against one or more datasets.

Usage (programmatic)::

    from alphamap.benchmark.runner import run_benchmark, print_report
    results = run_benchmark(data=my_bytes, label="my_corpus.txt")
    print_report(results)

Usage (from CLI)::

    alphamap benchmark corpus.txt --vs gzip,brotli,lzma,alphamap

Design:
    - No dependencies beyond stdlib + pycryptodome (already required).
    - Each backend is timed independently.
    - tracemalloc is used for peak-memory tracking.
    - Results are plain BenchmarkResult dataclasses — easy to serialise to JSON.
"""

from __future__ import annotations

import time
import tracemalloc
from typing import List, Optional

from ..backends import list_backends, get_backend
from ..backends.semantic_backend import SemanticBackend
from ..core.types import BenchmarkResult


def _time_and_memory(fn):
    """Run *fn()* once, return (result, elapsed_ms, peak_kb)."""
    tracemalloc.start()
    t0 = time.perf_counter()
    result = fn()
    elapsed_ms = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, elapsed_ms, peak // 1024


def run_benchmark(
    data: bytes,
    label: str = "input",
    backends: Optional[List[str]] = None,
) -> List[BenchmarkResult]:
    """Compress and decompress *data* with each backend; return results.

    Args:
        data:     Raw bytes to benchmark.  For SemanticBackend this should
                  be UTF-8 text; for others it can be anything.
        label:    Human-readable name for the dataset (used in reports).
        backends: Backend names to include.  Defaults to all registered.

    Returns:
        One :class:`BenchmarkResult` per backend, sorted by compression ratio
        (best first).
    """
    if backends is None:
        backends = list_backends()

    results: List[BenchmarkResult] = []
    original_size = len(data)

    for name in backends:
        try:
            backend = get_backend(name)

            # SemanticBackend needs training before compress; train on the data.
            # Use a fresh instance so each benchmark run is independent.
            if isinstance(backend, SemanticBackend):
                try:
                    text = data.decode("utf-8")
                    backend.train(text)
                except UnicodeDecodeError:
                    results.append(_failed_result(name, original_size, "not UTF-8"))
                    continue

            # --- Compress ---
            compressed, compress_ms, compress_kb = _time_and_memory(
                lambda b=backend: b.compress(data)
            )

            # --- Decompress ---
            # For SemanticBackend the same trained instance is reused.
            _, decompress_ms, decompress_kb = _time_and_memory(
                lambda b=backend, c=compressed: b.decompress(c)
            )

            peak_kb = max(compress_kb, decompress_kb)

            results.append(BenchmarkResult(
                label=name,
                original_size=original_size,
                compressed_size=len(compressed),
                compress_time_ms=round(compress_ms, 2),
                decompress_time_ms=round(decompress_ms, 2),
                peak_memory_kb=peak_kb,
            ))

        except Exception as exc:
            results.append(_failed_result(name, original_size, str(exc)))

    results.sort(key=lambda r: r.compressed_size)
    return results


def _failed_result(name: str, original_size: int, reason: str) -> BenchmarkResult:
    return BenchmarkResult(
        label=f"{name} [FAILED: {reason}]",
        original_size=original_size,
        compressed_size=original_size,  # no compression achieved
        compress_time_ms=0.0,
        decompress_time_ms=0.0,
    )


def print_report(results: List[BenchmarkResult], title: str = "Benchmark") -> None:
    """Print a formatted table of benchmark results to stdout."""
    if not results:
        print("No results.")
        return

    w_label = max(len(r.label) for r in results)
    w_label = max(w_label, 12)

    header = (
        f"{'Backend':<{w_label}}  "
        f"{'Orig (B)':>10}  "
        f"{'Comp (B)':>10}  "
        f"{'Ratio':>6}  "
        f"{'Saving':>7}  "
        f"{'Compress':>10}  "
        f"{'Decompress':>11}  "
        f"{'Mem (KB)':>9}"
    )
    sep = "-" * len(header)

    print(f"\n{title}")
    print(sep)
    print(header)
    print(sep)

    for r in results:
        print(
            f"{r.label:<{w_label}}  "
            f"{r.original_size:>10,}  "
            f"{r.compressed_size:>10,}  "
            f"{r.ratio:>6.2f}x  "
            f"{r.space_saving_pct:>6.1f}%  "
            f"{r.compress_time_ms:>9.1f}ms  "
            f"{r.decompress_time_ms:>10.1f}ms  "
            f"{r.peak_memory_kb:>8,}"
        )
    print(sep)
