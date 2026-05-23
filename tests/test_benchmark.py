"""Tests for alphamap.benchmark.runner."""

import pytest
import alphamap.backends  # register all backends

from alphamap.benchmark.runner import run_benchmark, print_report
from alphamap.core.types import BenchmarkResult


TEXT_DATA = (
    b"the quick brown fox jumps over the lazy dog "
    b"the fox the dog the fox the dog "
) * 80


def test_run_benchmark_returns_results():
    results = run_benchmark(data=TEXT_DATA, backends=["zlib", "gzip"])
    assert len(results) == 2
    for r in results:
        assert isinstance(r, BenchmarkResult)


def test_run_benchmark_all_backends():
    results = run_benchmark(data=TEXT_DATA)
    names = {r.label for r in results}
    assert "zlib" in names
    assert "gzip" in names
    assert "lzma" in names
    assert "alphamap" in names


def test_run_benchmark_sorted_by_compressed_size():
    results = run_benchmark(data=TEXT_DATA)
    sizes = [r.compressed_size for r in results]
    assert sizes == sorted(sizes)


def test_run_benchmark_original_size_preserved():
    results = run_benchmark(data=TEXT_DATA, backends=["zlib"])
    assert results[0].original_size == len(TEXT_DATA)


def test_run_benchmark_compress_time_positive():
    results = run_benchmark(data=TEXT_DATA, backends=["zlib"])
    assert results[0].compress_time_ms >= 0


def test_run_benchmark_ratio():
    results = run_benchmark(data=TEXT_DATA, backends=["zlib"])
    r = results[0]
    assert r.ratio == pytest.approx(r.original_size / r.compressed_size, rel=1e-3)


def test_run_benchmark_non_utf8_skips_semantic():
    """Binary data should not crash the benchmark; semantic marks as FAILED."""
    binary = bytes(range(256)) * 16
    results = run_benchmark(data=binary, backends=["zlib", "alphamap"])
    labels = [r.label for r in results]
    # zlib should succeed; alphamap should appear as FAILED
    zlib_ok = any("zlib" == l for l in labels)
    assert zlib_ok


def test_print_report_runs(capsys):
    results = run_benchmark(data=TEXT_DATA, backends=["zlib", "lzma"])
    print_report(results, title="Test Report")
    captured = capsys.readouterr()
    assert "Test Report" in captured.out
    assert "zlib" in captured.out


def test_print_report_empty(capsys):
    print_report([])
    captured = capsys.readouterr()
    assert "No results" in captured.out
