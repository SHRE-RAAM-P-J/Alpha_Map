"""
AlphaMap v2 CLI.

Entry point: alphamap (registered in pyproject.toml as alphamap.cli.main:main)

Subcommands:
    compress    Compress (and optionally encrypt) a file
    decompress  Decompress (and optionally decrypt) a file
    analyze     Profile a file and print its FileProfile
    inspect     Show the header metadata of a .amap archive
    train       Train a reusable dictionary from a corpus
    benchmark   Compare compression backends on a file
"""

from __future__ import annotations

import json
import sys

try:
    import click
except ImportError:  # pragma: no cover
    print("ERROR: 'click' is not installed. Run: pip install click", file=sys.stderr)
    sys.exit(1)

from ..pipeline.engine import Pipeline
from ..analysis.profiler import profile_file
from ..backends import list_backends
from ..benchmark.runner import run_benchmark, print_report
from ..semantic.dictionary import AlphaMap
from ..core.errors import AlphaMapError


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="alphamap")
def main():
    """AlphaMap — adaptive hybrid compression engine."""


# ---------------------------------------------------------------------------
# compress
# ---------------------------------------------------------------------------

@main.command()
@click.argument("input_file", metavar="INPUT")
@click.argument("output_file", metavar="OUTPUT", required=False)
@click.option("-k", "--key", "password", default=None,
              help="Encrypt output with AES-256-GCM using this password.")
@click.option("--strategy", "backend", default=None,
              help="Force a specific backend (alphamap, zlib, gzip, brotli, lzma).")
@click.option("--no-embed-dict", is_flag=True, default=False,
              help="Don't embed the semantic dictionary in the archive.")
@click.option("-d", "--dict", "dict_path", default=None,
              help="Path to an external pre-trained dictionary (.json).")
@click.option("--json-output", is_flag=True, default=False,
              help="Print stats as JSON.")
def compress(input_file, output_file, password, backend, no_embed_dict, dict_path, json_output):
    """Compress INPUT to OUTPUT (default: INPUT + .amap)."""
    if output_file is None:
        output_file = input_file + ".amap"

    try:
        p = Pipeline(password=password)
        stats = p.compress(
            input_file, output_file,
            embed_dict=not no_embed_dict,
            dict_path=dict_path,
            force_backend=backend,
        )
    except AlphaMapError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except FileNotFoundError as exc:
        click.echo(f"File not found: {exc}", err=True)
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(stats, indent=2))
    else:
        ratio = stats["ratio"]
        saving = 100 * (1 - stats["compressed_size"] / stats["original_size"])
        click.echo(f"  Input    : {stats['original_size']:,} bytes")
        click.echo(f"  Output   : {stats['final_size']:,} bytes ({saving:.1f}% saved)")
        click.echo(f"  Ratio    : {ratio:.2f}x")
        click.echo(f"  Method   : {stats['method']}")
        if password:
            click.echo(f"  Encrypted: yes (AES-256-GCM)")
        click.echo(f"✓ {output_file}")


# ---------------------------------------------------------------------------
# decompress
# ---------------------------------------------------------------------------

@main.command()
@click.argument("input_file", metavar="INPUT")
@click.argument("output_file", metavar="OUTPUT", required=False)
@click.option("-k", "--key", "password", default=None,
              help="Decryption password (required if file was encrypted).")
@click.option("-d", "--dict", "dict_path", default=None,
              help="External dictionary (only if none was embedded).")
def decompress(input_file, output_file, password, dict_path):
    """Decompress INPUT to OUTPUT (default: INPUT without .amap suffix)."""
    if output_file is None:
        output_file = input_file.removesuffix(".amap").removesuffix(".am11")
        if output_file == input_file:
            output_file = input_file + ".out"

    try:
        p = Pipeline(password=password)
        p.decompress(input_file, output_file, dict_path=dict_path)
    except AlphaMapError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except FileNotFoundError as exc:
        click.echo(f"File not found: {exc}", err=True)
        sys.exit(1)

    click.echo(f"✓ {output_file}")


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

@main.command()
@click.argument("input_file", metavar="INPUT")
@click.option("--json-output", is_flag=True, default=False,
              help="Print profile as JSON.")
def analyze(input_file, json_output):
    """Profile INPUT and show its compression characteristics."""
    try:
        profile = profile_file(input_file)
    except FileNotFoundError:
        click.echo(f"File not found: {input_file}", err=True)
        sys.exit(1)

    if json_output:
        import dataclasses
        click.echo(json.dumps(dataclasses.asdict(profile), indent=2))
        return

    click.echo(f"File type       : {profile.file_type.value}")
    click.echo(f"MIME hint       : {profile.mime_type or '(unknown)'}")
    click.echo(f"Sample size     : {profile.sample_size:,} bytes")
    click.echo(f"UTF-8           : {'yes' if profile.is_utf8 else 'no'}")
    click.echo(f"Entropy         : {profile.entropy:.3f} bits/byte  ", nl=False)
    if profile.entropy >= 7.5:
        click.echo("[already compressed / random]")
    elif profile.entropy <= 4.0:
        click.echo("[highly compressible]")
    else:
        click.echo("[moderate]")
    click.echo(f"Repetition score: {profile.repetition_score:.3f}")
    click.echo(f"Semantic score  : {profile.semantic_score:.3f}")

    from ..strategy.selector import select_backends
    available = list_backends()
    ranked = select_backends(profile, available)
    click.echo(f"\nRecommended backend order: {' → '.join(ranked)}")


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------

@main.command()
@click.argument("archive", metavar="ARCHIVE")
@click.option("--json-output", is_flag=True, default=False,
              help="Print metadata as JSON.")
def inspect(archive, json_output):
    """Show the header metadata of an .amap ARCHIVE without decompressing."""
    try:
        p = Pipeline()
        meta = p.inspect(archive)
    except AlphaMapError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except FileNotFoundError:
        click.echo(f"File not found: {archive}", err=True)
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(meta, indent=2))
        return

    import datetime
    created = (
        datetime.datetime.fromtimestamp(meta["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        if meta["created_at"] else "(unknown)"
    )
    click.echo(f"Format version  : {meta['version']}")
    click.echo(f"Method          : {meta['method']}")
    click.echo(f"Original size   : {meta['original_size']:,} bytes")
    click.echo(f"Encrypted       : {'yes' if meta['encrypted'] else 'no'}")
    click.echo(f"Embedded dict   : {'yes' if meta['embedded_dict'] else 'no'}")
    click.echo(f"Filename hint   : {meta['filename'] or '(none)'}")
    click.echo(f"Created at      : {created}")


# ---------------------------------------------------------------------------
# train
# ---------------------------------------------------------------------------

@main.command()
@click.argument("corpus", metavar="CORPUS")
@click.argument("output_dict", metavar="OUTPUT_DICT")
@click.option("--size", "dict_size", default=4096, show_default=True,
              help="Maximum number of entries in the dictionary.")
def train(corpus, output_dict, dict_size):
    """Train a reusable dictionary from CORPUS and save to OUTPUT_DICT."""
    try:
        text = open(corpus, "r", encoding="utf-8").read()
    except FileNotFoundError:
        click.echo(f"File not found: {corpus}", err=True)
        sys.exit(1)
    except UnicodeDecodeError:
        click.echo("Error: corpus must be UTF-8 text.", err=True)
        sys.exit(1)

    am = AlphaMap(dict_limit=dict_size)
    am.train(text)
    am.save(output_dict)
    click.echo(f"Dictionary trained: {len(am.word_to_id):,} entries → {output_dict}")


# ---------------------------------------------------------------------------
# benchmark
# ---------------------------------------------------------------------------

@main.command()
@click.argument("input_file", metavar="INPUT", required=False)
@click.option("--vs", "backends_str", default=None,
              help="Comma-separated list of backends (default: all registered).")
@click.option("--json-output", is_flag=True, default=False,
              help="Print results as JSON.")
def benchmark(input_file, backends_str, json_output):
    """Benchmark compression backends on INPUT (or a built-in sample)."""
    if input_file:
        try:
            data = open(input_file, "rb").read()
            label = input_file
        except FileNotFoundError:
            click.echo(f"File not found: {input_file}", err=True)
            sys.exit(1)
    else:
        # Built-in sample: the Canterbury corpus excerpt
        data = _builtin_sample()
        label = "(built-in sample)"

    backends = None
    if backends_str:
        backends = [b.strip() for b in backends_str.split(",") if b.strip()]

    results = run_benchmark(data=data, label=label, backends=backends)

    if json_output:
        import dataclasses
        click.echo(json.dumps(
            [dataclasses.asdict(r) for r in results],
            indent=2,
        ))
        return

    print_report(results, title=f"Benchmark — {label}")


def _builtin_sample() -> bytes:
    """A ~4 KB built-in text sample for quick smoke-test benchmarks."""
    passage = (
        "The Project Gutenberg eBook of Alice's Adventures in Wonderland, "
        "by Lewis Carroll. Alice was beginning to get very tired of sitting "
        "by her sister on the bank, and of having nothing to do: once or twice "
        "she had peeped into the book her sister was reading, but it had no "
        "pictures or conversations in it, and what is the use of a book, "
        "thought Alice, without pictures or conversations? So she was "
        "considering in her own mind (as well as she could, for the hot day "
        "made her feel very sleepy and stupid), whether the pleasure of making "
        "a daisy-chain would be worth the trouble of getting up and picking "
        "the daisies, when suddenly a White Rabbit with pink eyes ran close "
        "by her. There was nothing so very remarkable in that; nor did Alice "
        "think it so very much out of the way to hear the Rabbit say to itself, "
        "Oh dear! Oh dear! I shall be late! (when she thought it over afterwards, "
        "it occurred to her that she ought to have wondered at this, but at the "
        "time it all seemed quite natural); but when the Rabbit actually took a "
        "watch out of its waistcoat-pocket, and looked at it, and then hurried on, "
        "Alice started to her feet, for it flashed across her mind that she had "
        "never before seen a rabbit with either a waistcoat-pocket, or a watch "
        "to take out of it, and burning with curiosity, she ran across the field "
        "after it, and fortunately was just in time to see it pop down a large "
        "rabbit-hole under the hedge. "
    ) * 6
    return passage.encode("utf-8")
