#!/usr/bin/env python3
"""Rewrites the "Latest run" section of README.md (between the BENCH_RESULTS markers) from this run's
bench_* stdout lines. Only called by run_bench.sh after verify.py has confirmed every output file's rows
match the WideRow formula -- a result never lands in the README unless it was cross-checked first."""
import argparse
import datetime
import platform
import re
import subprocess
from pathlib import Path

START = "<!-- BENCH_RESULTS_START -->"
END = "<!-- BENCH_RESULTS_END -->"
NS_RE = re.compile(r"\(([\d.]+) ns/row\)")


def parse_ns(line: str) -> float:
    m = NS_RE.search(line)
    if not m:
        raise ValueError(f"couldn't find '(... ns/row)' in: {line!r}")
    return float(m.group(1))


def cpu_model() -> str:
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def git_rev(readme_dir: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=readme_dir, capture_output=True, text=True, check=True
        )
        return out.stdout.strip()
    except Exception:
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--cpp", required=True)
    ap.add_argument("--c", required=True)
    ap.add_argument("--rust", required=True)
    ap.add_argument("--python", required=True)
    args = ap.parse_args()

    readme_path = Path(__file__).parent / "README.md"

    results = {
        "C++ `avro_glue.hpp`": parse_ns(args.cpp),
        "C `avro-c` (generic)": parse_ns(args.c),
        "Rust `apache-avro` (serde)": parse_ns(args.rust),
        "Python `fastavro`": parse_ns(args.python),
    }
    fastest = min(results.values())

    lines = [
        START,
        "",
        f"Last run: {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M UTC}, "
        f"commit `{git_rev(readme_path.parent)}`, {args.n:,} rows, on `{cpu_model()}`.",
        "",
        "| writer | ns/row | rows/sec | vs fastest |",
        "|---|---|---|---|",
    ]
    for name, ns in sorted(results.items(), key=lambda kv: kv[1]):
        mult = ns / fastest
        mult_str = "1.0x (fastest)" if mult == 1.0 else f"{mult:.1f}x"
        lines.append(f"| {name} | {ns:.1f} | {1e9/ns:,.0f} | {mult_str} |")
    lines += ["", END]

    text = readme_path.read_text()
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(text):
        raise SystemExit(f"markers {START!r}/{END!r} not found in {readme_path}")
    readme_path.write_text(pattern.sub("\n".join(lines), text))
    print(f"updated {readme_path} with latest results")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
