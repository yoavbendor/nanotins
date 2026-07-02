#!/usr/bin/env python3
"""Cross-check every bench_*'s output file against the WideRow formula in README.md, using fastavro (an
independent Avro client) as the reader. Exits non-zero on the first mismatch."""
import math
import sys

from fastavro import reader


def expected_row(i: int) -> dict:
    return {
        "id": i,
        "s8": (i % 256) - 128,
        "u8f": i % 256,
        "s16": (i % 65536) - 32768,
        "u16f": i % 65536,
        "s32": i * 3 - 100000,
        "u32f": i * 7,
        "s64": -i * 123456789,
        "u64f": i * 987654321,
        "f1": i * 0.5,
        "f2": -i * 1.25,
        "d1": i * 2.718281828,
        "d2": -i * 3.14159265,
        "b1": (i % 2) == 0,
        "b2": (i % 3) == 0,
        "b3": (i % 5) == 0,
    }


def check_file(path: str, n: int) -> bool:
    with open(path, "rb") as f:
        records = list(reader(f))
    if len(records) != n:
        print(f"FAIL {path}: expected {n} records, got {len(records)}", file=sys.stderr)
        return False
    for i, record in enumerate(records):
        want = expected_row(i)
        for key, wv in want.items():
            gv = record[key]
            ok = math.isclose(gv, wv, rel_tol=1e-5) if isinstance(wv, float) else gv == wv
            if not ok:
                print(f"FAIL {path}: row {i} field {key!r}: got {gv!r}, expected {wv!r}", file=sys.stderr)
                return False
    print(f"OK {path}: {n} records match the WideRow formula")
    return True


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <n-rows> <file>...", file=sys.stderr)
        return 2
    n = int(sys.argv[1])
    ok = True
    for path in sys.argv[2:]:
        ok = check_file(path, n) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
