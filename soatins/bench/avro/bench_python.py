#!/usr/bin/env python3
"""fastavro benchmark. See ../README.md for the row schema/formulas this must match across all four
language variants."""
import sys
import time

import fastavro

SCHEMA = {
    "type": "record",
    "name": "WideRow",
    "fields": [
        {"name": "id", "type": "long"},
        {"name": "s8", "type": "int"},
        {"name": "u8f", "type": "int"},
        {"name": "s16", "type": "int"},
        {"name": "u16f", "type": "int"},
        {"name": "s32", "type": "int"},
        {"name": "u32f", "type": "long"},
        {"name": "s64", "type": "long"},
        {"name": "u64f", "type": "long"},
        {"name": "f1", "type": "float"},
        {"name": "f2", "type": "float"},
        {"name": "d1", "type": "double"},
        {"name": "d2", "type": "double"},
        {"name": "b1", "type": "boolean"},
        {"name": "b2", "type": "boolean"},
        {"name": "b3", "type": "boolean"},
    ],
}


def gen_rows(n):
    for i in range(n):
        yield {
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


def main():
    out_path, n = sys.argv[1], int(sys.argv[2])
    with open(out_path, "wb") as f:
        t0 = time.perf_counter()
        fastavro.writer(f, SCHEMA, gen_rows(n), codec="null")
        dt = time.perf_counter() - t0
    print(f"python fastavro: wrote {n} rows in {dt*1000:.2f} ms ({dt*1e9/n:.1f} ns/row)")


if __name__ == "__main__":
    main()
