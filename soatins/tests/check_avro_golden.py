#!/usr/bin/env python3
"""Golden-file check for soatins/avro_glue.hpp.

Runs the gen_avro_golden C++ binary (built via avro_glue's reflection-driven avro_schema_json<T>() /
to_avro_bytes<T>()), then decodes its output with fastavro -- an independent, real Avro client -- and
asserts the field values round-trip. This is the cross-check that the no-codegen encoder actually speaks
Avro's wire format, not just something our own code agrees with itself on.
"""
import json
import math
import subprocess
import sys
from pathlib import Path

from fastavro import schemaless_reader

EXPECTED = {
    "id": 0xAABBCCDD,
    "counter": -123456789012,
    "score": 3.5,
    "weight": 2.718281828,
    "active": True,
    "addr": bytes([192, 168, 1, 42]),
}


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <gen_avro_golden-binary> <out-dir>", file=sys.stderr)
        return 2
    gen_bin, out_dir = sys.argv[1], Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    subprocess.run([gen_bin, str(out_dir)], check=True)

    schema = json.loads((out_dir / "golden.avsc").read_text())
    with open(out_dir / "golden.bin", "rb") as f:
        record = schemaless_reader(f, schema)

    for key, want in EXPECTED.items():
        got = record[key]
        if isinstance(want, float):
            ok = math.isclose(got, want, rel_tol=1e-6)
        else:
            ok = got == want
        if not ok:
            print(f"FAIL: field {key!r}: fastavro decoded {got!r}, expected {want!r}", file=sys.stderr)
            return 1

    print(f"avro golden ok: fastavro decoded {record} matching schema {schema['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
