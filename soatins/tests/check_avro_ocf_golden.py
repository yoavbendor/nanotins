#!/usr/bin/env python3
"""Golden-file check for soatins/avro_glue.hpp's OCF streaming writer (avro_ocf_writer<T>).

Runs gen_avro_ocf_golden (a column_sink<T,N> streaming rows through avro_ocf_writer::write_block, one
Avro data block per flushed chunk), then reads the whole file back with fastavro.reader() -- which locates
the schema once from the file header and iterates every block via the sync marker -- and asserts every row
round-trips, in order, across block boundaries. This is the cross-check that streaming many chunks without
resending the schema actually produces a valid multi-block Avro Object Container File, not just a single
record that happens to decode.
"""
import math
import subprocess
import sys
from pathlib import Path

from fastavro import reader

K = 10


def expected_row(i: int) -> dict:
    return {
        "id": i * 5 + 2,
        "value": i * 1.25,
        "flag": (i % 2) == 0,
        "tag": bytes([i % 256, (i + 1) % 256]),
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <gen_avro_ocf_golden-binary> <out-file>", file=sys.stderr)
        return 2
    gen_bin, out_file = sys.argv[1], Path(sys.argv[2])
    out_file.parent.mkdir(parents=True, exist_ok=True)

    subprocess.run([gen_bin, str(out_file)], check=True)

    with open(out_file, "rb") as f:
        records = list(reader(f))

    if len(records) != K:
        print(f"FAIL: expected {K} records, got {len(records)}", file=sys.stderr)
        return 1

    for i, record in enumerate(records):
        want = expected_row(i)
        for key, wv in want.items():
            gv = record[key]
            ok = math.isclose(gv, wv, rel_tol=1e-6) if isinstance(wv, float) else gv == wv
            if not ok:
                print(f"FAIL: row {i} field {key!r}: fastavro decoded {gv!r}, expected {wv!r}", file=sys.stderr)
                return 1

    print(f"avro OCF golden ok: fastavro streamed {len(records)} records across multiple blocks, in order")
    return 0


if __name__ == "__main__":
    sys.exit(main())
