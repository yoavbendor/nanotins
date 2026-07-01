// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// apache-avro benchmark using the serde `append_ser` path (skips the dynamic Record/Value builder, so
// it's the fair comparison for a struct whose shape is known at compile time -- see ../README.md).

use apache_avro::{Schema, Writer};
use serde::Serialize;
use std::env;
use std::fs::File;
use std::time::Instant;

const SCHEMA: &str = r#"
{
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
    {"name": "b3", "type": "boolean"}
  ]
}
"#;

#[derive(Serialize)]
struct WideRow {
    id: u32,
    s8: i8,
    u8f: u8,
    s16: i16,
    u16f: u16,
    s32: i32,
    u32f: u32,
    s64: i64,
    u64f: u64,
    f1: f32,
    f2: f32,
    d1: f64,
    d2: f64,
    b1: bool,
    b2: bool,
    b3: bool,
}

fn make_row(i: u64) -> WideRow {
    WideRow {
        id: i as u32,
        s8: ((i % 256) as i32 - 128) as i8,
        u8f: (i % 256) as u8,
        s16: ((i % 65536) as i32 - 32768) as i16,
        u16f: (i % 65536) as u16,
        s32: (i as i64 * 3 - 100000) as i32,
        u32f: (i * 7) as u32,
        s64: -(i as i64) * 123456789,
        u64f: i * 987654321,
        f1: i as f32 * 0.5,
        f2: -(i as f32) * 1.25,
        d1: i as f64 * 2.718281828,
        d2: -(i as f64) * 3.14159265,
        b1: i % 2 == 0,
        b2: i % 3 == 0,
        b3: i % 5 == 0,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let out_path = &args[1];
    let n: u64 = args[2].parse().unwrap();

    let schema = Schema::parse_str(SCHEMA).unwrap();
    let file = File::create(out_path).unwrap();
    let mut writer = Writer::new(&schema, file);

    let t0 = Instant::now();
    for i in 0..n {
        writer.append_ser(make_row(i)).unwrap();
    }
    writer.flush().unwrap();
    let dt = t0.elapsed();

    println!(
        "rust apache-avro (serde): wrote {} rows in {:.2} ms ({:.1} ns/row)",
        n,
        dt.as_secs_f64() * 1000.0,
        dt.as_secs_f64() * 1e9 / n as f64
    );
}
