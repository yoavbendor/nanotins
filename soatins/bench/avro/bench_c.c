/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Yoav Bendor
 *
 * avro-c benchmark (generic/dynamic value API -- avro-c's "specific" API would be faster but requires
 * codegen from the schema, which defeats the point of this comparison). See ../README.md for the row
 * schema/formulas this must match across all four language variants.
 */
#include <avro.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static const char SCHEMA_JSON[] =
    "{"
    "\"type\":\"record\",\"name\":\"WideRow\",\"fields\":["
    "{\"name\":\"id\",\"type\":\"long\"},"
    "{\"name\":\"s8\",\"type\":\"int\"},"
    "{\"name\":\"u8f\",\"type\":\"int\"},"
    "{\"name\":\"s16\",\"type\":\"int\"},"
    "{\"name\":\"u16f\",\"type\":\"int\"},"
    "{\"name\":\"s32\",\"type\":\"int\"},"
    "{\"name\":\"u32f\",\"type\":\"long\"},"
    "{\"name\":\"s64\",\"type\":\"long\"},"
    "{\"name\":\"u64f\",\"type\":\"long\"},"
    "{\"name\":\"f1\",\"type\":\"float\"},"
    "{\"name\":\"f2\",\"type\":\"float\"},"
    "{\"name\":\"d1\",\"type\":\"double\"},"
    "{\"name\":\"d2\",\"type\":\"double\"},"
    "{\"name\":\"b1\",\"type\":\"boolean\"},"
    "{\"name\":\"b2\",\"type\":\"boolean\"},"
    "{\"name\":\"b3\",\"type\":\"boolean\"}"
    "]}";

static void set_int_field(avro_value_t* rec, const char* name, int32_t v) {
    avro_value_t field;
    size_t idx;
    avro_value_get_by_name(rec, name, &field, &idx);
    avro_value_set_int(&field, v);
}
static void set_long_field(avro_value_t* rec, const char* name, int64_t v) {
    avro_value_t field;
    size_t idx;
    avro_value_get_by_name(rec, name, &field, &idx);
    avro_value_set_long(&field, v);
}
static void set_float_field(avro_value_t* rec, const char* name, float v) {
    avro_value_t field;
    size_t idx;
    avro_value_get_by_name(rec, name, &field, &idx);
    avro_value_set_float(&field, v);
}
static void set_double_field(avro_value_t* rec, const char* name, double v) {
    avro_value_t field;
    size_t idx;
    avro_value_get_by_name(rec, name, &field, &idx);
    avro_value_set_double(&field, v);
}
static void set_bool_field(avro_value_t* rec, const char* name, int v) {
    avro_value_t field;
    size_t idx;
    avro_value_get_by_name(rec, name, &field, &idx);
    avro_value_set_boolean(&field, v);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <out-file> <n-rows>\n", argv[0]);
        return 2;
    }
    const char* out_path = argv[1];
    long n = atol(argv[2]);

    avro_schema_t schema;
    if (avro_schema_from_json_length(SCHEMA_JSON, sizeof(SCHEMA_JSON) - 1, &schema)) {
        fprintf(stderr, "schema parse failed: %s\n", avro_strerror());
        return 1;
    }

    avro_file_writer_t writer;
    if (avro_file_writer_create_with_codec(out_path, schema, &writer, "null", 0)) {
        fprintf(stderr, "writer create failed: %s\n", avro_strerror());
        return 1;
    }

    avro_value_iface_t* iface = avro_generic_class_from_schema(schema);
    avro_value_t value;
    avro_generic_value_new(iface, &value);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (long i = 0; i < n; ++i) {
        set_long_field(&value, "id", (int64_t)(uint32_t)i);
        set_int_field(&value, "s8", (int32_t)(i % 256) - 128);
        set_int_field(&value, "u8f", (int32_t)(i % 256));
        set_int_field(&value, "s16", (int32_t)(i % 65536) - 32768);
        set_int_field(&value, "u16f", (int32_t)(i % 65536));
        set_int_field(&value, "s32", (int32_t)(i * 3 - 100000));
        set_long_field(&value, "u32f", (int64_t)(uint32_t)(i * 7));
        set_long_field(&value, "s64", -(int64_t)i * 123456789LL);
        set_long_field(&value, "u64f", (int64_t)((uint64_t)i * 987654321ULL));
        set_float_field(&value, "f1", (float)i * 0.5f);
        set_float_field(&value, "f2", -(float)i * 1.25f);
        set_double_field(&value, "d1", (double)i * 2.718281828);
        set_double_field(&value, "d2", -(double)i * 3.14159265);
        set_bool_field(&value, "b1", (i % 2) == 0);
        set_bool_field(&value, "b2", (i % 3) == 0);
        set_bool_field(&value, "b3", (i % 5) == 0);

        if (avro_file_writer_append_value(writer, &value)) {
            fprintf(stderr, "append failed: %s\n", avro_strerror());
            return 1;
        }
    }

    avro_file_writer_flush(writer);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("c avro-c: wrote %ld rows in %.2f ms (%.1f ns/row)\n", n, ms, ms * 1e6 / (double)n);

    avro_value_decref(&value);
    avro_value_iface_decref(iface);
    avro_file_writer_close(writer);
    avro_schema_decref(schema);
    return 0;
}
