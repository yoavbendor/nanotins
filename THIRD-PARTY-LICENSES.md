# Third-party licenses

nanotins is licensed under Apache-2.0 (see [LICENSE](LICENSE)). It depends on the
following third-party software, all under permissive, Apache-2.0-compatible
licenses. These are pulled in at build time via CMake `FetchContent` and are **not**
redistributed in this repository; their license terms apply to those components.

| Component | Used by | License | Project |
|---|---|---|---|
| Apache Arrow nanoarrow | soatins (`to_arrow` / Arrow schema + array output) | Apache-2.0 | https://github.com/apache/arrow-nanoarrow |
| NVIDIA stdexec | nanotins (`bulk_for_each` over `ex::bulk`) | Apache-2.0 | https://github.com/NVIDIA/stdexec |
| Boost.Describe / MP11 (+ config, assert, preprocessor) | soatins (compile-time reflection) | BSL-1.0 | https://www.boost.org/ |

License compatibility: Apache-2.0, the Boost Software License 1.0, and the
Apache-2.0 components above are all permissive and mutually compatible.
