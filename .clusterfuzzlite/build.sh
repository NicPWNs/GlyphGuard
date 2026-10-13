#!/bin/bash -eu
# Build GlyphGuard's fuzz targets for ClusterFuzzLite (runs inside the build image).

# GlyphGuard has no runtime dependencies; install it from this checkout.
pip3 install --no-deps .

for fuzzer in "$SRC"/glyphguard/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
