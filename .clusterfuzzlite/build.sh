#!/bin/bash -eu
# Build GlyphGuard's fuzz targets for ClusterFuzzLite (runs inside the build image).

# GlyphGuard is pure Python with no runtime dependencies, so it is bundled straight from
# this checkout's src/ (no pip install, so nothing unpinned enters the build).
export PYTHONPATH="$SRC/glyphguard/src"

for fuzzer in "$SRC"/glyphguard/fuzz/fuzz_*.py; do
  # The fuzzer is bundled with PyInstaller, which needs telling where the package is and
  # about its data files (catalog.toml, profiles.toml).
  compile_python_fuzzer "$fuzzer" --paths "$SRC/glyphguard/src" --collect-data glyphguard
done
