# ClusterFuzzLite build image for GlyphGuard's Atheris fuzz targets (see fuzz/).
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY . $SRC/glyphguard
WORKDIR $SRC/glyphguard
COPY .clusterfuzzlite/build.sh $SRC/
