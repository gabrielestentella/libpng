#!/bin/bash -eu
#
# build.sh for libpng on OSS-Fuzz
#

################################################################################
# Enforce write support at compile time
################################################################################
export CXXFLAGS="$CXXFLAGS -DPNG_SIMPLIFIED_READ_SUPPORTED -DPNG_SIMPLIFIED_WRITE_SUPPORTED"
# export CPPFLAGS="$CPPFLAGS -DPNG_WRITE_SUPPORTED -DPNG_WRITE_TRANSFORMS_SUPPORTED" 

################################################################################
# Patch pnglibconf.dfa
#  * Disable STDIO and WARNING (unchanged)
#  * LEAVE 'WRITE' ALONE so encoder symbols stay in the library
################################################################################
cat scripts/pnglibconf.dfa | \
  sed -e "s/option STDIO/option STDIO disabled/" \
      -e "s/option WARNING /option WARNING disabled/" \
> scripts/pnglibconf.dfa.temp
mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa

################################################################################
# Build the static libpng with write support
################################################################################
autoreconf -f -i
./configure --with-libpng-prefix=OSS_FUZZ_
make -j"$(nproc)" clean
make -j"$(nproc)" libpng16.la               # produces .libs/libpng16.a

################################################################################
# Build fuzzers
################################################################################

$CXX $CXXFLAGS -std=c++11 -I. \
     $SRC/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc \
     -o $OUT/libpng_read_fuzzer \
     -lFuzzingEngine .libs/libpng16.a -lz

$CXX $CXXFLAGS -std=c++11 -I. \
     -DPNG_READ_UNKNOWN_CHUNKS_SUPPORTED \
     $SRC/libpng/contrib/oss-fuzz/libpng_unknown_chunk_fuzzer.cc \
     -o $OUT/libpng_unknown_chunk_fuzzer \
     -lFuzzingEngine .libs/libpng16.a -lz

$CXX $CXXFLAGS -std=c++11 -I. \
     -DPNG_READ_UNKNOWN_CHUNKS_SUPPORTED \
     $SRC/libpng/contrib/oss-fuzz/libpng_improved_read_fuzzer.cc \
     -o $OUT/libpng_improved_read_fuzzer \
     -lFuzzingEngine .libs/libpng16.a -lz

################################################################################
# Package seed corpora and dictionaries (unchanged)
################################################################################
find $SRC/libpng -name "*.png" | grep -v crashers | \
     xargs zip -q $OUT/libpng_read_fuzzer_seed_corpus.zip

find $SRC/libpng -name "*.png" | grep -v crashers | \
     xargs zip -q $OUT/libpng_unknown_chunk_fuzzer_seed_corpus.zip

find $SRC/libpng -name "*.png" | grep -v crashers | \
     xargs zip -q $OUT/libpng_improved_read_fuzzer_seed_corpus.zip

cp $SRC/libpng/contrib/oss-fuzz/*.dict \
   $SRC/libpng/contrib/oss-fuzz/*.options $OUT/