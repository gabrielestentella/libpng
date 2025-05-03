// libpng_read_fuzzer.cc
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

// The modifications in 2017 by Glenn Randers-Pehrson include
// 1. addition of a PNG_CLEANUP macro,
// 2. setting the option to ignore ADLER32 checksums,
// 3. adding "#include <string.h>" which is needed on some platforms
//    to provide memcpy().
// 4. adding read_end_info() and creating an end_info structure.
// 5. adding calls to png_set_*() transforms commonly used by browsers.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>

#define PNG_INTERNAL
#define PNG_sCAL_SUPPORTED

#include "png.h"

#define PNG_CLEANUP \
  if(png_handler.png_ptr) \
  { \
    if (png_handler.row_ptr) \
      png_free(png_handler.png_ptr, png_handler.row_ptr); \
    if (png_handler.end_info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        &png_handler.end_info_ptr); \
    else if (png_handler.info_ptr) \
      png_destroy_read_struct(&png_handler.png_ptr, &png_handler.info_ptr,\
        nullptr); \
    else \
      png_destroy_read_struct(&png_handler.png_ptr, nullptr, nullptr); \
    png_handler.png_ptr = nullptr; \
    png_handler.row_ptr = nullptr; \
    png_handler.info_ptr = nullptr; \
    png_handler.end_info_ptr = nullptr; \
  }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 5) return 0; // need at least a few bytes for dimensions
  png_image image;
  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;
  //use first bytes to construct small width/height to avoid huge allocs
  image.width = data[0] + 1;
  image.height = data[1] + 1;
  int colormode = data[2] % 3;
  //pick a color format: 0=RGBA, 1=GRAY, 2=RGBA palette (just for variety)
  image.format = (colormode == 1 ? PNG_FORMAT_GRAY : PNG_FORMAT_RGBA);
  //Allocate pixel buffer (assume 8-bit components)
  size_t pixel_size = PNG_IMAGE_SIZE(image);
  if (pixel_size > size - 3 || pixel_size == 0) return 0;
  //Use remaining fuzz data as pixel bytes
  png_bytep pixels = const_cast<png_bytep>(data + 3);
  //Write PNG to memory (output buffer allocated by libpng)
  png_bytep out_buf = NULL;
  png_alloc_size_t out_size = 0;
  if (!png_image_write_to_memory(&image, &out_buf, &out_size, 0, pixels, 0, NULL)) {
      png_image_free(&image);
      return 0; // writing failed
  }
  //free image memory
  png_image_free(&image);
  free(out_buf);
  return 0;
}

