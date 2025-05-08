// libpng_improved_read_fuzzer.cc
// Enhanced to cover critical functions in pngread.c
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that may
// be found in the LICENSE file https://cs.chromium.org/chromium/src/LICENSE

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>
#include <random>

#define PNG_INTERNAL
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

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngObjectHandler {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_voidp row_ptr = nullptr;
  BufState* buf_state = nullptr;

  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (end_info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    else if (info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    else
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    delete buf_state;
  }
};

void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* buf_state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

void* limited_malloc(png_structp, png_alloc_size_t size) {
  // libpng may allocate large amounts of memory that the fuzzer reports as
  // an error. In order to silence these errors, make libpng fail when trying
  // to allocate a large amount. This allocator used to be in the Chromium
  // version of this fuzzer.
  // This number is chosen to match the default png_user_chunk_malloc_max.
  if (size > 4000000)
    return nullptr;

  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  free(ptr);
}

static int user_chunk_callback(png_structp png_ptr, png_unknown_chunkp chunk) {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 2);

  if (chunk->size > 500000) {
    return -1; // Simulate error for large chunks
  }

  int choice = dis(gen);
  if (choice == 0 && chunk->name[0] == 'x' && chunk->name[1] == 'x') {
    return 1; // Simulate handling
  } else if (choice == 1) {
    return -1; // Simulate error
  }
  return 0; // Save chunk
}

static const int kPngHeaderSize = 8;

// Helper to apply random transformations
void apply_random_transforms(png_structp png_ptr, uint32_t seed) {
  std::mt19937 gen(seed);
  std::uniform_int_distribution<> dis(0, 1);

  if (dis(gen)) png_set_gray_to_rgb(png_ptr);
  if (dis(gen)) png_set_expand(png_ptr);
  if (dis(gen)) png_set_packing(png_ptr);
  if (dis(gen)) png_set_scale_16(png_ptr);
  if (dis(gen)) png_set_tRNS_to_alpha(png_ptr);
  if (dis(gen)) png_set_strip_alpha(png_ptr);
  if (dis(gen)) png_set_invert_mono(png_ptr);
  if (dis(gen)) png_set_bgr(png_ptr);
  if (dis(gen)) png_set_swap_alpha(png_ptr);
}

// Test simplified read API with colormap
int test_simplified_read(const uint8_t* data, size_t size, uint32_t seed) {
  png_image image;
  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;

  if (!png_image_begin_read_from_memory(&image, data, size)) {
    png_image_free(&image);
    return 0;
  }

  std::mt19937 gen(seed);
  std::uniform_int_distribution<> dis(0, 3);
  int format_choice = dis(gen);

  switch (format_choice) {
    case 0:
      image.format = PNG_FORMAT_GRAY | PNG_FORMAT_FLAG_COLORMAP;
      break;
    case 1:
      image.format = PNG_FORMAT_GA | PNG_FORMAT_FLAG_COLORMAP;
      break;
    case 2:
      image.format = PNG_FORMAT_RGB | PNG_FORMAT_FLAG_COLORMAP;
      break;
    case 3:
      image.format = PNG_FORMAT_RGBA;
      if (dis(gen)) image.format |= PNG_FORMAT_FLAG_LINEAR;
      break;
  }

  std::vector<png_byte> buffer(PNG_IMAGE_SIZE(image));
  std::vector<png_byte> colormap;
  if (image.format & PNG_FORMAT_FLAG_COLORMAP) {
    colormap.resize(image.colormap_entries * 4); // RGBA colormap
  }

  png_color background = {128, 128, 128};
  if (!png_image_finish_read(&image, &background, buffer.data(), 0,
                             colormap.empty() ? nullptr : colormap.data())) {
    png_image_free(&image);
    return 0;
  }

  png_image_free(&image);
  return 0;
}

// Test png_read_png to cover png_free_data
int test_png_read_png(PngObjectHandler& png_handler, uint32_t seed) {
  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  apply_random_transforms(png_handler.png_ptr, seed);
  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

#ifdef PNG_INFO_IMAGE_SUPPORTED
  png_read_png(png_handler.png_ptr, png_handler.info_ptr,
               PNG_TRANSFORM_EXPAND | PNG_TRANSFORM_GRAY_TO_RGB, nullptr);
#endif

  return 0;
}

// Entry point for LibFuzzer
// Roughly follows the libpng book example:
// http://www.libpng.org/pub/png/book/chapter13.html
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  std::vector<unsigned char> v(data, data + size);
  if (png_sig_cmp(v.data(), 0, kPngHeaderSize)) {
    // not a PNG.
    return 0;
  }

  uint32_t seed = size >= 4 ? *(uint32_t*)data : 0;
  std::mt19937 gen(seed);
  std::uniform_int_distribution<> dis(0, 2);

  test_simplified_read(data, size, seed);

  PngObjectHandler png_handler;
  png_handler.png_ptr = nullptr;
  png_handler.row_ptr = nullptr;
  png_handler.info_ptr = nullptr;
  png_handler.end_info_ptr = nullptr;
  
  png_handler.png_ptr = png_create_read_struct
    (PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) {
    return 0;
  }

  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) {
    PNG_CLEANUP
    return 0;
  }

  png_handler.end_info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.end_info_ptr) {
    PNG_CLEANUP
    return 0;
  }

  // Use a custom allocator that fails for large allocations to avoid OOM.
  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);

  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
#ifdef PNG_IGNORE_ADLER32
  png_set_option(png_handler.png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif

  // Setting up reading from buffer.
  png_handler.buf_state = new BufState();
  png_handler.buf_state->data = data + kPngHeaderSize;
  png_handler.buf_state->bytes_left = size - kPngHeaderSize;
  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, kPngHeaderSize);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

#ifdef PNG_READ_UNKNOWN_CHUNKS_SUPPORTED
  png_set_read_user_chunk_fn(png_handler.png_ptr, nullptr, user_chunk_callback);
  png_set_keep_unknown_chunks(png_handler.png_ptr, PNG_HANDLE_CHUNK_ALWAYS, nullptr, 0);
#endif

  // Set gamma for sequential read
  if (dis(gen)) {
    png_set_gAMA(png_handler.png_ptr, png_handler.info_ptr, 0.45455); // sRGB
  } else if (dis(gen)) {
    png_set_gAMA(png_handler.png_ptr, png_handler.info_ptr, 1.0); // Linear
  } else {
    png_set_gAMA(png_handler.png_ptr, png_handler.info_ptr, 0.8); // Custom
  }

  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  // reset error handler to put png_deleter into scope.
  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type;
  int filter_type;

  if (!png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width,
                    &height, &bit_depth, &color_type, &interlace_type,
                    &compression_type, &filter_type)) {
    PNG_CLEANUP
    return 0;
  }

  // This is going to be too slow.
  if (width && height > 50000000 / width) {
    PNG_CLEANUP
    return 0;
  }

#ifdef PNG_MNG_FEATURES_SUPPORTED
  if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGB_ALPHA) {
    png_set_mng_features(png_handler.png_ptr, PNG_FLAG_MNG_FILTER_64);
  }
#endif

  apply_random_transforms(png_handler.png_ptr, seed);
  int passes = png_set_interlace_handling(png_handler.png_ptr);
  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  int read_method = dis(gen);
  if (read_method == 0) { // Use png_read_row
    png_handler.row_ptr = png_malloc(
        png_handler.png_ptr, png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr));
    if (!png_handler.row_ptr) {
      PNG_CLEANUP
      return 0;
    }

    for (int pass = 0; pass < passes; ++pass) {
      for (png_uint_32 y = 0; y < height; ++y) {
        png_read_row(png_handler.png_ptr,
                     static_cast<png_bytep>(png_handler.row_ptr), nullptr);
      }
    }
  } else if (read_method == 1) { // Use png_read_rows
    std::vector<png_bytep> rows(height);
    png_size_t rowbytes = png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr);
    for (png_uint_32 y = 0; y < height; ++y) {
      rows[y] = static_cast<png_bytep>(png_malloc(png_handler.png_ptr, rowbytes));
      if (!rows[y]) {
        for (png_uint_32 i = 0; i < y; ++i) {
          png_free(png_handler.png_ptr, rows[i]);
        }
        PNG_CLEANUP
        return 0;
      }
    }

    if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
      for (png_uint_32 y = 0; y < height; ++y) {
        png_free(png_handler.png_ptr, rows[y]);
      }
      PNG_CLEANUP
      return 0;
    }

    png_uint_32 rows_to_read = height / 2 + 1;
    for (png_uint_32 y = 0; y < height; y += rows_to_read) {
      png_uint_32 num_rows = std::min(rows_to_read, height - y);
      png_read_rows(png_handler.png_ptr, rows.data() + y, nullptr, num_rows);
    }

    for (png_uint_32 y = 0; y < height; ++y) {
      png_free(png_handler.png_ptr, rows[y]);
    }
  } else { // Use png_read_image
    std::vector<png_bytep> rows(height);
    png_size_t rowbytes = png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr);
    for (png_uint_32 y = 0; y < height; ++y) {
      rows[y] = static_cast<png_bytep>(png_malloc(png_handler.png_ptr, rowbytes));
      if (!rows[y]) {
        for (png_uint_32 i = 0; i < y; ++i) {
          png_free(png_handler.png_ptr, rows[i]);
        }
        PNG_CLEANUP
        return 0;
      }
    }

    if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
      for (png_uint_32 y = 0; y < height; ++y) {
        png_free(png_handler.png_ptr, rows[y]);
      }
      PNG_CLEANUP
      return 0;
    }

    png_read_image(png_handler.png_ptr, rows.data());

    for (png_uint_32 y = 0; y < height; ++y) {
      png_free(png_handler.png_ptr, rows[y]);
    }
  }

  if (dis(gen)) {
    test_png_read_png(png_handler, seed);
  }

  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);

  PNG_CLEANUP

#ifdef PNG_SIMPLIFIED_READ_SUPPORTED
  // Simplified READ API
  png_image image;
  memset(&image, 0, (sizeof image));
  image.version = PNG_IMAGE_VERSION;

  if (!png_image_begin_read_from_memory(&image, data, size)) {
    return 0;
  }

  image.format = PNG_FORMAT_RGBA;
  std::vector<png_byte> buffer(PNG_IMAGE_SIZE(image));
  png_image_finish_read(&image, NULL, buffer.data(), 0, NULL);
#endif

  return 0;
}
