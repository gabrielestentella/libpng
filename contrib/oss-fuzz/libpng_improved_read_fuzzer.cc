// libpng_unknown_chunk_fuzzer.cc
// Enhanced to cover critical functions in pngread.c
// Copyright 2017-2018 Glenn Randers-Pehrson
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
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
    PNG_CLEANUP
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
  if (size > 4000000) // Reduced limit for stricter memory control
    return nullptr;
  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  free(ptr);
}

static int user_chunk_callback(png_structp png_ptr, png_unknown_chunkp chunk) {
  // Randomize handling to test different paths
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
  return 0; // Default: save chunk
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
}

// Test simplified read API
int test_simplified_read(const uint8_t* data, size_t size, uint32_t seed) {
  png_image image;
  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;

  if (!png_image_begin_read_from_memory(&image, data, size)) {
    png_image_free(&image);
    return 0;
  }

  // Randomly choose format and transformations
  std::mt19937 gen(seed);
  std::uniform_int_distribution<> dis(0, 1);
  image.format = PNG_FORMAT_RGBA;
  if (dis(gen)) image.format |= PNG_FORMAT_FLAG_LINEAR;
  if (dis(gen)) image.format |= PNG_FORMAT_FLAG_COLORMAP;

  std::vector<png_byte> buffer(PNG_IMAGE_SIZE(image));
  std::vector<png_byte> colormap;
  if (image.format & PNG_FORMAT_FLAG_COLORMAP) {
    colormap.resize(image.colormap_entries * 4); // RGBA colormap
  }

  png_color background = {128, 128, 128}; // Gray background
  if (!png_image_finish_read(&image, &background, buffer.data(), 0, colormap.empty() ? nullptr : colormap.data())) {
    png_image_free(&image);
    return 0;
  }

  png_image_free(&image);
  return 0;
}

// Entry point for LibFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  std::vector<unsigned char> v(data, data + size);
  if (png_sig_cmp(v.data(), 0, kPngHeaderSize)) {
    return 0;
  }

  // Use part of input as seed for randomization
  uint32_t seed = size >= 4 ? *(uint32_t*)data : 0;

  // Test simplified read API
  test_simplified_read(data, size, seed);

  // Original sequential read path
  PngObjectHandler png_handler;
  png_handler.png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
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

  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);
  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
#ifdef PNG_IGNORE_ADLER32
  png_set_option(png_handler.png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif

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

  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type, filter_type;
  if (!png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width,
                    &height, &bit_depth, &color_type, &interlace_type,
                    &compression_type, &filter_type)) {
    PNG_CLEANUP
    return 0;
  }

  if (width && height > 50000000 / width) {
    PNG_CLEANUP
    return 0;
  }

  // Apply random transformations
  apply_random_transforms(png_handler.png_ptr, seed);

  int passes = png_set_interlace_handling(png_handler.png_ptr);
  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  png_handler.row_ptr = png_malloc(
      png_handler.png_ptr, png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr));
  if (!png_handler.row_ptr) {
    PNG_CLEANUP
    return 0;
  }

  // Read image data with interlacing
  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr,
                   static_cast<png_bytep>(png_handler.row_ptr), nullptr);
    }
  }

  // Test png_read_image
  if (width * height < 1000000) { // Limit size for performance
    std::vector<png_bytep> rows(height);
    for (png_uint_32 y = 0; y < height; ++y) {
      rows[y] = static_cast<png_bytep>(png_malloc(png_handler.png_ptr,
          png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr)));
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

  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);

  PNG_CLEANUP
  return 0;
}