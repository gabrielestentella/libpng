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
  if (size > 8000000)
    return nullptr;

  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  return free(ptr);
}

void getFunctions (PngObjectHandler *png_handler) {
  png_get_valid(png_handler->png_ptr, png_handler->info_ptr, PNG_INFO_tRNS);
  png_get_rows(png_handler->png_ptr, png_handler->info_ptr);
  png_get_image_width(png_handler->png_ptr, png_handler->info_ptr);
  png_get_image_height(png_handler->png_ptr, png_handler->info_ptr);
  png_get_bit_depth(png_handler->png_ptr, png_handler->info_ptr);
  png_get_color_type(png_handler->png_ptr, png_handler->info_ptr);
  png_get_filter_type(png_handler->png_ptr, png_handler->info_ptr);
  png_get_compression_type(png_handler->png_ptr, png_handler->info_ptr);
  png_get_interlace_type(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_pixels_per_meter(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_pixels_per_meter(png_handler->png_ptr, png_handler->info_ptr);
  png_get_pixels_per_meter(png_handler->png_ptr, png_handler->info_ptr);
  png_get_pixel_aspect_ratio_fixed(png_handler->png_ptr, png_handler->info_ptr);
  png_get_pixel_aspect_ratio(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_offset_microns(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_offset_microns(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_offset_pixels(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_offset_pixels(png_handler->png_ptr, png_handler->info_ptr);
  png_get_pixels_per_inch(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_pixels_per_inch(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_pixels_per_inch(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_offset_inches_fixed(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_offset_inches_fixed(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_offset_inches(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_offset_inches(png_handler->png_ptr, png_handler->info_ptr);
  png_get_channels(png_handler->png_ptr, png_handler->info_ptr);
  png_get_signature(png_handler->png_ptr, png_handler->info_ptr);
  png_uint_32 res_x, res_y;
  int unit_type;
  png_get_pHYs_dpi(png_handler->png_ptr, png_handler->info_ptr, &res_x, &res_y, &unit_type);
  png_color_16p background;
  png_get_bKGD(png_handler->png_ptr, png_handler->info_ptr, &background);
  png_fixed_point whitex, whitey, redx, redy, redz, greenx, greeny, greenz, bluex, bluey, bluez;
  png_get_cHRM_fixed(png_handler->png_ptr, png_handler->info_ptr, &whitex, &whitey, &redx, &redy, &greenx, &greeny, &bluex, &bluey);
  double red_X, red_Y, red_Z, green_X, green_Y, green_Z, blue_X, blue_Y, blue_Z, white_X, white_Y;
  png_get_cHRM_XYZ(png_handler->png_ptr, png_handler->info_ptr,  &red_X,  &red_Y,  &red_Z,  &green_X, 
    &green_Y,  &green_Z,  &blue_X,  &blue_Y, &blue_Z);
  png_get_cHRM_XYZ_fixed(png_handler->png_ptr, png_handler->info_ptr, &redx, &redy, &redz, &greenx, &greeny, &greenz, 
    &bluex, &bluey, &bluez);
  png_get_cHRM(png_handler->png_ptr, png_handler->info_ptr, &white_X, &white_Y, &red_X, &red_Y, &green_X, &green_Y, &blue_X, &blue_Y);
  png_fixed_point file_gamma;
  png_get_gAMA_fixed(png_handler->png_ptr, png_handler->info_ptr, &file_gamma);
  double gamma_file;
  png_get_gAMA(png_handler->png_ptr, png_handler->info_ptr, &gamma_file);
  int file_srgb_intent;
  png_get_sRGB(png_handler->png_ptr, png_handler->info_ptr, &file_srgb_intent);
  png_charpp name;
  int compression_type;
  png_bytep profile;
  png_uint_32 proflen;
  png_get_iCCP(png_handler->png_ptr, png_handler->info_ptr, &name, &compression_type, &profile, &proflen);
  png_sPLT_tp spalettes;
  png_get_sPLT(png_handler->png_ptr, png_handler->info_ptr, &spalettes);
  png_uint_32 maxCLL, maxFALL, num_exif;
  png_bytep exif;
  png_get_eXIf(png_handler->png_ptr, png_handler->info_ptr, &exif);
  png_get_eXIf_1(png_handler->png_ptr, png_handler->info_ptr, &num_exif, &exif);
  png_uint_16p hist;
  png_get_hIST(png_handler->png_ptr, png_handler->info_ptr, &hist);
  png_int_32 offset_x, offset_y;
  png_get_oFFs(png_handler->png_ptr, png_handler->info_ptr, &offset_x, &offset_y, &unit_type);
  png_charp purpose, units;
  png_int_32 X0, X1;
  int type, nparams;
  png_charpp params;
  png_get_pCAL(png_handler->png_ptr, png_handler->info_ptr, &purpose, &X0, &X1, &type, &nparams, &units, &params);
  png_fixed_point width, height;
  png_get_sCAL_fixed(png_handler->png_ptr, png_handler->info_ptr, &unit_type, &width, &height);
  double width_2, height_2;
  png_get_sCAL(png_handler->png_ptr, png_handler->info_ptr, &unit_type, &width_2, &height_2);
  png_charpp width_3, height_3;
  png_get_sCAL_s(png_handler->png_ptr, png_handler->info_ptr, &unit_type, &width_3, &height_3);
  png_get_pHYs(png_handler->png_ptr, png_handler->info_ptr, &res_x, &res_y, &unit_type);
  png_colorp palette;
  png_get_PLTE(png_handler->png_ptr, png_handler->info_ptr, &palette, &unit_type);
  png_color_8p sig_bit;
  png_get_sBIT(png_handler->png_ptr, png_handler->info_ptr, &sig_bit);
  png_textp text_ptr;
  png_get_text(png_handler->png_ptr, png_handler->info_ptr, &text_ptr, &unit_type);
  png_timep mod_time;
  png_get_tIME(png_handler->png_ptr, png_handler->info_ptr, &mod_time);
  png_bytep trans_alpha;
  png_color_16p trans_color;
  png_get_tRNS(png_handler->png_ptr, png_handler->info_ptr, &trans_alpha, &unit_type, &trans_color);
  png_unknown_chunkpp entries;
  png_get_unknown_chunks(png_handler->png_ptr, png_handler->info_ptr, &entries);
  png_get_rgb_to_gray_status(png_handler->png_ptr);
  png_get_user_chunk_ptr(png_handler->png_ptr);
  png_get_compression_buffer_size(png_handler->png_ptr);
  png_get_user_width_max(png_handler->png_ptr);
  png_get_user_height_max(png_handler->png_ptr);
  png_get_chunk_cache_max(png_handler->png_ptr);
  png_get_chunk_malloc_max(png_handler->png_ptr);
  png_get_io_state(png_handler->png_ptr);
  png_get_io_chunk_type(png_handler->png_ptr);
  png_get_palette_max(png_handler->png_ptr, png_handler->info_ptr);
}

static const int kPngHeaderSize = 8;

// Entry point for LibFuzzer.
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

  // Reading.
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
  if (width && height > 100000000 / width) {
    PNG_CLEANUP
    return 0;
  }

  // Set several transforms that browsers typically use:
  png_set_gray_to_rgb(png_handler.png_ptr);
  png_set_expand(png_handler.png_ptr);
  png_set_packing(png_handler.png_ptr);
  png_set_scale_16(png_handler.png_ptr);
  png_set_tRNS_to_alpha(png_handler.png_ptr);

  int passes = png_set_interlace_handling(png_handler.png_ptr);

  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  png_handler.row_ptr = png_malloc(
      png_handler.png_ptr, png_get_rowbytes(png_handler.png_ptr,
                                            png_handler.info_ptr));

  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr,
                   static_cast<png_bytep>(png_handler.row_ptr), nullptr);
    }
  }
  getFunctions(&png_handler);
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
