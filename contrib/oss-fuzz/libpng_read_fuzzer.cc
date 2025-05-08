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

  // Enable additional transformations based on input data
  // Use the first few bytes after the header as control flags
  if (size >= kPngHeaderSize + 8) {
    // Use each bit of the control byte to enable a specific transformation
    png_byte control_byte = data[kPngHeaderSize];
    
    // BGR color handling - swap R and B channels
    if (control_byte & 0x01) {
      png_set_bgr(png_handler.png_ptr);
    }
    
    // Swap bytes for 16-bit depth images
    if (control_byte & 0x02) {
      png_set_swap(png_handler.png_ptr);
    }
    
    // Swap bits within bytes for sub-8-bit depths
    if (control_byte & 0x04) {
      png_set_packswap(png_handler.png_ptr);
    }
    
    // Swap alpha channel position
    if (control_byte & 0x08) {
      png_set_swap_alpha(png_handler.png_ptr);
    }
    
    // Invert alpha channel values
    if (control_byte & 0x10) {
      png_set_invert_alpha(png_handler.png_ptr);
    }
    
    // Invert monochrome values
    if (control_byte & 0x20) {
      png_set_invert_mono(png_handler.png_ptr);
    }
    
    // Set up shift parameters if relevant - shift adjusts bit significance
    if (control_byte & 0x40) {
      png_color_8 shift_params;
      // Use some bytes from the input as shift values
      shift_params.red = data[kPngHeaderSize + 1] & 0x07;    // Keep shifts small (0-7)
      shift_params.green = data[kPngHeaderSize + 2] & 0x07;
      shift_params.blue = data[kPngHeaderSize + 3] & 0x07;
      shift_params.gray = data[kPngHeaderSize + 4] & 0x07;
      shift_params.alpha = data[kPngHeaderSize + 5] & 0x07;
      png_set_shift(png_handler.png_ptr, &shift_params);
    }
    
    // Test user transform functionality
    if (control_byte & 0x80) {
      // The transform doesn't do anything but the API gets exercised
      png_set_user_transform_info(png_handler.png_ptr, 
                                 (void*)(data + kPngHeaderSize + 6), // Use input as transform pointer
                                 bit_depth,                         // Pass through the image depth
                                 color_type & PNG_COLOR_MASK_COLOR ? 3 : 1); // Channel count
    }
  }

  int passes = png_set_interlace_handling(png_handler.png_ptr);

  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  png_handler.row_ptr = png_malloc(
      png_handler.png_ptr, png_get_rowbytes(png_handler.png_ptr,
                                            png_handler.info_ptr));

  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr,
                   static_cast<png_bytep>(png_handler.row_ptr), nullptr);
      
      // Test row and pass number retrieval during reading
      if (size >= kPngHeaderSize + 10 && (data[kPngHeaderSize + 9] & 0x01)) {
        volatile png_uint_32 current_row = png_get_current_row_number(png_handler.png_ptr);
        volatile png_byte current_pass = png_get_current_pass_number(png_handler.png_ptr);
        (void)current_row; // Prevent unused variable warnings
        (void)current_pass;
      }
    }
  }

  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);


  png_row_info row_info;
  row_info.width = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
  row_info.rowbytes = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
  row_info.color_type = data[8];
  row_info.bit_depth = data[9];

  switch (row_info.color_type) {
      case PNG_COLOR_TYPE_GRAY:
          row_info.channels = 1;
          break;
      case PNG_COLOR_TYPE_PALETTE:
          row_info.channels = 1;
          break;
      case PNG_COLOR_TYPE_RGB:
          row_info.channels = 3;
          break;
      case PNG_COLOR_TYPE_RGB_ALPHA:
          row_info.channels = 4;
          break;
      case PNG_COLOR_TYPE_GRAY_ALPHA:
          row_info.channels = 2;
          break;
      default:
          row_info.channels = 1;
          break;
  }

  // Initialize variables for png_read_rows using fuzzer data
  png_bytepp row = nullptr;
  png_bytepp display_row = nullptr;
  png_uint_32 num_rows = 1; // Default to a safe value
  
  if (size >= kPngHeaderSize + 12) {
    // Use fuzzer data to determine how many rows to read
    num_rows = (data[kPngHeaderSize + 10] & 0x0F) + 1; // Limit to reasonable range (1-16)
    
    // Allocate row pointers
    row = static_cast<png_bytepp>(malloc(sizeof(png_bytep) * num_rows));
    if (row) {
      // Initialize all row pointers to our existing row buffer
      for (png_uint_32 i = 0; i < num_rows; i++) {
        row[i] = static_cast<png_bytep>(png_handler.row_ptr);
      }
      
      // Only create display_row if control bit is set
      if (data[kPngHeaderSize + 11] & 0x01) {
        display_row = static_cast<png_bytepp>(malloc(sizeof(png_bytep) * num_rows));
        if (display_row) {
          for (png_uint_32 i = 0; i < num_rows; i++) {
            display_row[i] = static_cast<png_bytep>(png_handler.row_ptr);
          }
        }
      }
      
      if (setjmp(png_jmpbuf(png_handler.png_ptr)) == 0) {
        png_read_rows(png_handler.png_ptr, row, display_row, num_rows);
      }

      png_read_image(png_handler.png_ptr, row);
      
      // Free allocated memory
      free(row);
      if (display_row) {
        free(display_row);
      }
    }
  }

  if (size >= kPngHeaderSize + 10 && (data[kPngHeaderSize + 9] & 0x02)) {
    volatile png_voidp user_ptr = png_get_user_transform_ptr(png_handler.png_ptr);
    (void)user_ptr; // Prevent unused variable warnings
  }

  if (size >= kPngHeaderSize + 4) {
    png_byte buf_32_1[4];
    png_byte buf_32_2[4];
    png_byte buf_16[2];

    memcpy(buf_32_1, data + kPngHeaderSize, 4);
    memcpy(buf_32_2, data + kPngHeaderSize, 4);
    memcpy(buf_16, data + kPngHeaderSize, 2);
    
    // Call the integer conversion functions - these are macros in the OSS-FUZZ environment
    volatile png_uint_32 val32 = png_get_uint_32(buf_32_1);
    volatile png_int_32 val32s = png_get_int_32(buf_32_2);
    volatile png_uint_16 val16 = png_get_uint_16(buf_16);
    
    // Test unknown chunk handling with public API
    if (png_handler.png_ptr) {
      png_byte chunk_name[5] = "zTXt";  // Using a known ancillary chunk type
      
      // Set unknown chunk handling with public API
      png_set_keep_unknown_chunks(png_handler.png_ptr, PNG_HANDLE_CHUNK_ALWAYS, 
                                  chunk_name, 1);
    }
  }

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
