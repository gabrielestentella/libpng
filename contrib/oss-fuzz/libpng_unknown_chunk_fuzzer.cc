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
  // Prevent large allocations to avoid OOM errors during fuzzing.
  if (size > 8000000)
    return nullptr;
  return malloc(size);
}

void default_free(png_structp, png_voidp ptr) {
  free(ptr);
}

// User callback for unknown chunks to exercise PNG_READ_USER_CHUNKS_SUPPORTED path
static int user_chunk_callback(png_structp png_ptr, png_unknown_chunkp chunk) {
  // Simulate different outcomes to test various paths in png_handle_unknown
  // Return values:
  //   Negative: Error (triggers png_chunk_error)
  //   Zero: Chunk not handled (may be saved if keep setting allows)
  //   Positive: Chunk handled (discarded by libpng)
  if (chunk->size > 1000000) {
    return -1; // Simulate error for large chunks
  }
  if (chunk->name[0] == 'x' && chunk->name[1] == 'x') {
    return 1; // Simulate handling for specific chunk (e.g., 'xxXX')
  }
  return 0; // Default: chunk not handled, may be saved
}

static const int kPngHeaderSize = 8;

// Entry point for LibFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < kPngHeaderSize) {
    return 0;
  }

  std::vector<unsigned char> v(data, data + size);
  if (png_sig_cmp(v.data(), 0, kPngHeaderSize)) {
    // Not a PNG file
    return 0;
  }

  PngObjectHandler png_handler;
  png_handler.png_ptr = nullptr;
  png_handler.row_ptr = nullptr;
  png_handler.info_ptr = nullptr;
  png_handler.end_info_ptr = nullptr;

  // Create PNG read structure
  png_handler.png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) {
    return 0;
  }

  // Create info and end_info structures
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

  // Set custom allocator to limit memory usage
  png_set_mem_fn(png_handler.png_ptr, nullptr, limited_malloc, default_free);

  // Disable CRC and ADLER32 checks to focus on chunk handling
  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
#ifdef PNG_IGNORE_ADLER32
  png_set_option(png_handler.png_ptr, PNG_IGNORE_ADLER32, PNG_OPTION_ON);
#endif

  // Set up buffer reading
  png_handler.buf_state = new BufState();
  png_handler.buf_state->data = data + kPngHeaderSize;
  png_handler.buf_state->bytes_left = size - kPngHeaderSize;
  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, kPngHeaderSize);

  // Set error handling
  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  // Enable unknown chunk handling
#ifdef PNG_READ_UNKNOWN_CHUNKS_SUPPORTED
  // Set user callback for unknown chunks
  png_set_read_user_chunk_fn(png_handler.png_ptr, nullptr, user_chunk_callback);

  // Configure to save unknown chunks (tests PNG_SAVE_UNKNOWN_CHUNKS_SUPPORTED)
  // Save all unknown chunks (critical and ancillary)
  png_set_keep_unknown_chunks(png_handler.png_ptr, PNG_HANDLE_CHUNK_ALWAYS, nullptr, 0);
#endif

  // Read PNG info
  png_read_info(png_handler.png_ptr, png_handler.info_ptr);

  // Reset error handler
  if (setjmp(png_jmpbuf(png_handler.png_ptr))) {
    PNG_CLEANUP
    return 0;
  }

  // Get image header
  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type, filter_type;
  if (!png_get_IHDR(png_handler.png_ptr, png_handler.info_ptr, &width,
                    &height, &bit_depth, &color_type, &interlace_type,
                    &compression_type, &filter_type)) {
    PNG_CLEANUP
    return 0;
  }

  // Limit processing for large images
  if (width && height > 100000000 / width) {
    PNG_CLEANUP
    return 0;
  }

  // Apply common transforms (as in original harness)
  png_set_gray_to_rgb(png_handler.png_ptr);
  png_set_expand(png_handler.png_ptr);
  png_set_packing(png_handler.png_ptr);
  png_set_scale_16(png_handler.png_ptr);
  png_set_tRNS_to_alpha(png_handler.png_ptr);

  // Handle interlacing
  int passes = png_set_interlace_handling(png_handler.png_ptr);
  png_read_update_info(png_handler.png_ptr, png_handler.info_ptr);

  // Allocate row buffer
  png_handler.row_ptr = png_malloc(
      png_handler.png_ptr, png_get_rowbytes(png_handler.png_ptr, png_handler.info_ptr));
  if (!png_handler.row_ptr) {
    PNG_CLEANUP
    return 0;
  }

  // Read image data (triggers unknown chunk handling during IDAT processing)
  for (int pass = 0; pass < passes; ++pass) {
    for (png_uint_32 y = 0; y < height; ++y) {
      png_read_row(png_handler.png_ptr,
                   static_cast<png_bytep>(png_handler.row_ptr), nullptr);
    }
  }

  // Read end info (triggers unknown chunk handling for trailing chunks)
  png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);

  // Cleanup
  PNG_CLEANUP
  return 0;
}