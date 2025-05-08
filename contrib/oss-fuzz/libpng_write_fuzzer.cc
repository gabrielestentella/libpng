// libpng_enhanced_write_fuzzer.cc
// Enhanced leak-free, OOM-safe write harness for libpng

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>
#include <algorithm> // For std::min

#include "png.h"

// Define a jmp_buf pointer for setjmp/longjmp error handling
// This needs to be accessible by the error handler if it's outside LLVMFuzzerTestOneInput
// For simplicity in this example, we'll keep it within the fuzzer function's scope
// and rely on libpng's internal jmp_buf.

/* ------------------------------------------------------------------ */
/* Helper: wrap-around byte reader                                    */
/* Consumes a byte from the data buffer, wrapping around if necessary.
   Increments the position pointer. */
static inline uint8_t next_byte(const uint8_t* data, size_t size, size_t* pos) {
  if (size == 0) return 0; // Avoid division by zero if size is 0
  uint8_t value = data[*pos % size];
  (*pos)++;
  return value;
}

/* Helper: consume a 16-bit unsigned integer from fuzzer data */
static inline uint16_t next_uint16(const uint8_t* data, size_t size, size_t* pos) {
  uint16_t val = (uint16_t)next_byte(data, size, pos) << 8;
  val |= (uint16_t)next_byte(data, size, pos);
  return val;
}

/* Helper: consume a 32-bit unsigned integer from fuzzer data */
static inline uint32_t next_uint32(const uint8_t* data, size_t size, size_t* pos) {
  uint32_t val = (uint32_t)next_byte(data, size, pos) << 24;
  val |= (uint32_t)next_byte(data, size, pos) << 16;
  val |= (uint32_t)next_byte(data, size, pos) << 8;
  val |= (uint32_t)next_byte(data, size, pos);
  return val;
}

/* Helper: consume a double (0.0 to 1.0 range from two bytes) */
static inline double next_double_norm(const uint8_t* data, size_t size, size_t* pos) {
    return (double)next_uint16(data, size, pos) / 65535.0;
}

/* Helper: consume a string of fuzzed length and content */
static inline char* next_string(const uint8_t* data, size_t size, size_t* pos, size_t max_len, png_structp png_ptr) {
    size_t len = next_byte(data, size, pos) % (max_len + 1);
    if (len == 0) return nullptr;
    // Use png_malloc to allow libpng to handle memory if it's passed to a png_set function
    // that might store it. Otherwise, ensure it's freed locally.
    // For simple keys/text that are copied by libpng, local stack or simple malloc is fine.
    char* str = (char*)png_malloc(png_ptr, len + 1);
    if (!str) png_error(png_ptr, "Out of memory in fuzzer (next_string)");
    for (size_t i = 0; i < len; ++i) {
        str[i] = (char)next_byte(data, size, pos);
    }
    str[len] = '\0';
    return str;
}


// Custom error handler to use with libpng
static void fuzzer_png_error_handler(png_structp png_ptr, png_const_charp error_msg) {
    // Get the jmp_buf from png_ptr
    jmp_buf* jmp_buf_ptr = (jmp_buf*)png_get_error_ptr(png_ptr);
    if (jmp_buf_ptr) {
        longjmp(*jmp_buf_ptr, 1);
    } else {
        // Fallback if jmp_buf is not set, though it should be by png_create_write_struct
        fprintf(stderr, "Libpng error: %s (jmp_buf not set)\n", error_msg);
        exit(1); // Or some other way to signal a hard error
    }
}

// Custom warning handler (optional, can be nullptr)
static void fuzzer_png_warning_handler(png_structp png_ptr, png_const_charp warning_msg) {
    // Do nothing with warnings to avoid verbose fuzzer output
    (void)png_ptr;
    (void)warning_msg;
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 32) return 0; // Ensure enough data for basic operations + some fuzzing
  size_t pos = 0;

  // --- IHDR parameters ---
  // Modest dimensions to keep rowbytes and total image size manageable
  uint32_t width = (next_uint16(data, size, &pos) % 255) + 1; // 1-256
  uint32_t height = (next_uint16(data, size, &pos) % 255) + 1; // 1-256

  const int color_types[] = {
      PNG_COLOR_TYPE_GRAY, PNG_COLOR_TYPE_RGB, PNG_COLOR_TYPE_PALETTE,
      PNG_COLOR_TYPE_GRAY_ALPHA, PNG_COLOR_TYPE_RGBA
  };
  int color_type = color_types[next_byte(data, size, &pos) % (sizeof(color_types)/sizeof(int))];

  int bit_depth;
  const int bit_depths_palette[] = {1, 2, 4, 8};
  const int bit_depths_gray[] = {1, 2, 4, 8, 16};
  const int bit_depths_rgb_ga[] = {8, 16};

  switch (color_type) {
      case PNG_COLOR_TYPE_PALETTE:
          bit_depth = bit_depths_palette[next_byte(data, size, &pos) % (sizeof(bit_depths_palette)/sizeof(int))];
          break;
      case PNG_COLOR_TYPE_GRAY:
          bit_depth = bit_depths_gray[next_byte(data, size, &pos) % (sizeof(bit_depths_gray)/sizeof(int))];
          break;
      case PNG_COLOR_TYPE_RGB:
      case PNG_COLOR_TYPE_GRAY_ALPHA:
      case PNG_COLOR_TYPE_RGBA:
      default: // Should not happen with the modulo logic above
          bit_depth = bit_depths_rgb_ga[next_byte(data, size, &pos) % (sizeof(bit_depths_rgb_ga)/sizeof(int))];
          break;
  }
  
  // Interlace type: NONE or ADAM7
  int interlace_type = (next_byte(data, size, &pos) % 2 == 0) ? PNG_INTERLACE_NONE : PNG_INTERLACE_ADAM7;


  // --- Libpng setup ---
  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, fuzzer_png_error_handler, fuzzer_png_warning_handler);
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) {
    png_destroy_write_struct(&png_ptr, nullptr);
    return 0;
  }

  // --- Buffers to free ---
  png_bytepp row_pointers = nullptr;
  uint32_t rows_allocated_count = 0;
  png_textp text_ptr = nullptr;
  png_unknown_chunkp unknown_chunks = nullptr;
  char* iccp_name_str = nullptr;
  png_bytep iccp_profile_ptr = nullptr;
  char* pcal_purpose_str = nullptr;
  char* pcal_units_str = nullptr;
  png_int_32* pcal_params_ptr = nullptr;
  char* splt_name_str = nullptr;
  png_sPLT_entryp splt_entries_ptr = nullptr;
  png_bytep exif_ptr = nullptr;


  // --- Longjmp cleanup ---
  // Use png_jmpbuf for libpng's own error handling via longjmp
  if (setjmp(png_jmpbuf(png_ptr))) {
    if (row_pointers) {
      for (uint32_t i = 0; i < rows_allocated_count; ++i) {
        png_free(png_ptr, row_pointers[i]);
      }
      png_free(png_ptr, row_pointers);
    }
    png_free(png_ptr, text_ptr); // png_set_text copies, but if we alloc'd for it
    png_free(png_ptr, unknown_chunks); // png_set_unknown_chunks copies name, but data if we alloc'd it
    png_free(png_ptr, iccp_name_str);
    png_free(png_ptr, iccp_profile_ptr);
    png_free(png_ptr, pcal_purpose_str);
    png_free(png_ptr, pcal_units_str);
    png_free(png_ptr, pcal_params_ptr);
    png_free(png_ptr, splt_name_str);
    png_free(png_ptr, splt_entries_ptr);
    png_free(png_ptr, exif_ptr);
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
  }

  // --- Discard-all write callback ---
  // This prevents OOM if the PNG data itself would be huge.
  png_set_write_fn(png_ptr, nullptr, [](png_structp, png_bytep, png_size_t) {}, nullptr);

  // --- Fuzz flags for enabling sections ---
  uint8_t settings_flags = next_byte(data, size, &pos);
  uint8_t chunk_flags1 = next_byte(data, size, &pos);
  uint8_t chunk_flags2 = next_byte(data, size, &pos);
  uint8_t transform_flags = next_byte(data, size, &pos);

  // --- Compression settings ---
  if (settings_flags & 0x01) png_set_compression_level(png_ptr, next_byte(data, size, &pos) % 10); // 0-9
  if (settings_flags & 0x02) png_set_compression_mem_level(png_ptr, (next_byte(data, size, &pos) % 9) + 1); // 1-9
  if (settings_flags & 0x04) {
    const int strategies[] = {Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED};
    png_set_compression_strategy(png_ptr, strategies[next_byte(data, size, &pos) % (sizeof(strategies)/sizeof(int))]);
  }
  if (settings_flags & 0x08) png_set_compression_window_bits(png_ptr, (next_byte(data, size, &pos) % 8) + 8); // 8-15
  // png_set_compression_method only supports Z_DEFLATED (8) for PNG.
  // Not fuzzing png_set_text_compression_* for brevity, but similar logic applies.

  // --- Filter settings ---
  if (settings_flags & 0x10) {
    // PNG_FILTER_NONE, PNG_FILTER_SUB, PNG_FILTER_UP, PNG_FILTER_AVG, PNG_FILTER_PAETH
    // Or a bitmask of these for heuristic selection
    png_set_filter(png_ptr, PNG_FILTER_TYPE_BASE, next_byte(data, size, &pos) & 0x1F); // Allow single or multiple
  }


  // --- IHDR ---
  png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth, color_type,
               interlace_type, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

  // --- Transformations (call before chunks that might be affected or provide data for them) ---
  if (transform_flags & 0x01 && color_type == PNG_COLOR_TYPE_GRAY && bit_depth == 1) png_set_invert_mono(png_ptr);
  if (transform_flags & 0x02) { // sBIT must be set for png_set_shift
    png_color_8 sig_bit;
    sig_bit.gray = (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    sig_bit.red = (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGBA || color_type == PNG_COLOR_TYPE_PALETTE) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    sig_bit.green = (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGBA || color_type == PNG_COLOR_TYPE_PALETTE) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    sig_bit.blue = (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGBA || color_type == PNG_COLOR_TYPE_PALETTE) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    sig_bit.alpha = (color_type == PNG_COLOR_TYPE_GRAY_ALPHA || color_type == PNG_COLOR_TYPE_RGBA) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    if (sig_bit.gray || sig_bit.red || sig_bit.green || sig_bit.blue || sig_bit.alpha) { // only set sBIT if any component is specified
        png_set_sBIT(png_ptr, info_ptr, &sig_bit);
        png_set_shift(png_ptr, &sig_bit); // Now set shift
    }
  }
  if (transform_flags & 0x04 && bit_depth < 8) png_set_packing(png_ptr);
  if (transform_flags & 0x08 && bit_depth < 8) png_set_packswap(png_ptr); // Swap bits in bytes
  if (transform_flags & 0x10 && (color_type == PNG_COLOR_TYPE_RGBA || color_type == PNG_COLOR_TYPE_GRAY_ALPHA)) png_set_swap_alpha(png_ptr);
  if (transform_flags & 0x20) png_set_filler(png_ptr, next_uint16(data, size, &pos) & 0xFF, (next_byte(data, size, &pos) % 2 == 0) ? PNG_FILLER_BEFORE : PNG_FILLER_AFTER);
  if (transform_flags & 0x40 && (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGBA)) png_set_bgr(png_ptr);
  if (transform_flags & 0x80 && bit_depth == 16) png_set_swap(png_ptr); // Swap bytes for 16-bit samples
  // png_set_invert_alpha is usually for tRNS, can be set before png_write_info

  // --- Ancillary Chunks ---

  // PLTE (Palette)
  if (chunk_flags1 & 0x01 && (color_type == PNG_COLOR_TYPE_PALETTE || (chunk_flags1 & 0x80))) { // 0x80 to force PLTE for non-palette (for testing robustness)
    int num_palette = (next_byte(data, size, &pos) % PNG_MAX_PALETTE_LENGTH) + 1;
    png_color palette[PNG_MAX_PALETTE_LENGTH];
    for (int i = 0; i < num_palette; ++i) {
      palette[i].red   = next_byte(data, size, &pos);
      palette[i].green = next_byte(data, size, &pos);
      palette[i].blue  = next_byte(data, size, &pos);
    }
    png_set_PLTE(png_ptr, info_ptr, palette, num_palette);

    // tRNS (Transparency for palette) - often follows PLTE
    if (chunk_flags1 & 0x02) {
        int num_trans = (next_byte(data, size, &pos) % num_palette) + 1;
        png_byte trans_alpha[PNG_MAX_PALETTE_LENGTH];
        for (int i = 0; i < num_trans; ++i) {
            trans_alpha[i] = next_byte(data, size, &pos);
        }
        // Potentially invert alpha before setting tRNS
        if (transform_flags & 0x0100) png_set_invert_alpha(png_ptr);
        png_set_tRNS(png_ptr, info_ptr, trans_alpha, num_trans, nullptr);
    }
  }

  // tRNS (Transparency for non-palette grayscale/RGB)
  if (!(chunk_flags1 & 0x01) && (chunk_flags1 & 0x02) && (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_RGB)) {
    png_color_16 trans_color_values;
    trans_color_values.gray = (color_type == PNG_COLOR_TYPE_GRAY) ? next_uint16(data, size, &pos) : 0;
    trans_color_values.red = (color_type == PNG_COLOR_TYPE_RGB) ? next_uint16(data, size, &pos) : 0;
    trans_color_values.green = (color_type == PNG_COLOR_TYPE_RGB) ? next_uint16(data, size, &pos) : 0;
    trans_color_values.blue = (color_type == PNG_COLOR_TYPE_RGB) ? next_uint16(data, size, &pos) : 0;
    png_set_tRNS(png_ptr, info_ptr, nullptr, 0, &trans_color_values);
  }


  // gAMA (Gamma)
  if (chunk_flags1 & 0x04) {
    double gamma = next_double_norm(data, size, &pos) * 2.0 + 0.01; // Avoid 0
    png_set_gAMA(png_ptr, info_ptr, gamma);
  }

  // sRGB (Standard RGB color space)
  if (chunk_flags1 & 0x08) {
    const int intents[] = {PNG_sRGB_INTENT_PERCEPTUAL, PNG_sRGB_INTENT_RELATIVE, 
                           PNG_sRGB_INTENT_SATURATION, PNG_sRGB_INTENT_ABSOLUTE};
    png_set_sRGB(png_ptr, info_ptr, intents[next_byte(data, size, &pos) % (sizeof(intents)/sizeof(int))]);
  }

  // iCCP (Embedded ICC profile)
  if (chunk_flags1 & 0x10) {
    iccp_name_str = next_string(data, size, &pos, 79, png_ptr); // Max 79 chars for name
    if (iccp_name_str) {
        png_uint_32 profile_len = (next_uint16(data, size, &pos) % 2048) + 1; // 1-2048 bytes profile
        iccp_profile_ptr = (png_bytep)png_malloc(png_ptr, profile_len);
        if (!iccp_profile_ptr) png_error(png_ptr, "OOM for iCCP profile");
        for (png_uint_32 i = 0; i < profile_len; ++i) {
            iccp_profile_ptr[i] = next_byte(data, size, &pos);
        }
        // Compression type for iCCP is always 0 (deflate)
        png_set_iCCP(png_ptr, info_ptr, iccp_name_str, PNG_COMPRESSION_TYPE_BASE, iccp_profile_ptr, profile_len);
        // png_set_iCCP makes a copy, so we can free our buffer
        png_free(png_ptr, iccp_name_str); iccp_name_str = nullptr;
        png_free(png_ptr, iccp_profile_ptr); iccp_profile_ptr = nullptr;
    }
  }
  
  // tEXt / zTXt / iTXt (Textual data)
  if (chunk_flags1 & 0x20) {
    text_ptr = (png_textp)png_malloc(png_ptr, sizeof(png_text));
    if (!text_ptr) png_error(png_ptr, "OOM for text_ptr");

    text_ptr->compression = next_byte(data, size, &pos) % (PNG_ITXT_COMPRESSION_zTXt + 1); // NONE, zTXt, iTXt modes
    text_ptr->key = next_string(data, size, &pos, 79, png_ptr); // Max 79 chars for key
    text_ptr->text = next_string(data, size, &pos, 256, png_ptr); // Text itself
    text_ptr->text_length = text_ptr->text ? strlen(text_ptr->text) : 0;
    text_ptr->itxt_length = 0; // Only for iTXt
    text_ptr->lang = nullptr;      // Only for iTXt
    text_ptr->lang_key = nullptr;  // Only for iTXt

    if (text_ptr->key && text_ptr->text) { // Must have key and text
        if (text_ptr->compression >= PNG_ITXT_COMPRESSION_NONE) { // iTXt
            text_ptr->lang = next_string(data, size, &pos, 10, png_ptr); // Language tag
            text_ptr->lang_key = next_string(data, size, &pos, 79, png_ptr); // Translated keyword
            text_ptr->itxt_length = text_ptr->text ? strlen(text_ptr->text) : 0;
        }
        png_set_text(png_ptr, info_ptr, text_ptr, 1);
    }
    // png_set_text makes copies, so free our allocated strings
    png_free(png_ptr, text_ptr->key);
    png_free(png_ptr, text_ptr->text);
    png_free(png_ptr, text_ptr->lang);
    png_free(png_ptr, text_ptr->lang_key);
    png_free(png_ptr, text_ptr); text_ptr = nullptr;
  }

  // bKGD (Background color)
  if (chunk_flags1 & 0x40) {
    png_color_16 background;
    if (color_type == PNG_COLOR_TYPE_PALETTE) {
        background.index = next_byte(data, size, &pos) % png_get_palette_max(png_ptr, info_ptr);
    } else if (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA) {
        background.gray = next_uint16(data, size, &pos) % ((1 << bit_depth) );
    } else { // RGB or RGBA
        background.red   = next_uint16(data, size, &pos) % ((1 << bit_depth) );
        background.green = next_uint16(data, size, &pos) % ((1 << bit_depth) );
        background.blue  = next_uint16(data, size, &pos) % ((1 << bit_depth) );
    }
    png_set_bKGD(png_ptr, info_ptr, &background);
  }

  // hIST (Histogram) - must be after PLTE if color_type is PALETTE
  if (chunk_flags2 & 0x01 && color_type == PNG_COLOR_TYPE_PALETTE) {
    png_uint_16p hist = nullptr;
    int num_palette = 0;
    png_colorp palette_tmp; // Not used, just to get num_palette
    if (png_get_PLTE(png_ptr, info_ptr, &palette_tmp, &num_palette) == PNG_INFO_PLTE && num_palette > 0) {
        hist = (png_uint_16p)png_malloc(png_ptr, num_palette * sizeof(png_uint_16));
        if (!hist) png_error(png_ptr, "OOM for hIST");
        for (int i = 0; i < num_palette; ++i) {
            hist[i] = next_uint16(data, size, &pos);
        }
        png_set_hIST(png_ptr, info_ptr, hist);
        png_free(png_ptr, hist); // png_set_hIST copies it
    }
  }

  // pHYs (Physical pixel dimensions)
  if (chunk_flags2 & 0x02) {
    png_set_pHYs(png_ptr, info_ptr,
                 next_uint32(data, size, &pos), // res_x
                 next_uint32(data, size, &pos), // res_y
                 next_byte(data, size, &pos) % 2); // unit_type: 0 for unknown, 1 for meter
  }

  // sBIT (Significant bits) - already set if transform_flags & 0x02 for png_set_shift
  // If not set by transform, can set it here.
  if (!(transform_flags & 0x02) && (chunk_flags2 & 0x04)) {
    png_color_8 sig_bit;
    sig_bit.gray = (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    sig_bit.red = (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGBA || color_type == PNG_COLOR_TYPE_PALETTE) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    sig_bit.green = (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGBA || color_type == PNG_COLOR_TYPE_PALETTE) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    sig_bit.blue = (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_RGBA || color_type == PNG_COLOR_TYPE_PALETTE) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
    sig_bit.alpha = (color_type == PNG_COLOR_TYPE_GRAY_ALPHA || color_type == PNG_COLOR_TYPE_RGBA) ? (next_byte(data, size, &pos) % bit_depth) + 1 : 0;
     if (sig_bit.gray || sig_bit.red || sig_bit.green || sig_bit.blue || sig_bit.alpha) {
        png_set_sBIT(png_ptr, info_ptr, &sig_bit);
    }
  }

  // sCAL (Physical scale of image subject)
  if (chunk_flags2 & 0x08) {
    double scal_width = next_double_norm(data, size, &pos) * 100.0 + 1e-6; // Avoid 0
    double scal_height = next_double_norm(data, size, &pos) * 100.0 + 1e-6;
    png_set_sCAL(png_ptr, info_ptr, (next_byte(data, size, &pos) % 2) + 1, scal_width, scal_height); // unit 1:meter, 2:radian
  }
  
  // // tIME (Image last modification time)
  // if (chunk_flags2 & 0x10) {
  //   png_time mod_time;
  //   // Fuzz time fields or use current time
  //   if (next_byte(data, size, &pos) % 2 == 0) {
  //       png_convert_from_time_t(&mod_time, time(nullptr));
  //   } else {
  //       mod_time.year   = next_uint16(data, size, &pos);
  //       mod_time.month  = next_byte(data, size, &pos) % 12 + 1;
  //       mod_time.day    = next_byte(data, size, &pos) % 31 + 1;
  //       mod_time.hour   = next_byte(data, size, &pos) % 24;
  //       mod_time.minute = next_byte(data, size, &pos) % 60;
  //       mod_time.second = next_byte(data, size, &pos) % 60;
  //   }
  //   png_set_tIME(png_ptr, info_ptr, &mod_time);
  // }

  // cHRM (Primary chromaticities and white point)
  if (chunk_flags2 & 0x20) {
    png_set_cHRM_fixed(png_ptr, info_ptr,
        next_uint32(data, size, &pos) % 100000, next_uint32(data, size, &pos) % 100000, // white_x, white_y
        next_uint32(data, size, &pos) % 100000, next_uint32(data, size, &pos) % 100000, // red_x, red_y
        next_uint32(data, size, &pos) % 100000, next_uint32(data, size, &pos) % 100000, // green_x, green_y
        next_uint32(data, size, &pos) % 100000, next_uint32(data, size, &pos) % 100000  // blue_x, blue_y
    );
  }

  // oFFs (Image offset)
  if (chunk_flags2 & 0x40) {
    png_set_oFFs(png_ptr, info_ptr,
                 (png_int_32)next_uint32(data, size, &pos), // x_offset
                 (png_int_32)next_uint32(data, size, &pos), // y_offset
                 next_byte(data, size, &pos) % 2); // unit_type: 0 for pixel, 1 for micrometer
  }
  
  // pCAL (Calibration of pixel values)
  if (chunk_flags2 & 0x80) {
    pcal_purpose_str = next_string(data, size, &pos, 79, png_ptr);
    if (pcal_purpose_str) {
        png_int_32 pcal_X0 = (png_int_32)next_uint32(data, size, &pos);
        png_int_32 pcal_X1 = (png_int_32)next_uint32(data, size, &pos);
        int pcal_type = next_byte(data, size, &pos) % 4; // 0-3
        int pcal_nparams = next_byte(data, size, &pos) % 10; // 0-9 params
        pcal_units_str = next_string(data, size, &pos, 79, png_ptr);
        if (pcal_units_str && pcal_nparams > 0) {
            pcal_params_ptr = (png_int_32*)png_malloc(png_ptr, pcal_nparams * sizeof(png_int_32));
            if (!pcal_params_ptr) png_error(png_ptr, "OOM for pCAL params");
            // For simplicity, we'll use raw char* for params here, libpng expects char**
            // This part needs careful handling of param strings.
            // For now, let's skip actually filling pcal_params to avoid complexity with char**
            // and focus on calling the function.
            // A more robust fuzzer would create an array of C-strings for pcal_params.
            // For now, pass null to avoid complex string array management.
            // To properly fuzz pCAL params, you'd need to create an array of char*
            // where each char* is a fuzzed string.
            // Simplified:
            char** temp_pcal_params = (char**)png_malloc(png_ptr, pcal_nparams * sizeof(char*));
            if (!temp_pcal_params) png_error(png_ptr, "OOM for pCAL param strings array");
            for(int i=0; i<pcal_nparams; ++i) {
                temp_pcal_params[i] = next_string(data, size, &pos, 30, png_ptr);
                if (!temp_pcal_params[i]) { // If one string fails, clean up and skip
                    for(int j=0; j<i; ++j) png_free(png_ptr, temp_pcal_params[j]);
                    png_free(png_ptr, temp_pcal_params);
                    temp_pcal_params = nullptr;
                    break;
                }
            }

            if(temp_pcal_params) {
                 png_set_pCAL(png_ptr, info_ptr, pcal_purpose_str, pcal_X0, pcal_X1,
                         pcal_type, pcal_nparams, pcal_units_str, (png_charpp)temp_pcal_params);
                for(int i=0; i<pcal_nparams; ++i) png_free(png_ptr, temp_pcal_params[i]);
                png_free(png_ptr, temp_pcal_params);
            }

        } else if (pcal_units_str) { // nparams == 0
             png_set_pCAL(png_ptr, info_ptr, pcal_purpose_str, pcal_X0, pcal_X1,
                         pcal_type, 0, pcal_units_str, nullptr);
        }
        png_free(png_ptr, pcal_purpose_str); pcal_purpose_str = nullptr;
        png_free(png_ptr, pcal_units_str); pcal_units_str = nullptr;
        // pcal_params_ptr was not used directly with png_set_pCAL in this simplified version
        png_free(png_ptr, pcal_params_ptr); pcal_params_ptr = nullptr; // ensure it's freed if allocated
    }
  }

  uint8_t chunk_flags3 = next_byte(data, size, &pos);

  // sPLT (Suggested palette)
  if (chunk_flags3 & 0x01) {
    png_sPLT_t new_palette;
    new_palette.name = next_string(data, size, &pos, 79, png_ptr);
    if (new_palette.name) {
        new_palette.depth = (next_byte(data, size, &pos) % 2 == 0) ? 8 : 16;
        new_palette.nentries = next_uint16(data, size, &pos) % 256; // Max 255 entries for simplicity
        if (new_palette.nentries > 0) {
            new_palette.entries = (png_sPLT_entryp)png_malloc(png_ptr, new_palette.nentries * sizeof(png_sPLT_entry));
            if (!new_palette.entries) png_error(png_ptr, "OOM for sPLT entries");
            splt_entries_ptr = new_palette.entries; // for cleanup
            for (int i = 0; i < new_palette.nentries; ++i) {
                if (new_palette.depth == 8) {
                    new_palette.entries[i].red = next_byte(data, size, &pos);
                    new_palette.entries[i].green = next_byte(data, size, &pos);
                    new_palette.entries[i].blue = next_byte(data, size, &pos);
                    new_palette.entries[i].alpha = next_byte(data, size, &pos);
                } else { // 16-bit
                    new_palette.entries[i].red = next_uint16(data, size, &pos);
                    new_palette.entries[i].green = next_uint16(data, size, &pos);
                    new_palette.entries[i].blue = next_uint16(data, size, &pos);
                    new_palette.entries[i].alpha = next_uint16(data, size, &pos);
                }
                new_palette.entries[i].frequency = next_uint16(data, size, &pos);
            }
            png_set_sPLT(png_ptr, info_ptr, &new_palette, 1);
            // png_set_sPLT copies, so free ours
            png_free(png_ptr, new_palette.entries); splt_entries_ptr = nullptr;
        }
        png_free(png_ptr, new_palette.name);
    }
  }

  // eXIf (Exchangeable Image File Format)
  if (chunk_flags3 & 0x02) {
      png_uint_32 exif_len = (next_uint16(data, size, &pos) % 1024) +1; // 1-1024 bytes
      exif_ptr = (png_bytep)png_malloc(png_ptr, exif_len);
      if (!exif_ptr) png_error(png_ptr, "OOM for eXIf data");
      for(png_uint_32 i=0; i<exif_len; ++i) {
          exif_ptr[i] = next_byte(data, size, &pos);
      }
      png_set_eXIf(png_ptr, info_ptr, exif_ptr);
      // png_set_eXIf makes a copy for info_ptr->exif, but not for num_exif > 1
      // For single eXIf chunk, it's copied.
      png_free(png_ptr, exif_ptr); exif_ptr = nullptr;
  }
  
  // Unknown Chunks
  if (chunk_flags3 & 0x04) {
    int num_unknown = next_byte(data, size, &pos) % 3; // 0-2 unknown chunks
    if (num_unknown > 0) {
        unknown_chunks = (png_unknown_chunkp)png_malloc(png_ptr, num_unknown * sizeof(png_unknown_chunk));
        if (!unknown_chunks) png_error(png_ptr, "OOM for unknown_chunks");

        for (int i = 0; i < num_unknown; ++i) {
            // Name: 4 bytes. Ensure it's a valid chunk name (letters).
            for (int j=0; j<4; ++j) unknown_chunks[i].name[j] = (next_byte(data, size, &pos) % 26) + 'a';
            unknown_chunks[i].name[4] = '\0'; // Not strictly necessary for fixed 4-byte name

            unknown_chunks[i].size = next_byte(data, size, &pos) % 64; // Small unknown chunks
            if (unknown_chunks[i].size > 0) {
                unknown_chunks[i].data = (png_bytep)png_malloc(png_ptr, unknown_chunks[i].size);
                if (!unknown_chunks[i].data) png_error(png_ptr, "OOM for unknown chunk data");
                for (size_t k = 0; k < unknown_chunks[i].size; ++k) {
                    unknown_chunks[i].data[k] = next_byte(data, size, &pos);
                }
            } else {
                unknown_chunks[i].data = nullptr;
            }
            unknown_chunks[i].location = (next_byte(data, size, &pos) % 2 == 0) ? PNG_HAVE_IHDR : PNG_AFTER_IDAT;
        }
        png_set_unknown_chunks(png_ptr, info_ptr, unknown_chunks, num_unknown);
        // png_set_unknown_chunks copies the provided structures and their data.
        for (int i = 0; i < num_unknown; ++i) {
            png_free(png_ptr, unknown_chunks[i].data);
        }
        png_free(png_ptr, unknown_chunks); unknown_chunks = nullptr;
    }
  }


  // --- Header write ---
  png_write_info(png_ptr, info_ptr);

  // --- Allocate and fill row data ---
  png_size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  const size_t kMaxImageBytes = 16 * 1024 * 1024; // Cap at 16 MiB to prevent huge allocations

  if (rowbytes == 0 || (height > 0 && rowbytes > kMaxImageBytes / height) ) { // Check for overflow before multiplication
    // This image would be too large, skip actual image data writing
    // but still call png_write_end for completeness of the PNG structure.
  } else {
    row_pointers = (png_bytepp)png_malloc(png_ptr, height * sizeof(png_bytep));
    if (!row_pointers) png_error(png_ptr, "OOM for row_pointers");

    for (uint32_t y = 0; y < height; ++y) {
      row_pointers[y] = (png_bytep)png_malloc(png_ptr, rowbytes);
      if (!row_pointers[y]) {
          rows_allocated_count = y; // Save how many were actually allocated
          png_error(png_ptr, "OOM for a row"); // This will longjmp
      }
      rows_allocated_count++;
      for (png_size_t i = 0; i < rowbytes; ++i) {
        row_pointers[y][i] = next_byte(data, size, &pos);
      }
    }
    png_set_rows(png_ptr, info_ptr, row_pointers);

    // --- Encode image ---
    // png_write_png is a high-level function; direct png_write_image is used here.
    png_write_image(png_ptr, row_pointers);
  }

  // --- End of PNG ---
  png_write_end(png_ptr, info_ptr); // Pass info_ptr for trailing chunks if any

  // --- Normal cleanup ---
  if (row_pointers) {
    for (uint32_t i = 0; i < rows_allocated_count; ++i) {
      png_free(png_ptr, row_pointers[i]);
    }
    png_free(png_ptr, row_pointers);
  }
  // Other dynamically allocated resources for chunks were typically freed after their png_set_* call
  // if libpng copies them, or would be freed in the longjmp path.
  // Ensure any helpers like next_string that use png_malloc and aren't passed to png_set (or are but not copied)
  // are freed here too if not handled by longjmp path.
  // The current structure for iccp_name_str, etc., frees them after use or relies on longjmp.

  png_destroy_write_struct(&png_ptr, &info_ptr);
  return 0;
}
