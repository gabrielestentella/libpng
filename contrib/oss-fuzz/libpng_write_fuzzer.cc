// libpng classic‑writer fuzz harness
// Builds on the original libpng_write_fuzzer but exercises the full writer
// surface by driving the low‑level API (png_write_image / png_write_rows).
//
// Practical‑tips integrated:
//   • fuzz‑controlled IHDR (bit depth, colour type, interlace)
//   • png_set_compression_level() 0‑9
//   • png_set_filter() to hit every filter path
//   • negative row‑stride option
//   • choice between single‑call png_write_image() and row‑at‑a‑time png_write_rows()
//
// The harness keeps allocations below 1 MiB to remain AFL/OSSFuzz‑friendly.
//
#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <cstring>
#include "png.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Need at least a small header for parameters */
  if (size < 20) return 0;

  /* ─── Parameter decoding ─────────────────────────────────────────────── */
  size_t idx = 0;
  const uint8_t w_b  = data[idx++];               /* width  (1‑256)  */
  const uint8_t h_b  = data[idx++];               /* height (1‑256)  */
  const uint8_t cfg  = data[idx++];
  const uint8_t comp = data[idx++] % 10;          /* zlib level 0‑9  */
  const uint8_t filt = data[idx++] % 6;           /* filter variant  */
  const uint8_t mode = data[idx++] & 1;           /* 0=image,1=rows  */

  /* bits in cfg */
  const bool bit16      = cfg & 0x01;             /* 0=8‑bit, 1=16‑bit */
  const uint8_t ct_bits = (cfg >> 1) & 0x03;      /* colour‑type selector */
  const bool interlaced = cfg & 0x08;             /* Adam7 on/off */
  const bool negstride  = cfg & 0x10;             /* reverse rows */

  png_uint_32 width  = static_cast<png_uint_32>(w_b) + 1;
  png_uint_32 height = static_cast<png_uint_32>(h_b) + 1;

  int colour_type;
  int bpp; /* bytes per pixel (not bits) */
  switch (ct_bits) {
    case 0:  colour_type = PNG_COLOR_TYPE_GRAY;  bpp = 1; break;
    case 1:  colour_type = PNG_COLOR_TYPE_RGB;   bpp = 3; break;
    default: colour_type = PNG_COLOR_TYPE_RGBA;  bpp = 4; break; /* fallback */
  }

  int bit_depth = bit16 ? 16 : 8;
  bpp *= (bit_depth == 16) ? 2 : 1;

  /* guard against pathological allocations */
  size_t need = static_cast<size_t>(width) * height * bpp;
  if (need == 0 || need > (1 << 20) || size - idx < need) return 0;

  const uint8_t *src_pixels = data + idx;
  std::vector<uint8_t> pixels(src_pixels, src_pixels + need);

  /* ─── libpng setup ───────────────────────────────────────────────────── */
  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return 0;
  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) { png_destroy_write_struct(&png_ptr, nullptr); return 0; }
  if (setjmp(png_jmpbuf(png_ptr))) { png_destroy_write_struct(&png_ptr, &info_ptr); return 0; }

  /* write into an in‑memory vector so we don't touch the FS */
  std::vector<png_byte> out;
  auto write_cb = [](png_structp p, png_bytep d, png_size_t l) {
    auto *vec = static_cast<std::vector<png_byte>*>(png_get_io_ptr(p));
    vec->insert(vec->end(), d, d + l);
  };
  png_set_write_fn(png_ptr, &out, write_cb, nullptr);

  png_set_IHDR(png_ptr, info_ptr,
               width, height,
               bit_depth, colour_type,
               interlaced ? PNG_INTERLACE_ADAM7 : PNG_INTERLACE_NONE,
               PNG_COMPRESSION_TYPE_DEFAULT,
               PNG_FILTER_TYPE_DEFAULT);

  png_set_compression_level(png_ptr, comp);

  static const int filter_tbl[6] = {
    PNG_NO_FILTERS,
    PNG_FILTER_NONE,
    PNG_FILTER_SUB,
    PNG_FILTER_UP,
    PNG_FILTER_AVG,
    PNG_FILTER_PAETH
  };
  png_set_filter(png_ptr, 0, filter_tbl[filt]);

  png_write_info(png_ptr, info_ptr);

  /* Row‑pointer table — forward or reversed */
  std::vector<png_bytep> rows(height);
  if (!negstride) {
    for (png_uint_32 y = 0; y < height; ++y)
      rows[y] = pixels.data() + y * width * bpp;
  } else {
    for (png_uint_32 y = 0; y < height; ++y)
      rows[y] = pixels.data() + (height - 1 - y) * width * bpp;
  }

  /* ─── Encode ─────────────────────────────────────────────────────────── */
  if (!mode) {
    /* single‑call path */
    png_write_image(png_ptr, rows.data());
  } else {
    /* row‑at‑a‑time path with interlace handling */
    const int passes = png_set_interlace_handling(png_ptr);
    for (int pass = 0; pass < passes; ++pass) {
      for (png_uint_32 y = 0; y < height; ++y)
        png_write_rows(png_ptr, &rows[y], 1);
    }
  }

  png_write_end(png_ptr, info_ptr);
  png_destroy_write_struct(&png_ptr, &info_ptr);
  return 0;
}
