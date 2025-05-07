// libpng_full_write_fuzzer.cc
// Leak-free, OOM-safe write harness for libpng

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <setjmp.h>
#include "png.h"

/* ------------------------------------------------------------------ */
/* Helper: wrap-around byte reader                                    */
static inline uint8_t next_byte(const uint8_t* d, size_t sz, size_t* p) {
  uint8_t v = d[*p % sz];
  ++(*p);
  return v;
}
/* ------------------------------------------------------------------ */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 8) return 0;
  size_t pos = 0;

/* ---- choose modest IHDR so png_get_rowbytes() is in-range --------- */
  uint32_t w = (((uint32_t)next_byte(data,size,&pos) << 8) |
                 next_byte(data,size,&pos)) % 256 + 1;
  uint32_t h = (((uint32_t)next_byte(data,size,&pos) << 8) |
                 next_byte(data,size,&pos)) % 256 + 1;
  static const int cts[] = {PNG_COLOR_TYPE_GRAY, PNG_COLOR_TYPE_RGB,
                            PNG_COLOR_TYPE_PALETTE, PNG_COLOR_TYPE_GRAY_ALPHA,
                            PNG_COLOR_TYPE_RGBA};
  static const int bds[] = {1, 2, 4, 8, 16};
  int color_type = cts[next_byte(data,size,&pos) % 5];
  int bit_depth  = bds[next_byte(data,size,&pos) % 5];

/* ---- libpng init --------------------------------------------------- */
  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,
                                               nullptr,nullptr,nullptr);
  if (!png_ptr) return 0;
  png_infop info_ptr  = png_create_info_struct(png_ptr);
  if (!info_ptr) { png_destroy_write_struct(&png_ptr,nullptr); return 0; }

/* ---- buffers to free in any path ---------------------------------- */
  png_bytep* rows = nullptr;  uint32_t rows_alloc = 0;
  uint16_t*  hist = nullptr;  /* freed right after write_info() */
  /* (temporary ICC profile freed immediately after png_set_iCCP) */

/* ---- longjmp cleanup ---------------------------------------------- */
  if (setjmp(png_jmpbuf(png_ptr))) {
    for (uint32_t i = 0; i < rows_alloc; ++i) free(rows[i]);
    free(rows);
    free(hist);
    png_destroy_write_struct(&png_ptr,&info_ptr);
    return 0;
  }

/* ---- discard-all write callback (prevents OOM from giant chunks) --- */
  png_set_write_fn(
      png_ptr, nullptr,
      [](png_structp, png_bytep, png_size_t) {/* drop bytes */},
      nullptr);

/* ---- IHDR ---------------------------------------------------------- */
  png_set_IHDR(png_ptr, info_ptr, w, h, bit_depth, color_type,
               PNG_INTERLACE_ADAM7, PNG_COMPRESSION_TYPE_BASE,
               PNG_FILTER_TYPE_BASE);

/* ---- ancillary chunks driven by 16 flag bits ---------------------- */
  uint16_t flags = ((uint16_t)next_byte(data,size,&pos) << 8) |
                   next_byte(data,size,&pos);

  /* PLTE */
  if ((flags & 0x0001) &&
      (color_type == PNG_COLOR_TYPE_PALETTE || color_type == PNG_COLOR_TYPE_RGB))
  {
    int n = 1 + (next_byte(data,size,&pos) % 16);
    png_color pal[16];
    for (int i = 0; i < n; ++i) {
      pal[i].red   = next_byte(data,size,&pos);
      pal[i].green = next_byte(data,size,&pos);
      pal[i].blue  = next_byte(data,size,&pos);
    }
    png_set_PLTE(png_ptr, info_ptr, pal, n);
  }

  /* tEXt */
  if (flags & 0x0002) {
    char txt[50];
    for (int i = 0; i < 50; ++i) txt[i] = next_byte(data,size,&pos);
    png_text t{}; t.compression = PNG_TEXT_COMPRESSION_zTXt;
    t.key  = (png_charp)"Desc";
    t.text = txt;
    png_set_text(png_ptr, info_ptr, &t, 1);
  }

  /* iCCP (profile copied, free immediately) */
  if (flags & 0x0004) {
    int clen = 20 + (next_byte(data,size,&pos) % 80);
    uint8_t* iccp = (uint8_t*)malloc(clen);
    for (int i = 0; i < clen; ++i) iccp[i] = next_byte(data,size,&pos);
    png_set_iCCP(png_ptr, info_ptr, (png_const_charp)"prof",
                 PNG_COMPRESSION_TYPE_BASE, iccp, clen);
    free(iccp);
  }

  /* bKGD */
  if (flags & 0x0008) {
    png_color_16 bg;
    bg.red   = (next_byte(data,size,&pos)<<8) | next_byte(data,size,&pos);
    bg.green = (next_byte(data,size,&pos)<<8) | next_byte(data,size,&pos);
    bg.blue  = (next_byte(data,size,&pos)<<8) | next_byte(data,size,&pos);
    png_set_bKGD(png_ptr, info_ptr, &bg);
  }

  /* gAMA */
  if (flags & 0x0010) {
    double g = 0.01 + (next_byte(data,size,&pos) / 255.0) * 10.0;
    png_set_gAMA(png_ptr, info_ptr, g);
  }

  /* pHYs */
  if (flags & 0x0020) {
    png_set_pHYs(png_ptr, info_ptr,
                 next_byte(data,size,&pos),
                 next_byte(data,size,&pos),
                 PNG_RESOLUTION_METER);
  }

  /* sBIT */
  if (flags & 0x0040) {
    png_color_8 sb{
        (png_byte)(next_byte(data,size,&pos)&0x1F),
        (png_byte)(next_byte(data,size,&pos)&0x1F),
        (png_byte)(next_byte(data,size,&pos)&0x1F),
        (png_byte)(next_byte(data,size,&pos)&0x1F)};
    png_set_sBIT(png_ptr, info_ptr, &sb);
  }

  /* sCAL */
  if (flags & 0x0080)
    png_set_sCAL(png_ptr, info_ptr, PNG_SCALE_METER, 1.0, 1.0);

  /* hIST */
  if ((flags & 0x0100) && color_type == PNG_COLOR_TYPE_PALETTE) {
    int n; png_colorp pal; png_get_PLTE(png_ptr, info_ptr, &pal, &n);
    if (n > 0) {
      hist = (uint16_t*)malloc(sizeof(uint16_t)*n);
      for (int i = 0; i < n; ++i) hist[i] = next_byte(data,size,&pos);
      png_set_hIST(png_ptr, info_ptr, hist);
    }
  }

  /* tIME */
  if (flags & 0x0200) {
    png_time tm; png_convert_from_time_t(&tm, std::time(nullptr));
    png_set_tIME(png_ptr, info_ptr, &tm);
  }

  /* sRGB */
  if (flags & 0x0400)
    png_set_sRGB(png_ptr, info_ptr, PNG_sRGB_INTENT_PERCEPTUAL);

/* ---- header write (hIST consumed) --------------------------------- */
  png_write_info(png_ptr, info_ptr);
  free(hist); hist = nullptr;

/* ---- allocate rows with hard cap ---------------------------------- */
  size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  const size_t kMaxImageBytes = 32 * 1024 * 1024; /* 32 MiB */
  if (rowbytes == 0 || (uint64_t)rowbytes * h > kMaxImageBytes) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;                                      /* skip oversized img */
  }

  rows = (png_bytep*)malloc(sizeof(png_bytep) * h);
  for (uint32_t y = 0; y < h; ++y) {
    rows[y] = (png_bytep)malloc(rowbytes);
    ++rows_alloc;
    for (size_t i = 0; i < rowbytes; ++i)
      rows[y][i] = next_byte(data,size,&pos);
  }
  png_set_rows(png_ptr, info_ptr, rows);

/* ---- encode image -------------------------------------------------- */
  png_write_image(png_ptr, rows);
  png_write_end  (png_ptr, info_ptr);

/* ---- normal cleanup ------------------------------------------------ */
  for (uint32_t i = 0; i < rows_alloc; ++i) free(rows[i]);
  free(rows);
  png_destroy_write_struct(&png_ptr, &info_ptr);
  return 0;
}
