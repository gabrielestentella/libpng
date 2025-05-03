// libpng_write_fuzzer_augmented.cc – extended harness to exercise critical write paths
// Leak‑safe, duplication‑free version.
// Sections marked with "// *** NEW ***" are the main additions.

#include <png.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <algorithm>

// === *** NEW *** helper that injects one application‑defined ancillary chunk ===
#ifdef PNG_SET_UNKNOWN_CHUNKS_SUPPORTED
static void AddUnknownChunk(png_structp png_ptr, png_infop info_ptr,
                            const uint8_t *data, size_t size) {
  if (size < 8) return;                       // need 4‑byte name + ≥4‑byte payload
  png_unknown_chunk unk{};
  memcpy(unk.name, data, 4);                  // chunk name (may be invalid – fine for fuzz)
  unk.size = static_cast<png_uint_32>(size - 4);
  unk.data = const_cast<png_byte *>(data + 4);// point to fuzz buffer (read‑only for libpng)
  unk.location = PNG_HAVE_IHDR;               // write before PLTE/IDAT
  png_set_unknown_chunks(png_ptr, info_ptr, &unk, 1);
  png_set_unknown_chunk_location(png_ptr, info_ptr, 0, PNG_HAVE_IHDR);
}
#else   // fallback stub when unknown‑chunk support is disabled
static void AddUnknownChunk(png_structp, png_infop, const uint8_t *, size_t) {}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 20) return 0;

  // === basic image descriptor ===
  png_image image{};
  image.version = PNG_IMAGE_VERSION;
  image.width  = static_cast<uint32_t>(data[0] + 1);
  image.height = static_cast<uint32_t>(data[1] + 1);
  image.width  += (static_cast<uint32_t>(data[4] & 0x3F) << 8);   // widen for IHDR checks
  image.height += (static_cast<uint32_t>(data[5] & 0x3F) << 8);

  uint8_t colour_sel = data[2] % 3;
  image.format = (colour_sel == 1) ? PNG_FORMAT_GRAY : PNG_FORMAT_RGBA;

  uint8_t ctrl = data[3];
  bool want_plte    = ctrl & 1;
  bool want_trns    = ctrl & 2;
  bool want_unknown = ctrl & 4;
  bool want_time    = ctrl & 8;

  size_t pixel_bytes = PNG_IMAGE_SIZE(image);
  if (pixel_bytes == 0 || pixel_bytes > size - 10) return 0;

  const uint8_t *pixels = data + 10;

  // === traditional write API ===
  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return 0;
  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) { png_destroy_write_struct(&png_ptr, nullptr); return 0; }

  struct OutBuf { png_bytep buf; png_size_t size; } ob{nullptr, 0};
  if (setjmp(png_jmpbuf(png_ptr))) {            // single setjmp handles all errors
    png_destroy_write_struct(&png_ptr, &info_ptr);
    free(ob.buf);
    return 0;
  }

  auto write_fn = [](png_structp png_ptr, png_bytep data, png_size_t length) {
    auto *ob = static_cast<OutBuf *>(png_get_io_ptr(png_ptr));
    png_bytep nb = static_cast<png_bytep>(realloc(ob->buf, ob->size + length));
    if (!nb) png_error(png_ptr, "oom");
    memcpy(nb + ob->size, data, length);
    ob->buf = nb; ob->size += length;
  };
  png_set_write_fn(png_ptr, &ob, write_fn, nullptr);(png_ptr, &ob, write_fn, nullptr);

  png_set_IHDR(png_ptr, info_ptr,
               image.width, image.height,
               8,
               (colour_sel == 1) ? PNG_COLOR_TYPE_GRAY : PNG_COLOR_TYPE_RGBA,
               PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

  // === *** NEW *** palette & transparency ===
  if (want_plte) {
    png_color palette[256];
    for (int i = 0; i < 256; ++i) {
      palette[i].red   = static_cast<png_byte>(i);
      palette[i].green = static_cast<png_byte>(255 - i);
      palette[i].blue  = static_cast<png_byte>((i * 17) & 0xFF);
    }
    png_set_PLTE(png_ptr, info_ptr, palette, 256);
    if (want_trns) {
      png_byte alphas[256];
      for (int i = 0; i < 256; ++i) alphas[i] = static_cast<png_byte>(i);
      png_set_tRNS(png_ptr, info_ptr, alphas, 256, nullptr);
    }
  }

  // === *** NEW *** unknown chunk injection ===
  if (want_unknown) {
    size_t tail = size - pixel_bytes;
    size_t unksz = tail > 40 ? 32 : (tail > 12 ? tail - 8 : 0);
    if (unksz) AddUnknownChunk(png_ptr, info_ptr, data + size - unksz, unksz);
  }

  png_write_info(png_ptr, info_ptr);

  size_t row_stride = (colour_sel == 1) ? image.width : image.width * 4;
  png_bytep row = const_cast<png_bytep>(pixels);
  for (uint32_t y = 0; y < image.height && y * row_stride < pixel_bytes; ++y) {
    png_write_row(png_ptr, row + y * row_stride);
  }

  if (want_time) {
    png_time mod; png_convert_from_time_t(&mod, time(nullptr));
    png_set_tIME(png_ptr, info_ptr, &mod);
  }

  png_write_end(png_ptr, info_ptr);
  png_destroy_write_struct(&png_ptr, &info_ptr);
  free(ob.buf);
  return 0;
}
