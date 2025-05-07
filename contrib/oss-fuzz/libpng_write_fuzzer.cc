// File: libpng_full_write_fuzzer.cc
// Fuzz target exercising libpng’s full write API (pngwrite.c)
// Revised to treat `data[]` as a ring buffer and avoid ANY out-of-bounds.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <ctime>
#include <setjmp.h>
#include <algorithm>
#include <string>

#include "png.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8) return 0;

    // A helper to read any byte at offset (wraps around size)
    auto read_byte = [&](size_t offset) -> uint8_t {
        return data[offset % size];
    };

    // 1) Parse basic params from first 6 bytes (safe via read_byte)
    uint32_t w = ((uint32_t(read_byte(0)) << 8) | read_byte(1)) % 256 + 1;
    uint32_t h = ((uint32_t(read_byte(2)) << 8) | read_byte(3)) % 256 + 1;
    static const int color_types[] = {
        PNG_COLOR_TYPE_GRAY,
        PNG_COLOR_TYPE_RGB,
        PNG_COLOR_TYPE_PALETTE,
        PNG_COLOR_TYPE_GRAY_ALPHA,
        PNG_COLOR_TYPE_RGBA
    };
    static const int bit_depths[] = {1,2,4,8,16};
    int ct = read_byte(4) % 5;
    int bd = read_byte(5) % 5;
    int color_type = color_types[ct];
    int bit_depth  = bit_depths[bd];

    // 2) Create write structs
    png_structp png_ptr = png_create_write_struct(
        PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png_ptr) return 0;
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_write_struct(&png_ptr, nullptr);
        return 0;
    }
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_write_struct(&png_ptr, &info_ptr);
        return 0;
    }

    // 3) In-memory write
    struct Mem { std::vector<uint8_t> buf; } mem;
    auto write_cb = [](png_structp p, png_bytep d, png_size_t len){
        auto m = reinterpret_cast<Mem*>(png_get_io_ptr(p));
        m->buf.insert(m->buf.end(), d, d + len);
    };
    auto flush_cb = [](png_structp){};
    png_set_write_fn(png_ptr, &mem, write_cb, flush_cb);

    // 4) IHDR + interlace+filter/compression defaults
    png_set_IHDR(png_ptr, info_ptr,
                 w, h, bit_depth, color_type,
                 PNG_INTERLACE_ADAM7,
                 PNG_COMPRESSION_TYPE_BASE,
                 PNG_FILTER_TYPE_BASE);

    // 5) Flags & chunk writers
    // Use bytes 6/7 for a 16-bit flag word
    uint16_t flags = (uint16_t(read_byte(6)) << 8) | read_byte(7);
    size_t pos = 8;

    // PLTE
    if ((flags & 0x0001) &&
        (color_type == PNG_COLOR_TYPE_PALETTE ||
         color_type == PNG_COLOR_TYPE_RGB)) {
        int n = read_byte(pos++) % 16 + 1;
        std::vector<png_color> plt(n);
        for (int i = 0; i < n; i++) {
            plt[i].red   = read_byte(pos++);
            plt[i].green = read_byte(pos++);
            plt[i].blue  = read_byte(pos++);
        }
        png_set_PLTE(png_ptr, info_ptr, plt.data(), n);
    }

    // tEXt
    if (flags & 0x0002) {
        png_text text;
        text.compression = PNG_TEXT_COMPRESSION_zTXt;
        text.key         = const_cast<png_charp>("Desc");
        int len = std::min<int>(50, int(size)); 
        static std::string txt;
        txt.resize(len);
        for (int i = 0; i < len; i++) txt[i] = read_byte(pos++);
        text.text = const_cast<png_charp>(txt.c_str());
        png_set_text(png_ptr, info_ptr, &text, 1);
    }

    // iCCP
    if (flags & 0x0004) {
        png_uint_32 clen = std::min<png_uint_32>(100, png_uint_32(size));
        std::vector<png_byte> profile(clen);
        for (png_uint_32 i = 0; i < clen; i++) profile[i] = read_byte(pos++);
        png_set_iCCP(png_ptr, info_ptr,
                     (png_const_charp)"prof",
                     PNG_COMPRESSION_TYPE_BASE,
                     profile.data(), clen);
    }

    // bKGD
    if (flags & 0x0008) {
        png_color_16 bg;
        bg.red   = (uint16_t(read_byte(pos++)) << 8) | read_byte(pos++);
        bg.green = (uint16_t(read_byte(pos++)) << 8) | read_byte(pos++);
        bg.blue  = (uint16_t(read_byte(pos++)) << 8) | read_byte(pos++);
        png_set_bKGD(png_ptr, info_ptr, &bg);
    }

    // gAMA
    if (flags & 0x0010) {
        double gamma = 0.01 + (read_byte(pos++) / 255.0) * 10.0;
        png_set_gAMA(png_ptr, info_ptr, gamma);
    }

    // pHYs
    if (flags & 0x0020) {
        png_set_pHYs(png_ptr, info_ptr,
                     read_byte(pos++),
                     read_byte(pos++),
                     PNG_RESOLUTION_METER);
    }

    // sBIT
    if (flags & 0x0040) {
        png_color_8 sig;
        sig.red   = read_byte(pos++) & 0x1F;
        sig.green = read_byte(pos++) & 0x1F;
        sig.blue  = read_byte(pos++) & 0x1F;
        sig.alpha = read_byte(pos++) & 0x1F;
        png_set_sBIT(png_ptr, info_ptr, &sig);
    }

    // sCAL
    if (flags & 0x0080) {
        png_set_sCAL(png_ptr, info_ptr,
                     PNG_SCALE_METER, 1.0, 1.0);
    }

    // hIST
    if ((flags & 0x0100) && color_type == PNG_COLOR_TYPE_PALETTE) {
        int n; png_colorp pal;
        png_get_PLTE(png_ptr, info_ptr, &pal, &n);
        if (n > 0) {
            std::vector<png_uint_16> hist(n);
            for (int i = 0; i < n; i++) hist[i] = read_byte(pos++);
            png_set_hIST(png_ptr, info_ptr,
                         (png_const_uint_16p)hist.data());
        }
    }

    // tIME
    if (flags & 0x0200) {
        png_time mod_time;
        png_convert_from_time_t(&mod_time, std::time(nullptr));
        png_set_tIME(png_ptr, info_ptr, &mod_time);
    }

    // sRGB
    if (flags & 0x0400) {
        png_set_sRGB(png_ptr, info_ptr, PNG_sRGB_INTENT_PERCEPTUAL);
    }

    // 6) Write header
    png_write_info(png_ptr, info_ptr);

    // 7) Safe row preparation: per-byte fill
    size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    std::vector<png_bytep> rows(h);
    for (uint32_t y = 0; y < h; y++) {
        rows[y] = (png_bytep)malloc(rowbytes);
        for (size_t i = 0; i < rowbytes; i++) {
            rows[y][i] = read_byte(pos++);
        }
    }
    png_set_rows(png_ptr, info_ptr, rows.data());

    // 8) Write image + end
    png_write_image(png_ptr, rows.data());
    png_write_end(png_ptr, info_ptr);

    // 9) Cleanup
    for (auto r : rows) free(r);
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}
