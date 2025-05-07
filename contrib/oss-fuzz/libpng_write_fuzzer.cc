#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <ctime>
#include <setjmp.h>

#include "png.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8) return 0;

    //1) Parse basic image parameters (keep dims small)
    uint32_t w  = (((uint32_t)data[0] << 8) | data[1]) % 256 + 1;
    uint32_t h  = (((uint32_t)data[2] << 8) | data[3]) % 256 + 1;
    static const int color_types[] = {
        PNG_COLOR_TYPE_GRAY,
        PNG_COLOR_TYPE_RGB,
        PNG_COLOR_TYPE_PALETTE,
        PNG_COLOR_TYPE_GRAY_ALPHA,
        PNG_COLOR_TYPE_RGBA
    };
    static const int bit_depths[] = {1,2,4,8,16};
    int ct = data[4] % 5;
    int bd = data[5] % 5;
    int color_type = color_types[ct];
    int bit_depth  = bit_depths[bd];

    //2) Create write structs
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

    //3) In‐memory write callbacks
    struct Mem { std::vector<uint8_t> buf; };
    Mem mem;
    auto write_cb = [](png_structp p, png_bytep d, png_size_t len){
        auto m = reinterpret_cast<Mem*>(png_get_io_ptr(p));
        m->buf.insert(m->buf.end(), d, d+len);
    };
    auto flush_cb = [](png_structp){};
    png_set_write_fn(png_ptr, &mem, write_cb, flush_cb);

    //4) IHDR + default ADAM7, BASE compression/filter
    png_set_IHDR(png_ptr, info_ptr,
                 w, h, bit_depth, color_type,
                 PNG_INTERLACE_ADAM7,
                 PNG_COMPRESSION_TYPE_BASE,
                 PNG_FILTER_TYPE_BASE);

    //5) Ancillary chunks driven by flags (use two bytes → 16 bits)
    uint16_t flags = ((uint16_t)data[6] << 8) | data[7];
    size_t pos = 8;

    if (flags & 0x0001) {
        //PLTE
        if (color_type == PNG_COLOR_TYPE_PALETTE ||
            color_type == PNG_COLOR_TYPE_RGB) {
            int n = std::min<int>(data[pos++ % size], 16);
            if (n < 1) n = 1;
            std::vector<png_color> plt(n);
            for (int i = 0; i < n; i++) {
                plt[i].red   = data[pos++ % size];
                plt[i].green = data[pos++ % size];
                plt[i].blue  = data[pos++ % size];
            }
            png_set_PLTE(png_ptr, info_ptr, plt.data(), n);
        }
    }
    if (flags & 0x0002) {
        //tEXt
        png_text text;
        text.compression = PNG_TEXT_COMPRESSION_zTXt;
        text.key         = const_cast<png_charp>("Desc");
        int len = std::min<int>(size - pos, 50);
        static std::string txt;
        txt.assign(reinterpret_cast<const char*>(data+pos), len);
        text.text = const_cast<png_charp>(txt.c_str());
        png_set_text(png_ptr, info_ptr, &text, 1);
        pos += len;
    }
    if (flags & 0x0004) {
        //iCCP
        int clen = std::min<int>(size - pos, 100);
        png_charp profile = (png_charp)malloc(clen);
        memcpy(profile, data+pos, clen);
        png_set_iCCP(png_ptr, info_ptr,
                     const_cast<png_charp>("prof"), PNG_COMPRESSION_TYPE_BASE,
                     (png_charp)profile, clen);
        free(profile);
        pos += clen;
    }
    if (flags & 0x0008) {
        //bKGD
        png_color_16 bg;
        bg.red   = ((uint16_t)data[pos%size] << 8) | data[(pos+1)%size];
        bg.green = ((uint16_t)data[(pos+2)%size] << 8) | data[(pos+3)%size];
        bg.blue  = ((uint16_t)data[(pos+4)%size] << 8) | data[(pos+5)%size];
        png_set_bKGD(png_ptr, info_ptr, &bg);
        pos += 6;
    }
    if (flags & 0x0010) {
        //gAMA
        double gamma = 0.01 + (data[pos++ % size] / 255.0) * 10.0;
        png_set_gAMA(png_ptr, info_ptr, gamma);
    }
    if (flags & 0x0020) {
        //pHYs
        png_set_pHYs(png_ptr, info_ptr,
                     (png_uint_32)data[pos%size],
                     (png_uint_32)data[(pos+1)%size],
                     PNG_RESOLUTION_METER);
        pos += 2;
    }
    if (flags & 0x0040) {
        //sBIT
        png_color_8 sig;
        sig.red   = data[pos++] & 0x1F;
        sig.green = data[pos++] & 0x1F;
        sig.blue  = data[pos++] & 0x1F;
        sig.alpha = data[pos++] & 0x1F;
        png_set_sBIT(png_ptr, info_ptr, &sig);
    }
    if (flags & 0x0080) {
        //sCAL (must pass doubles, not strings)
        png_set_sCAL(png_ptr, info_ptr,
                     PNG_SCALE_METER,
                     /* width */  1.0,
                     /* height */ 1.0);
    }
    if (flags & 0x0100) {
        //hIST (only valid if PLTE is set)
        if (png_get_color_type(png_ptr, info_ptr) == PNG_COLOR_TYPE_PALETTE) {
            png_color_16p hist = (png_color_16p)malloc(
                png_get_palette_max(png_ptr, info_ptr) * sizeof(png_color_16));
            //fill from fuzz data
            for (int i = 0; i < png_get_palette_max(png_ptr, info_ptr); i++) {
                hist[i].red   = data[pos%size];
                hist[i].green = data[(pos+1)%size];
                hist[i].blue  = data[(pos+2)%size];
                pos += 3;
            }
            png_set_hIST(png_ptr, info_ptr, hist);
            free(hist);
        }
    }
    if (flags & 0x0200) {
        //tIME
        png_time mod_time;
        png_convert_from_time_t(&mod_time, std::time(nullptr));
        png_set_tIME(png_ptr, info_ptr, &mod_time);
    }
    if (flags & 0x0400) {
        //sRGB
        png_set_sRGB(png_ptr, info_ptr, PNG_sRGB_INTENT_PERCEPTUAL);
    }

    //6) Write header
    png_write_info(png_ptr, info_ptr);

    //7) Prepare rows
    int channels = png_get_channels(png_ptr, info_ptr);
    size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    std::vector<png_bytep> rows(h);
    for (uint32_t y = 0; y < h; y++) {
        rows[y] = (png_bytep)malloc(rowbytes);
        memcpy(rows[y],
               data + pos + (y * rowbytes) % (size - pos),
               rowbytes);
    }
    png_set_rows(png_ptr, info_ptr, rows.data());

    //8) Write image + end
    png_write_image(png_ptr, rows.data());
    png_write_end(png_ptr, info_ptr);

    //9) Cleanup
    for (auto r : rows) free(r);
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}
