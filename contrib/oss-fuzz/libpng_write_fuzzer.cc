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

    //1. Parse basic image parameters (keep dims small to avoid huge allocs)
    uint32_t w = ((data[0] << 8) | data[1]) % 256 + 1;
    uint32_t h = ((data[2] << 8) | data[3]) % 256 + 1;
    static const int color_types[] = {
        PNG_COLOR_TYPE_GRAY,
        PNG_COLOR_TYPE_RGB,
        PNG_COLOR_TYPE_PALETTE,
        PNG_COLOR_TYPE_GRAY_ALPHA,
        PNG_COLOR_TYPE_RGBA
    };
    static const int bit_depths[] = {1,2,4,8,16};
    int ct_idx = data[4] % 5;
    int bd_idx = data[5] % 5;
    int color_type = color_types[ct_idx];
    int bit_depth  = bit_depths[bd_idx];

    //2. Create write struct + info struct
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

    //3. Install a memory‐write callback
    struct Mem { std::vector<uint8_t> buf; };
    Mem mem;
    auto write_cb = [](png_structp p, png_bytep d, png_size_t len){
        reinterpret_cast<Mem*>(png_get_io_ptr(p))
          ->buf.insert( 
              reinterpret_cast<Mem*>(png_get_io_ptr(p))
                ->buf.end(), d, d+len);
    };
    auto flush_cb = [](png_structp){};
    png_set_write_fn(png_ptr, &mem, write_cb, flush_cb);

    //4. IHDR + defaults
    png_set_IHDR(png_ptr, info_ptr,
                 w, h, bit_depth, color_type,
                 PNG_INTERLACE_ADAM7,
                 PNG_COMPRESSION_TYPE_BASE,
                 PNG_FILTER_TYPE_BASE);

    //5. Optional chunks/transforms driven by flags byte
    uint8_t flags = data[6];
    size_t pos = 7;

    if (flags & 1) {
        //PLTE for palette or RGB
        if (color_type==PNG_COLOR_TYPE_PALETTE ||
            color_type==PNG_COLOR_TYPE_RGB) {
            int n = std::min<int>(data[pos++ % size], 16);
            if (n<1) n=1;
            std::vector<png_color> plt(n);
            for (int i=0; i<n; i++) {
                plt[i].red   = data[pos++ % size];
                plt[i].green = data[pos++ % size];
                plt[i].blue  = data[pos++ % size];
            }
            png_set_PLTE(png_ptr, info_ptr, plt.data(), n);
        }
    }

    if (flags & 2) {
        //tEXt chunk
        png_text text;
        text.compression = PNG_TEXT_COMPRESSION_zTXt;
        text.key         = const_cast<png_charp>("Description");
        int len = std::min<int>(size - pos, 50);
        static std::string txt;
        txt.assign(reinterpret_cast<const char*>(data+pos), len);
        text.text = const_cast<png_charp>(txt.c_str());
        png_set_text(png_ptr, info_ptr, &text, 1);
        pos += len;
    }

    if (flags & 4) {
        //bKGD
        png_color_16 bg;
        bg.red   = (data[pos%size]<<8) | data[(pos+1)%size];
        bg.green = (data[(pos+2)%size]<<8) | data[(pos+3)%size];
        bg.blue  = (data[(pos+4)%size]<<8) | data[(pos+5)%size];
        png_set_bKGD(png_ptr, info_ptr, &bg);
        pos += 6;
    }

    if (flags & 8) {
        //gAMA
        double gamma = 0.01 + (data[pos++ % size]/255.0)*10.0;
        png_set_gAMA(png_ptr, info_ptr, gamma);
    }

    if (flags & 16) {
        //pHYs
        png_set_pHYs(png_ptr, info_ptr,
                     (png_uint_32)data[pos%size],
                     (png_uint_32)data[(pos+1)%size],
                     PNG_RESOLUTION_METER);
        pos += 2;
    }

    if (flags & 32) {
        //sBIT
        png_color_8 sig;
        sig.red   = data[pos++] & 0x1F;
        sig.green = data[pos++] & 0x1F;
        sig.blue  = data[pos++] & 0x1F;
        sig.alpha = data[pos++] & 0x1F;
        png_set_sBIT(png_ptr, info_ptr, &sig);
    }

    if (flags & 64) {
        //sCAL (meter, fixed text)
        png_set_sCAL(png_ptr, info_ptr,
                     PNG_SCALE_METER,
                     const_cast<png_charp>("1.0"),
                     const_cast<png_charp>("1.0"));
    }

    if (flags & 128) {
        //tIME = now
        png_time mod_time;
        png_convert_from_time_t(&mod_time, std::time(nullptr));
        png_set_tIME(png_ptr, info_ptr, &mod_time);
    }

    //6. Write header
    png_write_info(png_ptr, info_ptr);

    //7. Prepare rows
    png_set_rows(png_ptr, info_ptr, nullptr);
    png_uint_32 channels = png_get_channel_count(png_ptr, info_ptr);
    size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    std::vector<png_bytep> rows(h);
    for (uint32_t y=0; y<h; y++) {
        rows[y] = (png_bytep)malloc(rowbytes);
        memcpy(rows[y],
               data + pos + (y * rowbytes) % (size - pos),
               rowbytes);
    }
    png_set_rows(png_ptr, info_ptr, rows.data());

    //8. Write image + end
    png_write_image(png_ptr, rows.data());
    png_write_end(png_ptr, info_ptr);

    //9. Cleanup
    for (auto r : rows) free(r);
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
}
