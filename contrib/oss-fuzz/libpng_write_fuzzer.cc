// libpng_full_write_fuzzer.cc  –  final, wrap-safe version
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

    size_t pos = 0;
    auto next_byte = [&]() -> uint8_t {
        uint8_t v = data[pos % size];
        ++pos;
        return v;
    };

    uint32_t w = ((((uint32_t)next_byte()) << 8) | next_byte()) % 256 + 1;
    uint32_t h = ((((uint32_t)next_byte()) << 8) | next_byte()) % 256 + 1;
    static const int cts[] = {PNG_COLOR_TYPE_GRAY, PNG_COLOR_TYPE_RGB,
                              PNG_COLOR_TYPE_PALETTE, PNG_COLOR_TYPE_GRAY_ALPHA,
                              PNG_COLOR_TYPE_RGBA};
    static const int bds[] = {1, 2, 4, 8, 16};
    int color_type = cts[next_byte() % 5];
    int bit_depth  = bds[next_byte() % 5];

    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,nullptr,nullptr,nullptr);
    if(!png_ptr) return 0;
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if(!info_ptr){ png_destroy_write_struct(&png_ptr,nullptr); return 0; }
    if(setjmp(png_jmpbuf(png_ptr))){ png_destroy_write_struct(&png_ptr,&info_ptr); return 0; }

    struct Mem { std::vector<uint8_t> buf; } mem;
    png_set_write_fn(png_ptr,&mem,
        [](png_structp p,png_bytep d,png_size_t l){
            auto m=reinterpret_cast<Mem*>(png_get_io_ptr(p));
            m->buf.insert(m->buf.end(),d,d+l);
        }, nullptr);

    png_set_IHDR(png_ptr,info_ptr,w,h,bit_depth,color_type,
                 PNG_INTERLACE_ADAM7,PNG_COMPRESSION_TYPE_BASE,PNG_FILTER_TYPE_BASE);

    uint16_t flags = (uint16_t(next_byte()) << 8) | next_byte();

    // ---------------- ancillary chunks ----------------------
    if(flags & 0x0001){                  // PLTE (up to 16 entries)
        if(color_type==PNG_COLOR_TYPE_PALETTE || color_type==PNG_COLOR_TYPE_RGB){
            int n = 1 + (next_byte() % 16);
            std::vector<png_color> pal(n);
            for(int i=0;i<n;i++){
                pal[i].red   = next_byte();
                pal[i].green = next_byte();
                pal[i].blue  = next_byte();
            }
            png_set_PLTE(png_ptr,info_ptr,pal.data(),n);
        }
    }

    if(flags & 0x0002){                  // tEXt
        png_text txt{}; txt.compression=PNG_TEXT_COMPRESSION_zTXt;
        txt.key = const_cast<png_charp>("Desc");
        int len = std::min<int>(size,50);
        static std::string s;
        s.clear();
        for(int i=0;i<len;i++) s.push_back(next_byte());
        txt.text = const_cast<png_charp>(s.c_str());
        png_set_text(png_ptr,info_ptr,&txt,1);
    }

    std::vector<uint8_t> iccp;           // keep alive for iCCP
    if(flags & 0x0004){
        int clen = 20 + (next_byte() % 80);     // 20-100 bytes
        iccp.resize(clen);
        for(int i=0;i<clen;i++) iccp[i] = next_byte();
        png_set_iCCP(png_ptr,info_ptr,(png_const_charp)"prof",
                     PNG_COMPRESSION_TYPE_BASE,iccp.data(),clen);
    }

    if(flags & 0x0008){                  // bKGD
        png_color_16 bg;
        bg.red   = (next_byte()<<8)|next_byte();
        bg.green = (next_byte()<<8)|next_byte();
        bg.blue  = (next_byte()<<8)|next_byte();
        png_set_bKGD(png_ptr,info_ptr,&bg);
    }

    if(flags & 0x0010){                  // gAMA
        double g = 0.01 + (next_byte() / 255.0) * 10.0;
        png_set_gAMA(png_ptr,info_ptr,g);
    }

    if(flags & 0x0020){                  // pHYs
        png_set_pHYs(png_ptr,info_ptr,next_byte(),next_byte(),PNG_RESOLUTION_METER);
    }

    if(flags & 0x0040){                  // sBIT
        png_color_8 sbit{ static_cast<png_byte>(next_byte()&0x1F),
                          static_cast<png_byte>(next_byte()&0x1F),
                          static_cast<png_byte>(next_byte()&0x1F),
                          static_cast<png_byte>(next_byte()&0x1F)};
        png_set_sBIT(png_ptr,info_ptr,&sbit);
    }

    if(flags & 0x0080){ png_set_sCAL(png_ptr,info_ptr,PNG_SCALE_METER,1.0,1.0); }

    std::vector<uint16_t> hist;          // keep alive for hIST
    if((flags & 0x0100) && color_type==PNG_COLOR_TYPE_PALETTE){
        int n; png_colorp pal; png_get_PLTE(png_ptr,info_ptr,&pal,&n);
        if(n>0){
            hist.resize(n);
            for(int i=0;i<n;i++) hist[i] = next_byte();
            png_set_hIST(png_ptr,info_ptr,hist.data());
        }
    }

    if(flags & 0x0200){
        png_time tm; png_convert_from_time_t(&tm, time(nullptr));
        png_set_tIME(png_ptr,info_ptr,&tm);
    }
    if(flags & 0x0400){ png_set_sRGB(png_ptr,info_ptr,PNG_sRGB_INTENT_PERCEPTUAL); }

    // --------------------------------------------------------

    png_write_info(png_ptr,info_ptr);

    size_t rowbytes = png_get_rowbytes(png_ptr,info_ptr);
    std::vector<png_bytep> rows(h);
    for(uint32_t y=0;y<h;y++){
        rows[y]=(png_bytep)malloc(rowbytes);
        for(size_t i=0;i<rowbytes;i++) rows[y][i]=next_byte();
    }
    png_set_rows(png_ptr,info_ptr,rows.data());

    png_write_image(png_ptr,rows.data());
    png_write_end  (png_ptr,info_ptr);

    for(auto r:rows) free(r);
    png_destroy_write_struct(&png_ptr,&info_ptr);
    return 0;
}
