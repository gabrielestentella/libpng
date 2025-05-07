// libpng_full_write_fuzzer.cc  –  KEEP ALIVE BUFFERS FOR iCCP & hIST
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

    uint32_t w = ((((uint32_t)data[0]) << 8) | data[1]) % 256 + 1;
    uint32_t h = ((((uint32_t)data[2]) << 8) | data[3]) % 256 + 1;
    static const int cts[] = {PNG_COLOR_TYPE_GRAY, PNG_COLOR_TYPE_RGB,
                              PNG_COLOR_TYPE_PALETTE, PNG_COLOR_TYPE_GRAY_ALPHA,
                              PNG_COLOR_TYPE_RGBA};
    static const int bds[] = {1, 2, 4, 8, 16};
    int color_type = cts[data[4] % 5];
    int bit_depth  = bds[data[5] % 5];

    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr,nullptr,nullptr);
    if (!png_ptr) return 0;
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) { png_destroy_write_struct(&png_ptr,nullptr); return 0; }
    if (setjmp(png_jmpbuf(png_ptr))) { png_destroy_write_struct(&png_ptr,&info_ptr); return 0; }

    struct Mem { std::vector<uint8_t> buf; } mem;
    auto write_cb=[](png_structp p,png_bytep d,png_size_t l){
        auto m=reinterpret_cast<Mem*>(png_get_io_ptr(p));
        m->buf.insert(m->buf.end(),d,d+l);};
    png_set_write_fn(png_ptr,&mem,write_cb,nullptr);

    png_set_IHDR(png_ptr,info_ptr,w,h,bit_depth,color_type,
                 PNG_INTERLACE_ADAM7,PNG_COMPRESSION_TYPE_BASE,PNG_FILTER_TYPE_BASE);

    uint16_t flags=(uint16_t(data[6])<<8)|data[7];
    size_t pos=8;

    if(flags&0x0001){
        if(color_type==PNG_COLOR_TYPE_PALETTE||color_type==PNG_COLOR_TYPE_RGB){
            int n = 1 + (data[pos++ % size] % 16);
            std::vector<png_color> pal(n);
            for(int i=0;i<n;i++){
                pal[i].red=data[pos++%size];
                pal[i].green=data[pos++%size];
                pal[i].blue=data[pos++%size];
            }
            png_set_PLTE(png_ptr,info_ptr,pal.data(),n);
        }}
    if(flags&0x0002){
        png_text txt{}; txt.compression=PNG_TEXT_COMPRESSION_zTXt;
        txt.key=const_cast<png_charp>("Desc");
        int len=std::min<int>(size-pos,50);
        static std::string t; t.assign(reinterpret_cast<const char*>(data+pos),len);
        txt.text=const_cast<png_charp>(t.c_str());
        png_set_text(png_ptr,info_ptr,&txt,1);
        pos+=len;
    }
    std::vector<uint8_t> iccp;               // keep until end
    if(flags&0x0004){
        png_uint_32 clen=std::min<png_uint_32>(size-pos,100);
        iccp.assign(data+pos,data+pos+clen);
        png_set_iCCP(png_ptr,info_ptr,(png_const_charp)"prof",
                     PNG_COMPRESSION_TYPE_BASE,iccp.data(),clen);
        pos+=clen;
    }
    if(flags&0x0008){
        png_color_16 bg;
        bg.red=((uint16_t)data[pos%size]<<8)|data[(pos+1)%size];
        bg.green=((uint16_t)data[(pos+2)%size]<<8)|data[(pos+3)%size];
        bg.blue=((uint16_t)data[(pos+4)%size]<<8)|data[(pos+5)%size];
        png_set_bKGD(png_ptr,info_ptr,&bg);
        pos+=6;
    }
    if(flags&0x0010){
        double g=0.01+(data[pos++%size]/255.0)*10.0;
        png_set_gAMA(png_ptr,info_ptr,g);
    }
    if(flags&0x0020){
        png_set_pHYs(png_ptr,info_ptr,(png_uint_32)data[pos%size],
                     (png_uint_32)data[(pos+1)%size],PNG_RESOLUTION_METER);
        pos+=2;
    }
    if(flags&0x0040){
        png_color_8 sbit{ static_cast<png_byte>(data[pos++]&0x1F),
                          static_cast<png_byte>(data[pos++]&0x1F),
                          static_cast<png_byte>(data[pos++]&0x1F),
                          static_cast<png_byte>(data[pos++]&0x1F)};
        png_set_sBIT(png_ptr,info_ptr,&sbit);
    }
    if(flags&0x0080){
        png_set_sCAL(png_ptr,info_ptr,PNG_SCALE_METER,1.0,1.0);
    }
    std::vector<uint16_t> hist;              // keep until end
    if(flags&0x0100 && color_type==PNG_COLOR_TYPE_PALETTE){
        int n; png_colorp pal; png_get_PLTE(png_ptr,info_ptr,&pal,&n);
        if(n>0){
            hist.resize(n);
            for(int i=0;i<n;i++) hist[i]=data[(pos+i)%size];
            png_set_hIST(png_ptr,info_ptr,hist.data());
            pos+=n;
        }
    }
    if(flags&0x0200){
        png_time tm; png_convert_from_time_t(&tm,time(nullptr));
        png_set_tIME(png_ptr,info_ptr,&tm);
    }
    if(flags&0x0400){
        png_set_sRGB(png_ptr,info_ptr,PNG_sRGB_INTENT_PERCEPTUAL);
    }

    png_write_info(png_ptr,info_ptr);

    size_t rowbytes=png_get_rowbytes(png_ptr,info_ptr);
    std::vector<png_bytep> rows(h);
    for(uint32_t y=0;y<h;y++){
        rows[y]=(png_bytep)malloc(rowbytes);
        for(size_t i=0;i<rowbytes;i++){
            size_t idx=(pos+y*rowbytes+i)%size;
            rows[y][i]=data[idx];
        }}
    png_set_rows(png_ptr,info_ptr,rows.data());

    png_write_image(png_ptr,rows.data());
    png_write_end  (png_ptr,info_ptr);

    for(auto r:rows) free(r);
    png_destroy_write_struct(&png_ptr,&info_ptr);
    return 0;
}
