// libpng_full_write_fuzzer.cc  –  C-only buffers, no leak on longjmp
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <setjmp.h>
#include "png.h"

/* ---------------- helper: wrap reads ---------------- */
static inline uint8_t next_byte(const uint8_t *data, size_t size, size_t *pos) {
  uint8_t v = data[*pos % size];
  ++(*pos);
  return v;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return 0;
  size_t pos = 0;

/* ---- basic image parameters ---- */
  uint32_t w = ((uint32_t)next_byte(data,size,&pos) << 8 | next_byte(data,size,&pos)) % 256 + 1;
  uint32_t h = ((uint32_t)next_byte(data,size,&pos) << 8 | next_byte(data,size,&pos)) % 256 + 1;
  static const int cts[] = {PNG_COLOR_TYPE_GRAY, PNG_COLOR_TYPE_RGB,
                            PNG_COLOR_TYPE_PALETTE, PNG_COLOR_TYPE_GRAY_ALPHA,
                            PNG_COLOR_TYPE_RGBA};
  static const int bds[] = {1,2,4,8,16};
  int color_type = cts[next_byte(data,size,&pos) % 5];
  int bit_depth  = bds[next_byte(data,size,&pos) % 5];

/* ---- libpng init ---- */
  png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING,nullptr,nullptr,nullptr);
  if (!png_ptr) return 0;
  png_infop info_ptr  = png_create_info_struct(png_ptr);
  if (!info_ptr) { png_destroy_write_struct(&png_ptr,nullptr); return 0; }

/* ---- buffers potentially leaked ---- */
  unsigned char *out_buf = nullptr; size_t out_cap = 0, out_size = 0;
  uint8_t  *iccp = nullptr;
  uint16_t *hist = nullptr; int hist_n = 0;
  png_bytep *rows = nullptr; uint32_t rows_alloc = 0;

/* ---- longjmp cleanup ---- */
  if (setjmp(png_jmpbuf(png_ptr))) {
    for (uint32_t i = 0; i < rows_alloc; ++i) free(rows[i]);
    free(rows);
    free(hist);
    free(iccp);
    free(out_buf);
    png_destroy_write_struct(&png_ptr,&info_ptr);
    return 0;
  }

/* ---- memory write callback (malloc/realloc) ---- */
  struct Mem { unsigned char **buf; size_t *size; size_t *cap; };
  Mem mem{&out_buf,&out_size,&out_cap};
  png_set_write_fn(
      png_ptr,&mem,
      [](png_structp p,png_bytep d,png_size_t l){
        auto m = reinterpret_cast<Mem*>(png_get_io_ptr(p));
        size_t needed = *m->size + l;
        if (needed > *m->cap) {
          size_t newcap = (*m->cap ? *m->cap : 256);
          while (newcap < needed) newcap *= 2;
          unsigned char *tmp = (unsigned char*)realloc(*m->buf,newcap);
          if (!tmp) png_error(p,"OOM");
          *m->buf = tmp; *m->cap = newcap;
        }
        memcpy(*m->buf + *m->size, d, l);
        *m->size += l;
      },
      nullptr);

/* ---- IHDR ---- */
  png_set_IHDR(png_ptr,info_ptr,w,h,bit_depth,color_type,
               PNG_INTERLACE_ADAM7,PNG_COMPRESSION_TYPE_BASE,PNG_FILTER_TYPE_BASE);

/* ---- ancillary chunks ---- */
  uint16_t flags = ((uint16_t)next_byte(data,size,&pos) << 8) | next_byte(data,size,&pos);

  if (flags & 0x0001) {                           /* PLTE */
    if (color_type==PNG_COLOR_TYPE_PALETTE || color_type==PNG_COLOR_TYPE_RGB) {
      int n = 1 + (next_byte(data,size,&pos) % 16);
      png_color pal[16];
      for (int i=0;i<n;i++){ pal[i].red=next_byte(data,size,&pos);
                            pal[i].green=next_byte(data,size,&pos);
                            pal[i].blue=next_byte(data,size,&pos);}
      png_set_PLTE(png_ptr,info_ptr,pal,n);
    }
  }

  if (flags & 0x0002) {                           /* tEXt */
    char text_buf[50];
    for (int i=0;i<50;i++) text_buf[i]=next_byte(data,size,&pos);
    png_text txt{}; txt.compression=PNG_TEXT_COMPRESSION_zTXt;
    txt.key=(png_charp)"Desc"; txt.text=text_buf;
    png_set_text(png_ptr,info_ptr,&txt,1);
  }

  if (flags & 0x0004) {                           /* iCCP */
    int clen = 20 + (next_byte(data,size,&pos) % 80);
    iccp = (uint8_t*)malloc(clen);
    for (int i=0;i<clen;i++) iccp[i]=next_byte(data,size,&pos);
    png_set_iCCP(png_ptr,info_ptr,(png_const_charp)"prof",
                 PNG_COMPRESSION_TYPE_BASE,iccp,clen);
  }

  if (flags & 0x0008) {                           /* bKGD */
    png_color_16 bg;
    bg.red  =(next_byte(data,size,&pos)<<8)|next_byte(data,size,&pos);
    bg.green=(next_byte(data,size,&pos)<<8)|next_byte(data,size,&pos);
    bg.blue =(next_byte(data,size,&pos)<<8)|next_byte(data,size,&pos);
    png_set_bKGD(png_ptr,info_ptr,&bg);
  }

  if (flags & 0x0010) {                           /* gAMA */
    double gamma = 0.01 + (next_byte(data,size,&pos)/255.0)*10.0;
    png_set_gAMA(png_ptr,info_ptr,gamma);
  }

  if (flags & 0x0020) {                           /* pHYs */
    png_set_pHYs(png_ptr,info_ptr,next_byte(data,size,&pos),
                 next_byte(data,size,&pos),PNG_RESOLUTION_METER);
  }

  if (flags & 0x0040) {                           /* sBIT */
    png_color_8 sbit{(png_byte)(next_byte(data,size,&pos)&0x1F),
                     (png_byte)(next_byte(data,size,&pos)&0x1F),
                     (png_byte)(next_byte(data,size,&pos)&0x1F),
                     (png_byte)(next_byte(data,size,&pos)&0x1F)};
    png_set_sBIT(png_ptr,info_ptr,&sbit);
  }

  if (flags & 0x0080) { png_set_sCAL(png_ptr,info_ptr,PNG_SCALE_METER,1.0,1.0); }

  if ((flags & 0x0100) && color_type==PNG_COLOR_TYPE_PALETTE) { /* hIST */
    int n; png_colorp pal; png_get_PLTE(png_ptr,info_ptr,&pal,&n);
    if (n>0){
      hist_n=n; hist=(uint16_t*)malloc(sizeof(uint16_t)*n);
      for (int i=0;i<n;i++) hist[i]=next_byte(data,size,&pos);
      png_set_hIST(png_ptr,info_ptr,hist);
    }
  }

  if (flags & 0x0200){ png_time tm; png_convert_from_time_t(&tm,time(nullptr));
                       png_set_tIME(png_ptr,info_ptr,&tm);}
  if (flags & 0x0400){ png_set_sRGB(png_ptr,info_ptr,PNG_sRGB_INTENT_PERCEPTUAL);}

  png_write_info(png_ptr,info_ptr);

/* ---- rows ---- */
  size_t rowbytes = png_get_rowbytes(png_ptr,info_ptr);
  rows = (png_bytep*)malloc(sizeof(png_bytep)*h);
  for (uint32_t y=0;y<h;y++){
    rows[y]=(png_bytep)malloc(rowbytes);
    ++rows_alloc;
    for (size_t i=0;i<rowbytes;i++) rows[y][i]=next_byte(data,size,&pos);
  }
  png_set_rows(png_ptr,info_ptr,rows);

  png_write_image(png_ptr,rows);
  png_write_end  (png_ptr,info_ptr);

/* ---- normal cleanup ---- */
  for (uint32_t i=0;i<rows_alloc;++i) free(rows[i]);
  free(rows);
  free(hist);
  free(iccp);
  free(out_buf);
  png_destroy_write_struct(&png_ptr,&info_ptr);
  return 0;
}
