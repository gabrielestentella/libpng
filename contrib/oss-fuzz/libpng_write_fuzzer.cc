#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <ctime>
#include <setjmp.h>
#include "png.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 10) return 0;

  //returns next data byte
  size_t pos = 0;
  auto next = [&](void) -> uint8_t { return data[pos++ % size]; };

  //Step 1: Build small png image
  png_image img;
  std::memset(&img, 0, sizeof(img));
  img.version = PNG_IMAGE_VERSION;
  img.width   = 1 + next();
  img.height  = 1 + next();
  //alpha or no alpha?
  img.format  = (next() & 1) ? PNG_FORMAT_RGBA : PNG_FORMAT_RGB;

  //Step 2: pixel buffer allocation
  //(note: we could use a pallete too)
  size_t pixel_bytes = PNG_IMAGE_SIZE(img);
  std::vector<uint8_t> pixels(pixel_bytes);
  for (size_t i = 0; i < pixel_bytes; ++i) 
    pixels[i] = next();   //random initialization

  //Step 3: Create write and info struct
  png_structp png_ptr = png_create_write_struct(
    PNG_LIBPNG_VER_STRING, 
    nullptr,
    nullptr, 
    nullptr
  );
  if (!png_ptr) return 0;

  png_infop info_ptr = png_create_info_struct(png_ptr);
  if (!info_ptr) { 
    png_destroy_write_struct(&png_ptr, nullptr);
    return 0;
  }

  //set up guard in case of error
  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
  }

  //tiny ring-buffer sink (32-63 bytes) to trigger flush paths
  struct Sink { std::vector<uint8_t> buf; };
  Sink sink{ std::vector<uint8_t>(32 + (next() & 31)) };

  //modify how png struct is written by default
  //(we discard the bytes since we dont really care what happens to them)
  png_set_write_fn(
    png_ptr, 
    &sink,
    [](png_structp, png_bytep, png_size_t) {}, // drop bytes 
    nullptr
  );

  //Step 4: Set up randomized interlace (Adam7)
  int interlace = (next() & 1)
    ? PNG_INTERLACE_ADAM7
    : PNG_INTERLACE_NONE;

  //Step 5: Set Up header
  png_set_IHDR(
    png_ptr, 
    info_ptr,
    img.width, 
    img.height,
    8, // bit-depth
    PNG_COLOR_TYPE_RGBA, //format matches img.format
    interlace,
    PNG_COMPRESSION_TYPE_BASE,
    PNG_FILTER_TYPE_BASE
  );


  //Step 6: Set up filter mask & compression level

  //0b111 mask :
  //Sub: 1
  //Up: 2
  //Avg: 4
  unsigned filter_mask = (next() & 7)
    ? PNG_ALL_FILTERS
    : PNG_NO_FILTERS;
  png_set_filter(png_ptr, PNG_FILTER_TYPE_BASE, filter_mask);
  png_set_compression_level(png_ptr, next() % 10);  // 0-9

  //Step 7: Optional colour-space chunks for non-palette
  if (next() & 1) {
  if (next() & 1) {
    png_set_sRGB(
      png_ptr, 
      info_ptr,
      PNG_sRGB_INTENT_PERCEPTUAL
    );
  } else {
    png_set_gAMA_fixed(
      png_ptr, 
      info_ptr, 
      45455 //pretty much the default gamma
    );  // gama ~ 2.2
  }
  }

  png_write_info(png_ptr, info_ptr);

  /* Adam-7 scheduling may change the per-row byte count,
     so enable it *before* you ask for rowbytes. */
  unsigned passes = 1;
  if (interlace == PNG_INTERLACE_ADAM7)
      passes = png_set_interlace_handling(png_ptr);

  /* Now this is the **final** size libpng will copy for each row */
  const png_uint_32 rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  if (rowbytes == 0 || rowbytes > (1 << 20))  /* 1 MiB sanity limit */
      return 0;

  /* Fresh slab + row table sized to the real rowbytes              */
  std::vector<uint8_t> slab(img.height * rowbytes);
  std::vector<png_bytep> rows(img.height);
  for (png_uint_32 y = 0; y < img.height; ++y) {
    rows[y] = &slab[y * rowbytes];
    for (png_uint_32 x = 0; x < rowbytes; ++x)
      slab[y * rowbytes + x] = next();      /* fill with fuzz data */
  }

  //size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
  //std::vector<png_bytep> rows(img.height);
  
  //for (png_uint_32 i = 0; i < img.height; ++i)
  //  rows[i] = (png_bytep)&pixels[i * rowbytes];
  

  //Step 9: choose pass-by-pass or bulk write
  if (next() & 1) {                     /* row-at-a-time path */
    for (unsigned p = 0; p < passes; ++p)
      for (png_uint_32 y = 0; y < img.height; ++y)
          png_write_row(png_ptr, rows[y]);
  } else {                             /* bulk path */
      png_write_image(png_ptr, rows.data());
  }

  png_write_end(png_ptr, info_ptr);
  png_destroy_write_struct(&png_ptr, &info_ptr);


  //Risky extra coverage
  //Step 10:  try to write to memory
  png_bytep out_buf = nullptr;
  png_alloc_size_t out_size = 0;
  png_image_write_to_memory(
    &img, 
    &out_buf, 
    &out_size,
    0, //convert to 8 bit
    pixels.data(), 
    0, //row stride
    nullptr
  );
  free(out_buf);
  return 0;
}