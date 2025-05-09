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

  //Step 3: set up PNG struct and functions
  png_structp png_ptr = png_create_write_struct(
    PNG_LIBPNG_VER_STRING,  //user_png_ver
    nullptr,                //error_ptr
    nullptr,                //error_fn
    nullptr                 //warn_fn
  );
  if (!png_ptr) return 0;
  png_infop info_ptr  = png_create_info_struct(png_ptr);
  if (!info_ptr) { png_destroy_write_struct(&png_ptr, nullptr); return 0; }

  //set up clean up when error
  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
  }

  //modify how png struct is written by default
  //(we discard the bytes since we dont really care what happens to them)
  png_set_write_fn(
    png_ptr, 
    nullptr,
    [](png_structp, png_bytep, png_size_t) {}, //actual write function
    nullptr
  );

  //Step 4: setting up IHDR header 
  //extra setters could be used to set 
  //a filter type and a compression type
  int color_type = (img.format == PNG_FORMAT_RGBA) ?
                      PNG_COLOR_TYPE_RGBA : PNG_COLOR_TYPE_RGB;
  png_set_IHDR(
    png_ptr, 
    info_ptr,
    img.width, 
    img.height, 
    8, //bit depth
    color_type,
    PNG_INTERLACE_NONE,
    PNG_COMPRESSION_TYPE_BASE,
    PNG_FILTER_TYPE_BASE
  );


  //reshaping image pixels to sets of rows
  size_t rowbytes = (img.format == PNG_FORMAT_RGBA ?
                      img.width * 4 : img.width * 3);
  std::vector<png_bytep> rows(img.height);
  for (png_uint_32 y = 0; y < img.height; ++y)
    rows[y] = (png_bytep)&pixels[y * rowbytes];

  //Step 5: actually writing the image (i.e. dropping the bytes)
  //and destroying the struct
  png_write_info(png_ptr, info_ptr);
  png_write_image(png_ptr, rows.data());
  png_write_end  (png_ptr, info_ptr);
  png_destroy_write_struct(&png_ptr, &info_ptr);


  //now try to write to memory (risky but increases coverage)
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