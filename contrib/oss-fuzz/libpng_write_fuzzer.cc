//#define PNG_CPY_TEST_FUZZ
#ifdef PNG_CPY_TEST_FUZZ
  #define static                 /* remove 'static' so symbols are extern */
  #define main  pngcp_main      /* rename its main() to pngcp_main()      */
  #include "contrib/tools/pngcp.c"
  #undef main
  #undef static
  int pngcp_main(int argc, char** argv);
#endif 

// libpng_write_fuzzer.cc – with extra png_write_image coverage
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <ctime>
#include <setjmp.h>
#include "png.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 10) return 0;
  size_t pos = 0;
  auto next = [&](void) -> uint8_t { return data[pos++ % size]; };

  /* -------- build a small PNG_IMAGE ----------------------------- */
  png_image img;
  std::memset(&img, 0, sizeof(img));
  img.version = PNG_IMAGE_VERSION;
  img.width   = 1 + next();
  img.height  = 1 + next();
  img.format  = (next() & 1) ? PNG_FORMAT_RGBA : PNG_FORMAT_RGB;

  /* allocate pixel buffer */
  size_t pixel_bytes = PNG_IMAGE_SIZE(img);
  std::vector<uint8_t> pixels(pixel_bytes);
  for (size_t i = 0; i < pixel_bytes; ++i) pixels[i] = next();

  png_structp png_ptr = png_create_write_struct(
      PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_ptr) return 0;
  png_infop info_ptr  = png_create_info_struct(png_ptr);
  if (!info_ptr) { png_destroy_write_struct(&png_ptr, nullptr); return 0; }

  /* longjmp-safe clean-up */
  if (setjmp(png_jmpbuf(png_ptr))) {
    png_destroy_write_struct(&png_ptr, &info_ptr);
    return 0;
  }

  /* discard-all write callback */
  png_set_write_fn(png_ptr, nullptr,
      [](png_structp, png_bytep, png_size_t) {/* drop */}, nullptr);

  /* IHDR — map from simplified API params */
  int color_type = (img.format == PNG_FORMAT_RGBA) ?
                      PNG_COLOR_TYPE_RGBA : PNG_COLOR_TYPE_RGB;
  png_set_IHDR(png_ptr, info_ptr,
                img.width, img.height, 8 /*bit depth*/,
                color_type,
                PNG_INTERLACE_NONE,
                PNG_COMPRESSION_TYPE_BASE,
                PNG_FILTER_TYPE_BASE);

  /* row pointers */
  size_t rowbytes = (img.format == PNG_FORMAT_RGBA ?
                      img.width * 4 : img.width * 3);
  std::vector<png_bytep> rows(img.height);
  for (png_uint_32 y = 0; y < img.height; ++y)
    rows[y] = (png_bytep)&pixels[y * rowbytes];

  png_write_info(png_ptr, info_ptr);
  png_write_image(png_ptr, rows.data());
  png_write_end  (png_ptr, info_ptr);
  png_destroy_write_struct(&png_ptr, &info_ptr);
  

  /* --- original simplified-API path (unchanged) ----------------- */
  png_bytep out_buf = nullptr;
  png_alloc_size_t out_size = 0;
  png_image_write_to_memory(&img, &out_buf, &out_size,
                            0 /* convert_to_8bit */,
                            pixels.data(), 0 /* row_stride */, nullptr);
  free(out_buf);

#ifdef PNG_CPY_TEST_FUZZ
  //PNG CPY SECTION

  //write the fuzz‑generated PNG to a temp input file
  char in_template[]  = "./pngcp_in_XXXXXX";
  int  infd = mkstemp(in_template);
  if (infd < 0) { free(out_buf); return 0; }
  write(infd, out_buf, out_size);
  close(infd);

  //second temp name will be the output file created by pngcp
  char out_template[] = "./pngcp_out_XXXXXX";
  int  outfd = mkstemp(out_template);   //just reserves the path
  close(outfd);                         //cp_one_file will re‑create
  unlink(out_template);                 //remove placeholder

  //call cp_one_file directly 
  char *argv_cp[] = { (char*)"pngcp", in_template, out_template };
  pngcp_main(3, argv_cp);

  // tidy up
  unlink(in_template);
  unlink(out_template);
#endif 
  return 0;
}