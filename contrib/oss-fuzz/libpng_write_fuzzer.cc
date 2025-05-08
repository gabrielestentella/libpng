#define PNG_CPY_TEST_FUZZ
#ifdef PNG_CPY_TEST_FUZZ
  #define static                 /* remove 'static' so symbols are extern */
  #define main  pngcp_main      /* rename its main() to pngcp_main()      */
  #include "contrib/tools/pngcp.c"
  #undef main
  #undef static
  int pngcp_main(int argc, char** argv);
#endif 

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vector>
#include <unistd.h>   // mkstemp, unlink
#include <fcntl.h>
#include <stdio.h>

#define PNG_INTERNAL
#define PNG_sCAL_SUPPORTED

#include "png.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 5) return 0; //at least a few bytes for dimensions
  png_image image;
  memset(&image, 0, sizeof(image));
  image.version = PNG_IMAGE_VERSION;
  //use first bytes to construct small width/height
  image.width = data[0] + 1;
  image.height = data[1] + 1;
  int colormode = data[2] % 3;
  //pick a color format: 0=RGBA, 1=GRAY, 2=RGBA palette (just for variety)
  image.format = (colormode == 1 ? PNG_FORMAT_GRAY : PNG_FORMAT_RGBA);
  //Allocate pixel buffer (assume 8-bit components)
  size_t pixel_size = PNG_IMAGE_SIZE(image);
  if (pixel_size > size - 3 || pixel_size == 0) return 0;
  //Use remaining fuzz data as pixel bytes
  png_bytep pixels = const_cast<png_bytep>(data + 3);
  //Write PNG to memory (output buffer allocated by libpng)
  png_bytep out_buf = NULL;
  png_alloc_size_t out_size = 0;
  if (png_image_write_to_memory(&image, &out_buf, &out_size, 0, pixels, 0, NULL) == -1) {
      png_image_free(&image);
      return 0; // writing failed
  }
  //free image memory
  png_image_free(&image);

#ifdef PNG_CPY_TEST_FUZZ
  //PNG CPY SECTION

  //write the fuzz‑generated PNG to a temp input file
  char in_template[]  = "./tmp/pngcp_in_XXXXXX";
  int  infd = mkstemp(in_template);
  if (infd < 0) { free(out_buf); return 0; }
  write(infd, out_buf, out_size);
  close(infd);

  //second temp name will be the output file created by pngcp
  char out_template[] = "./tmp/pngcp_out_XXXXXX";
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

  free(out_buf);
  return 0;
}
