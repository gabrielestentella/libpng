
#include <png.h>

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

//Step 8: Write info & image data
png_write_info(png_ptr, info_ptr);

size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
if (rowbytes > 0 && rowbytes <= (1 << 20)) {
// single row from fuzz input
std::vector<uint8_t> row(rowbytes);
for (size_t i = 0; i < rowbytes; ++i) {
    row[i] = next();
}

//If Adam7, finish setup
if (interlace == PNG_INTERLACE_ADAM7) {
    png_set_interlace_handling(png_ptr);
}

// choose pass-by-pass or bulk
if (next() & 1) {
    for (uint32_t y = 0; y < img.height; ++y) {
    png_write_row(png_ptr, row.data());
    }
} else {
    std::vector<uint8_t> imgbuf(img.height * rowbytes);
    for (size_t i = 0; i < imgbuf.size(); ++i) {
    imgbuf[i] = next();
    }
    png_write_image(png_ptr, imgbuf.data());
}
}

png_write_end(png_ptr, info_ptr);




  