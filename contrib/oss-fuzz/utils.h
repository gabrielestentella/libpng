#ifndef UTILS_H
#define UTILS_H

#include "png.h"

/** Code taken from libpng_read_fuzzer.cc **/
struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngObjectHandler {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  png_voidp row_ptr = nullptr;
  BufState* buf_state = nullptr;

  ~PngObjectHandler() {
    if (row_ptr)
      png_free(png_ptr, row_ptr);
    if (end_info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, &end_info_ptr);
    else if (info_ptr)
      png_destroy_read_struct(&png_ptr, &info_ptr, nullptr);
    else
      png_destroy_read_struct(&png_ptr, nullptr, nullptr);
    delete buf_state;
  }
};

/** NEW: Test getters**/
void test_getters (PngObjectHandler *png_handler) {
  png_get_valid(png_handler->png_ptr, png_handler->info_ptr, PNG_INFO_tRNS);
  png_get_rows(png_handler->png_ptr, png_handler->info_ptr);
  png_get_image_width(png_handler->png_ptr, png_handler->info_ptr);
  png_get_image_height(png_handler->png_ptr, png_handler->info_ptr);
  png_get_bit_depth(png_handler->png_ptr, png_handler->info_ptr);
  png_get_color_type(png_handler->png_ptr, png_handler->info_ptr);
  png_get_filter_type(png_handler->png_ptr, png_handler->info_ptr);
  png_get_compression_type(png_handler->png_ptr, png_handler->info_ptr);
  png_get_interlace_type(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_pixels_per_meter(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_pixels_per_meter(png_handler->png_ptr, png_handler->info_ptr);
  png_get_pixels_per_meter(png_handler->png_ptr, png_handler->info_ptr);
  png_get_pixel_aspect_ratio_fixed(png_handler->png_ptr, png_handler->info_ptr);
  png_get_pixel_aspect_ratio(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_offset_microns(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_offset_microns(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_offset_pixels(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_offset_pixels(png_handler->png_ptr, png_handler->info_ptr);
  png_get_pixels_per_inch(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_pixels_per_inch(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_pixels_per_inch(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_offset_inches_fixed(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_offset_inches_fixed(png_handler->png_ptr, png_handler->info_ptr);
  png_get_x_offset_inches(png_handler->png_ptr, png_handler->info_ptr);
  png_get_y_offset_inches(png_handler->png_ptr, png_handler->info_ptr);
  png_get_channels(png_handler->png_ptr, png_handler->info_ptr);
  png_get_signature(png_handler->png_ptr, png_handler->info_ptr);
  png_uint_32 res_x, res_y;
  int unit_type;
  png_get_pHYs_dpi(png_handler->png_ptr, png_handler->info_ptr, &res_x, &res_y, &unit_type);
  png_color_16p background;
  png_get_bKGD(png_handler->png_ptr, png_handler->info_ptr, &background);
  png_fixed_point whitex, whitey, redx, redy, redz, greenx, greeny, greenz, bluex, bluey, bluez;
  png_get_cHRM_fixed(png_handler->png_ptr, png_handler->info_ptr, &whitex, &whitey, &redx, &redy, &greenx, &greeny, &bluex, &bluey);
  double red_X, red_Y, red_Z, green_X, green_Y, green_Z, blue_X, blue_Y, blue_Z, white_X, white_Y;
  png_get_cHRM_XYZ(png_handler->png_ptr, png_handler->info_ptr,  &red_X,  &red_Y,  &red_Z,  &green_X, 
    &green_Y,  &green_Z,  &blue_X,  &blue_Y, &blue_Z);
  png_get_cHRM_XYZ_fixed(png_handler->png_ptr, png_handler->info_ptr, &redx, &redy, &redz, &greenx, &greeny, &greenz, 
    &bluex, &bluey, &bluez);
  png_get_cHRM(png_handler->png_ptr, png_handler->info_ptr, &white_X, &white_Y, &red_X, &red_Y, &green_X, &green_Y, &blue_X, &blue_Y);
  png_fixed_point file_gamma;
  png_get_gAMA_fixed(png_handler->png_ptr, png_handler->info_ptr, &file_gamma);
  double gamma_file;
  png_get_gAMA(png_handler->png_ptr, png_handler->info_ptr, &gamma_file);
  int file_srgb_intent;
  png_get_sRGB(png_handler->png_ptr, png_handler->info_ptr, &file_srgb_intent);
  png_charpp name;
  int compression_type;
  png_bytep profile;
  png_uint_32 proflen;
  png_get_iCCP(png_handler->png_ptr, png_handler->info_ptr, &name, &compression_type, &profile, &proflen);
  png_sPLT_tp spalettes;
  png_get_sPLT(png_handler->png_ptr, png_handler->info_ptr, &spalettes);
  png_uint_32 maxCLL, maxFALL, num_exif;
  png_bytep exif;
  png_get_eXIf(png_handler->png_ptr, png_handler->info_ptr, &exif);
  png_get_eXIf_1(png_handler->png_ptr, png_handler->info_ptr, &num_exif, &exif);
  png_uint_16p hist;
  png_get_hIST(png_handler->png_ptr, png_handler->info_ptr, &hist);
  png_int_32 offset_x, offset_y;
  png_get_oFFs(png_handler->png_ptr, png_handler->info_ptr, &offset_x, &offset_y, &unit_type);
  png_charp purpose, units;
  png_int_32 X0, X1;
  int type, nparams;
  png_charpp params;
  png_get_pCAL(png_handler->png_ptr, png_handler->info_ptr, &purpose, &X0, &X1, &type, &nparams, &units, &params);
  png_fixed_point width, height;
  png_get_sCAL_fixed(png_handler->png_ptr, png_handler->info_ptr, &unit_type, &width, &height);
  double width_2, height_2;
  png_get_sCAL(png_handler->png_ptr, png_handler->info_ptr, &unit_type, &width_2, &height_2);
  png_charpp width_3, height_3;
  png_get_sCAL_s(png_handler->png_ptr, png_handler->info_ptr, &unit_type, &width_3, &height_3);
  png_get_pHYs(png_handler->png_ptr, png_handler->info_ptr, &res_x, &res_y, &unit_type);
  png_colorp palette;
  png_get_PLTE(png_handler->png_ptr, png_handler->info_ptr, &palette, &unit_type);
  png_color_8p sig_bit;
  png_get_sBIT(png_handler->png_ptr, png_handler->info_ptr, &sig_bit);
  png_textp text_ptr;
  png_get_text(png_handler->png_ptr, png_handler->info_ptr, &text_ptr, &unit_type);
  png_timep mod_time;
  png_get_tIME(png_handler->png_ptr, png_handler->info_ptr, &mod_time);
  png_bytep trans_alpha;
  png_color_16p trans_color;
  png_get_tRNS(png_handler->png_ptr, png_handler->info_ptr, &trans_alpha, &unit_type, &trans_color);
  png_unknown_chunkpp entries;
  png_get_unknown_chunks(png_handler->png_ptr, png_handler->info_ptr, &entries);
  png_get_rgb_to_gray_status(png_handler->png_ptr);
  png_get_user_chunk_ptr(png_handler->png_ptr);
  png_get_compression_buffer_size(png_handler->png_ptr);
  png_get_user_width_max(png_handler->png_ptr);
  png_get_user_height_max(png_handler->png_ptr);
  png_get_chunk_cache_max(png_handler->png_ptr);
  png_get_chunk_malloc_max(png_handler->png_ptr);
  png_get_io_state(png_handler->png_ptr);
  png_get_io_chunk_type(png_handler->png_ptr);
  png_get_palette_max(png_handler->png_ptr, png_handler->info_ptr);
}

#endif // UTILS_H
