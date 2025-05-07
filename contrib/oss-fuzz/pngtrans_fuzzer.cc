#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "png.h"

// Helper function to initialize a row_info structure
static void init_row_info(png_row_info* row_info, png_uint_32 width, 
                         png_byte color_type, png_byte bit_depth) {
    row_info->width = width;
    row_info->rowbytes = PNG_ROWBYTES(row_info->pixel_depth, width);
    row_info->color_type = color_type;
    row_info->bit_depth = bit_depth;
    row_info->channels = png_get_channels(NULL, color_type, bit_depth);
    row_info->pixel_depth = row_info->channels * bit_depth;
}

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) return 0; // Need minimum data for initialization

    // Initialize PNG structures
    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) return 0;
    
    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }

    // Extract parameters from input data
    png_byte color_type = data[0] % 6; // All valid color types
    png_byte bit_depth;
    switch (data[1] % 5) {
        case 0: bit_depth = 1; break;
        case 1: bit_depth = 2; break;
        case 2: bit_depth = 4; break;
        case 3: bit_depth = 8; break;
        case 4: bit_depth = 16; break;
    }
    png_uint_32 width = *(png_uint_32*)(data + 2) % 1024 + 1; // 1-1024 width
    if (width == 0) width = 1;
    
    // Initialize row info
    png_row_info row_info;
    init_row_info(&row_info, width, color_type, bit_depth);
    
    // Allocate row buffer
    size_t rowbytes = PNG_ROWBYTES(row_info.pixel_depth, width);
    png_bytep row = (png_bytep)malloc(rowbytes);
    if (!row) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }
    
    // Fill row with fuzzer data (wrapping around if needed)
    for (size_t i = 0; i < rowbytes; i++) {
        row[i] = data[(i + 6) % size];
    }

    // Test various transformations based on input data
    uint8_t transform_type = data[4] % 12;
    
    switch (transform_type) {
        case 0:
            png_do_bgr(&row_info, row);
            break;
        case 1:
            png_do_invert(&row_info, row);
            break;
        case 2:
            png_do_packswap(&row_info, row);
            break;
        case 3:
            png_do_swap(&row_info, row);
            break;
        case 4:
            png_do_strip_channel(&row_info, row, data[5] % 2);
            break;
        case 5:
            // Set up for filler test
            if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_GRAY) {
                png_ptr->transformations |= PNG_FILLER;
                if (data[5] % 2) {
                    png_ptr->flags |= PNG_FLAG_FILLER_AFTER;
                } else {
                    png_ptr->flags &= ~PNG_FLAG_FILLER_AFTER;
                }
                png_do_strip_channel(&row_info, row, data[5] % 2);
            }
            break;
        case 6:
            if (color_type & PNG_COLOR_MASK_ALPHA) {
                png_do_swap_alpha(&row_info, row);
            }
            break;
        case 7:
            if (color_type & PNG_COLOR_MASK_ALPHA) {
                png_do_invert_alpha(&row_info, row);
            }
            break;
        case 8:
            if (color_type == PNG_COLOR_TYPE_PALETTE && bit_depth < 8) {
                png_ptr->num_palette = 1 << bit_depth;
                png_do_check_palette_indexes(png_ptr, &row_info);
            }
            break;
        case 9:
            // Test interlace handling
            if (data[5] % 2) {
                png_ptr->interlaced = 1;
                png_set_interlace_handling(png_ptr);
            }
            break;
        case 10:
            // Test packing
            if (bit_depth < 8) {
                png_ptr->transformations |= PNG_PACK;
                png_do_packswap(&row_info, row);
            }
            break;
        case 11:
            // Test shift
            if (bit_depth < 8) {
                png_color_8 shift;
                shift.red = data[5] % (1 << bit_depth);
                shift.green = data[6] % (1 << bit_depth);
                shift.blue = data[7] % (1 << bit_depth);
                shift.alpha = data[8] % (1 << bit_depth);
                png_set_shift(png_ptr, &shift);
                // Shift is applied during read, so we can't directly test here
            }
            break;
    }

    // Clean up
    free(row);
    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    
    return 0;
}