#include <png.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Fuzzing harness for libpng's pngwrite.c using libFuzzer
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Limit input size to prevent excessive memory usage
    if (size < 100 || size > 1000000) {
        return 0;
    }

    // Initialize PNG image structure
    png_image image;
    memset(&image, 0, sizeof(image));
    image.version = PNG_IMAGE_VERSION;

    // Extract image parameters from input data
    // Use first few bytes to set width, height, and format
    if (size < 8) {
        return 0;
    }

    // Width and height: limit to reasonable values (1 to 2048)
    uint32_t width = (data[0] << 8) | data[1];
    width = 1 + (width % 2048); // Ensure width is 1 to 2048
    uint32_t height = (data[2] << 8) | data[3];
    height = 1 + (height % 2048); // Ensure height is 1 to 2048

    // Format: select from valid PNG formats
    uint8_t format_byte = data[4];
    png_uint_32 format;
    switch (format_byte % 8) {
        case 0: format = PNG_FORMAT_GRAY; break;
        case 1: format = PNG_FORMAT_GA; break;
        case 2: format = PNG_FORMAT_AG; break;
        case 3: format = PNG_FORMAT_RGB; break;
        case 4: format = PNG_FORMAT_BGR; break;
        case 5: format = PNG_FORMAT_RGBA; break;
        case 6: format = PNG_FORMAT_ARGB; break;
        case 7: format = PNG_FORMAT_BGRA; break;
        default: format = PNG_FORMAT_RGB; break;
    }

    // Decide whether to convert to 8-bit or keep 16-bit
    int convert_to_8bit = (data[5] % 2);

    // Calculate expected buffer size based on format
    unsigned int channels = PNG_IMAGE_PIXEL_CHANNELS(format);
    size_t pixel_size = (format & PNG_FORMAT_FLAG_LINEAR) ? sizeof(png_uint_16) : sizeof(png_byte);
    size_t row_stride = width * channels * pixel_size;

    // Check if input data is sufficient for image buffer
    size_t required_size = height * row_stride;
    if (size < required_size + 8) {
        return 0; // Not enough data for image buffer
    }

    // Set image parameters
    image.width = width;
    image.height = height;
    image.format = format;

    // Use remaining input data as image buffer
    const void *buffer = data + 8;

    // Optional colormap for paletted images
    void *colormap = NULL;
    png_uint_32 colormap_entries = 0;
    if (format_byte % 16 == 8) { // Occasionally test colormap
        image.format |= PNG_FORMAT_FLAG_COLORMAP;
        colormap_entries = 1 + (data[6] % 256); // Up to 256 entries
        image.colormap_entries = colormap_entries;
        // Use part of input data for colormap
        if (size > required_size + 8 + colormap_entries * channels) {
            colormap = (void *)(data + 8 + required_size);
        } else {
            colormap_entries = 0; // Not enough data
            image.colormap_entries = 0;
        }
    }

    // Output memory buffer for PNG data
    png_alloc_size_t memory_bytes = 0;

    // Write PNG to memory
    int result = png_image_write_to_memory(&image, NULL, &memory_bytes,
                                          convert_to_8bit, buffer,
                                          (png_int_32)row_stride, colormap);

    // If memory_bytes is set, try writing with an actual buffer
    if (memory_bytes > 0 && memory_bytes < 10000000) { // Limit output size
        void *memory = malloc(memory_bytes);
        if (memory) {
            result = png_image_write_to_memory(&image, memory, &memory_bytes,
                                              convert_to_8bit, buffer,
                                              (png_int_32)row_stride, colormap);
            free(memory);
        }
    }

    // Clean up
    png_image_free(&image);

    return 0;
}