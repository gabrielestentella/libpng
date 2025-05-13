#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <iostream>
#define PNG_INTERNAL
#include "png.h"

struct BufState {
  const uint8_t* data;
  size_t bytes_left;
};

struct PngObjectHandler {
  png_infop info_ptr = nullptr;
  png_structp png_ptr = nullptr;
  png_infop end_info_ptr = nullptr;
  BufState* buf_state = nullptr;
};

void user_read_data(png_structp png_ptr, png_bytep data, size_t length) {
  BufState* buf_state = static_cast<BufState*>(png_get_io_ptr(png_ptr));
  if (length > buf_state->bytes_left) {
    png_error(png_ptr, "read error");
  }
  memcpy(data, buf_state->data, length);
  buf_state->bytes_left -= length;
  buf_state->data += length;
}

int parse_png(const uint8_t* data, size_t size) {
  PngObjectHandler png_handler;
  png_handler.png_ptr = nullptr;
  png_handler.info_ptr = nullptr;
  png_handler.png_ptr = png_create_read_struct
    (PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png_handler.png_ptr) {
    return 0;
  }
  png_handler.info_ptr = png_create_info_struct(png_handler.png_ptr);
  if (!png_handler.info_ptr) {
    return 0;
  }
  png_set_crc_action(png_handler.png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
  // Setting up reading from buffer.
  png_handler.buf_state = new BufState();
  png_handler.buf_state->data = data + 8;
  png_handler.buf_state->bytes_left = size - 8;
  png_set_read_fn(png_handler.png_ptr, png_handler.buf_state, user_read_data);
  png_set_sig_bytes(png_handler.png_ptr, 8);
  // Reading.
  png_read_info(png_handler.png_ptr, png_handler.info_ptr);
  int unit;
  png_charpp width_3, height_3;
  png_get_sCAL_s(png_handler.png_ptr, png_handler.info_ptr, &unit, width_3, height_3);
  return 0;
}

int main(int argc, char* argv[]) {
  std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);
  std::vector<uint8_t> buffer(size);
  if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
    std::cerr << "Error reading file: " << argv[1] << "\n";
    return 1;
  }
  return parse_png(buffer.data(), buffer.size());
}
