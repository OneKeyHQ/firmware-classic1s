#ifndef MI2C_FRAME_H
#define MI2C_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static inline bool mi2c_frame_transport_success(int result) {
  return result >= 0;
}

static inline bool mi2c_frame_payload_length(uint16_t wire_length,
                                             uint16_t caller_capacity,
                                             uint16_t response_data_max,
                                             uint16_t *payload_length) {
  uint16_t payload;

  if (payload_length == NULL || wire_length < 2) {
    return false;
  }
  payload = wire_length - 2;
  if (payload > response_data_max || payload > caller_capacity) {
    return false;
  }
  *payload_length = payload;
  return true;
}

#endif
