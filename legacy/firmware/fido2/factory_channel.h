#ifndef FACTORY_CHANNEL_H
#define FACTORY_CHANNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "transport_limits.h"

#define FACTORY_CHANNEL_RESPONSE_BUFFER_SIZE (TRANSPORT_MAX_RESPONSE + 2)

static inline bool factory_channel_append_status(uint8_t *buffer,
                                                 uint16_t *response_len,
                                                 uint16_t status) {
  if (buffer == NULL || response_len == NULL ||
      *response_len > TRANSPORT_MAX_RESPONSE) {
    return false;
  }

  buffer[*response_len] = (uint8_t)(status >> 8);
  buffer[*response_len + 1] = (uint8_t)status;
  *response_len += 2;
  return true;
}

#endif
