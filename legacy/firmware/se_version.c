#include "se_version.h"

#include <stddef.h>

static bool parse_component(const char **cursor, uint8_t *component) {
  uint8_t value = 0;
  bool has_digit = false;

  while (**cursor >= '0' && **cursor <= '9') {
    uint8_t digit = (uint8_t)(**cursor - '0');

    if (value > 25 || (value == 25 && digit > 5)) {
      return false;
    }
    value = (uint8_t)(value * 10 + digit);
    has_digit = true;
    (*cursor)++;
  }
  if (!has_digit) {
    return false;
  }
  *component = value;
  return true;
}

bool se_version_is_at_least(const char *version, uint8_t required_major,
                            uint8_t required_minor, uint8_t required_patch) {
  uint8_t components[4] = {0};
  const char *cursor = version;

  if (cursor == NULL) {
    return false;
  }
  for (uint8_t index = 0; index < 4; index++) {
    if (!parse_component(&cursor, &components[index])) {
      return false;
    }
    if (*cursor == '\0') {
      if (index < 2) {
        return false;
      }
      break;
    }
    if (*cursor != '.' || index == 3) {
      return false;
    }
    cursor++;
  }
  if (components[0] != required_major) {
    return components[0] > required_major;
  }
  if (components[1] != required_minor) {
    return components[1] > required_minor;
  }
  return components[2] >= required_patch;
}
