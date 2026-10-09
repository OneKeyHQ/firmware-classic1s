#ifndef SE_VERSION_H
#define SE_VERSION_H

#include <stdbool.h>
#include <stdint.h>

bool se_version_is_at_least(const char *version, uint8_t required_major,
                            uint8_t required_minor, uint8_t required_patch);

#endif
