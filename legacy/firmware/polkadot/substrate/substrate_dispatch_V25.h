#ifndef __POLKADOT_SUBSTRATE_DISPATCH_V25_H__
#define __POLKADOT_SUBSTRATE_DISPATCH_V25_H__

#include <stddef.h>
#include <stdint.h>
#include "../parser_impl.h"
#include "stdbool.h"
#include "substrate_functions.h"
#include "substrate_functions_V25.h"

parser_error_t _readMethod_V25(parser_context_t* c, uint8_t moduleIdx,
                               uint8_t callIdx, pd_Method_V25_t* method);

const char* _getMethod_ModuleName_V25(uint8_t moduleIdx);

const char* _getMethod_Name_V25(uint8_t moduleIdx, uint8_t callIdx);
const char* _getMethod_Name_V25_ParserFull(uint16_t callPrivIdx);

const char* _getMethod_ItemName_V25(uint8_t moduleIdx, uint8_t callIdx,
                                    uint8_t itemIdx);

uint8_t _getMethod_NumItems_V25(uint8_t moduleIdx, uint8_t callIdx);

parser_error_t _getMethod_ItemValue_V25(pd_Method_V25_t* m, uint8_t moduleIdx,
                                        uint8_t callIdx, uint8_t itemIdx,
                                        char* outValue, uint16_t outValueLen,
                                        uint8_t pageIdx, uint8_t* pageCount);

bool _getMethod_ItemIsExpert_V25(uint8_t moduleIdx, uint8_t callIdx,
                                 uint8_t itemIdx);
bool _getMethod_IsNestingSupported_V25(uint8_t moduleIdx, uint8_t callIdx);
#endif
