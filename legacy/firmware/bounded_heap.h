#ifndef BOUNDED_HEAP_H
#define BOUNDED_HEAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uintptr_t start;
  uintptr_t current;
  uintptr_t end;
} BoundedHeap;

bool bounded_heap_init(BoundedHeap *heap, void *start, void *end);
bool bounded_heap_adjust(BoundedHeap *heap, ptrdiff_t increment,
                         void **previous_break);

#endif  // BOUNDED_HEAP_H
