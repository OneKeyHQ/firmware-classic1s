#include "bounded_heap.h"

#include <errno.h>

bool bounded_heap_init(BoundedHeap *heap, void *start, void *end) {
  uintptr_t start_address = (uintptr_t)start;
  uintptr_t end_address = (uintptr_t)end;

  if (heap == NULL || start == NULL || end == NULL ||
      start_address > end_address) {
    return false;
  }

  heap->start = start_address;
  heap->current = start_address;
  heap->end = end_address;
  return true;
}

bool bounded_heap_adjust(BoundedHeap *heap, ptrdiff_t increment,
                         void **previous_break) {
  if (heap == NULL || previous_break == NULL || heap->start > heap->current ||
      heap->current > heap->end) {
    return false;
  }

  uintptr_t previous = heap->current;
  if (increment > 0) {
    size_t amount = (size_t)increment;
    if (amount > heap->end - heap->current) {
      return false;
    }
    heap->current += amount;
  } else if (increment < 0) {
    /* Avoid negating PTRDIFF_MIN. */
    size_t amount = (size_t)(-(increment + 1));
    amount++;
    if (amount > heap->current - heap->start) {
      return false;
    }
    heap->current -= amount;
  }

  *previous_break = (void *)previous;
  return true;
}

#if !defined(EMULATOR) || !EMULATOR
extern uint8_t _heap_start[];
extern uint8_t _heap_end[];

void *_sbrk(ptrdiff_t increment) {
  static BoundedHeap heap;
  static bool heap_initialized;
  void *previous_break = NULL;

  if (!heap_initialized) {
    if (!bounded_heap_init(&heap, _heap_start, _heap_end)) {
      errno = ENOMEM;
      return (void *)-1;
    }
    heap_initialized = true;
  }

  if (!bounded_heap_adjust(&heap, increment, &previous_break)) {
    errno = ENOMEM;
    return (void *)-1;
  }

  return previous_break;
}
#endif
