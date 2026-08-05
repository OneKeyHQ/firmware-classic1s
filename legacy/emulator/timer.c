/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2017 Saleem Rashid <trezor@saleemrashid.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <time.h>
#include <string.h>

#include "timer.h"

#define EMULATOR_TIMER_COUNT 8

typedef struct {
  char name[32];
  uint32_t last;
  uint32_t cycle;
  timer_func callback;
} EmulatorTimer;

static EmulatorTimer emulator_timers[EMULATOR_TIMER_COUNT];
static timer_func emulator_loop_callback;
static uint32_t emulator_loop_last;
static uint32_t emulator_loop_interval;

void timer_init(void) {
  memset(emulator_timers, 0, sizeof(emulator_timers));
  emulator_loop_callback = NULL;
}

static uint32_t timer_out_array[timer_out_null];
static void timer_out_decrease(void) {
  uint32_t i = timer_out_null;
  while (i--) {
    if (timer_out_array[i]) timer_out_array[i]--;
  }
}
void timer_out_set(TimerOut type, uint32_t val) { timer_out_array[type] = val; }
uint32_t timer_out_get(TimerOut type) { return timer_out_array[type]; }

uint32_t timer_ms(void) {
  static int counter = 0;
  struct timespec t = {0};
  counter++;
  clock_gettime(CLOCK_MONOTONIC, &t);

  uint32_t msec = t.tv_sec * 1000 + (t.tv_nsec / 1000000);
  if (counter > 1000) {
    counter = 0;
    timer_out_decrease();
  }
  return msec;
}

void delay_ms(uint32_t uiDelay_Ms) { (void)uiDelay_Ms; }

void delay_us(uint32_t uiDelay_us) { (void)uiDelay_us; }

uint32_t svc_timer_ms(void) { return timer_ms(); }

void svc_system_reset(void) {}

void register_timer(char *name, uint32_t cycle, timer_func callback) {
  EmulatorTimer *free_slot = NULL;

  for (size_t i = 0; i < EMULATOR_TIMER_COUNT; i++) {
    if (emulator_timers[i].callback != NULL &&
        strcmp(emulator_timers[i].name, name) == 0) {
      free_slot = &emulator_timers[i];
      break;
    }
    if (free_slot == NULL && emulator_timers[i].callback == NULL) {
      free_slot = &emulator_timers[i];
    }
  }

  if (free_slot == NULL) return;
  strncpy(free_slot->name, name, sizeof(free_slot->name) - 1);
  free_slot->name[sizeof(free_slot->name) - 1] = '\0';
  free_slot->last = timer_ms();
  free_slot->cycle = cycle;
  free_slot->callback = callback;
}

void unregister_timer(char *name) {
  for (size_t i = 0; i < EMULATOR_TIMER_COUNT; i++) {
    if (emulator_timers[i].callback != NULL &&
        strcmp(emulator_timers[i].name, name) == 0) {
      memset(&emulator_timers[i], 0, sizeof(emulator_timers[i]));
      return;
    }
  }
}

void register_loop_callback(timer_func callback, uint32_t start,
                            uint32_t interval) {
  emulator_loop_callback = callback;
  emulator_loop_last = start;
  emulator_loop_interval = interval;
}

void unregister_loop_callback(void) { emulator_loop_callback = NULL; }

void loop_callback_handler(void) {
  uint32_t now = timer_ms();

  for (size_t i = 0; i < EMULATOR_TIMER_COUNT; i++) {
    EmulatorTimer *timer = &emulator_timers[i];
    if (timer->callback != NULL && now - timer->last >= timer->cycle) {
      timer_func callback = timer->callback;
      timer->last = now;
      callback();
    }
  }

  if (emulator_loop_callback != NULL &&
      now - emulator_loop_last >= emulator_loop_interval) {
    timer_func callback = emulator_loop_callback;
    emulator_loop_last = now;
    callback();
  }
}

void timer_sleep_start_reset(void) {}

uint32_t timer_get_sleep_count(void) { return 0; }
