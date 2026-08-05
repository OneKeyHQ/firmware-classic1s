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

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "usb.h"

#include "debug.h"
#include "fido2/ctap_trans.h"
#include "messages.h"
#include "timer.h"

static volatile char tiny = 0;

void usbInit(void) { emulatorSocketInit(); }

#if DEBUG_LINK
#define _ISDBG (((iface == 1) ? 'd' : 'n'))
#else
#define _ISDBG ('n')
#endif

void waitAndProcessUSBRequests(uint32_t millis) {
  emulatorPoll();

  static uint8_t buffer[USB_PACKET_SIZE];

  int iface = 0;
  size_t received =
      emulatorSocketRead(&iface, buffer, sizeof(buffer), millis);
  if (received > 0) {
    if (iface == 2) {
      if (received == sizeof(U2FHID_FRAME)) {
        U2FHID_FRAME frame;
        memcpy(&frame, buffer, sizeof(frame));
        u2fhid_read(tiny, &frame);
        usb_u2f_data_send();
      }
    } else if (!tiny) {
      msg_read_common(_ISDBG, buffer, received);
    } else {
      msg_read_tiny(buffer, received);
    }
  }

  const uint8_t *data;
  while ((data = msg_out_data()) != NULL) {
    emulatorSocketWrite(0, data, USB_PACKET_SIZE);
  }

#if DEBUG_LINK
  while ((data = msg_debug_out_data()) != NULL) {
    emulatorSocketWrite(1, data, USB_PACKET_SIZE);
  }
#endif
}

void usbPoll(void) { waitAndProcessUSBRequests(0); }

void usb_u2f_data_send(void) {
  const uint8_t *data;
  while ((data = u2f_out_data()) != NULL) {
    emulatorSocketWrite(2, data, USB_PACKET_SIZE);
  }
}

void usbDisconnect(void) {}

void usbReconnect(void) {}

char usbTiny(char set) {
  char old = tiny;
  tiny = set;
  return old;
}

void usbFlush(uint32_t millis) {
  const uint8_t *data;
  while ((data = msg_out_data()) != NULL) {
    emulatorSocketWrite(0, data, USB_PACKET_SIZE);
  }
  usleep(millis * 1000);
}
