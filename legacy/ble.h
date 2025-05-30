#ifndef __BLE_H__
#define __BLE_H__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "trans_fifo.h"

#define BLE_NAME_LEN 0x12
#define BLE_ADV_OFF 0x00
#define BLE_ADV_ON 0x01
#define BLE_ADV_ON_TEMP 0x05
#define BLE_ADV_OFF_TEMP 0x06

#define BUTTON_PRESS_BLE_ON 0x01
#define BUTTON_PRESS_BLE_OFF 0x02

enum {
  BLE_CMD_CONNECT_STATE = 0x01,
  BLE_CMD_PAIR_STATE = 0x02,
  BLE_CMD_PASSKEY = 0x03,
  BLE_CMD_BT_NAME = 0x04,
  BLE_CMD_BATTERY = 0x05,
  BLE_CMD_VER = 0x06,
  BLE_CMD_ONOFF_BLE = 0x07,
  BLE_CMD_DFU_STA = 0x0A,
  BLE_CMD_DEVICE_PUBKEY = 0x0B,
  BLE_CMD_DEVICE_SIGN = 0x0C,
  BLE_CMD_BUILD_ID = 0x0D,
  BLE_CMD_HASH = 0x0E,
  BLE_CMD_HW_VER = 0x0F
};

typedef enum {
  HW_VER_INVALID = 0xFFFF,
  HW_VER_V_1_X = 3300,
  HW_VER_V_2_0 = 2072,
  HW_VER_V_PURE = 984,
  HW_VER_V_ERROR = 0,
} HW_VER_t;

enum { BLE_PBUKEY_GET = 0x00, BLE_PBUKEY_LOCK = 0x01 };

bool ble_connect_state(void);
void ble_request_info(uint8_t type);
void ble_ctl_onoff(void);
void ble_reset(void);
void ble_uart_poll(uint8_t *buf);
void ble_update_poll(void);

int ble_get_error(void);
bool ble_get_pubkey(uint8_t *pubkey);
bool ble_lock_pubkey(void);
bool ble_sign_msg(uint8_t *msg, uint32_t msg_len, uint8_t *sign);
bool ble_get_version(char **ver);
bool ble_get_hw_version(HW_VER_t *ver);

#if !EMULATOR

bool ble_hw_ver_is_pure(void);
bool ble_is_enable(void);
bool ble_name_state(void);
bool ble_ver_state(void);
bool ble_build_id_state(void);
bool ble_hash_state(void);
bool ble_battery_state(void);
char *ble_get_name(void);
char *ble_get_ver(void);
char *ble_get_build_id(void);
uint8_t *ble_get_hash(void);
bool ble_switch_state(void);
void ble_set_switch(bool flag);
bool ble_get_switch(void);
void ble_request_switch_state(void);
void change_ble_sta(uint8_t mode);
bool ble_passkey_state(void);
bool ble_hw_ver_state(void);
#else
#define ble_name_state(...) false
#define ble_ver_state(...) false
#define ble_get_name(...) "K0000"
#define ble_get_ver(...) "1.0.1"
#define ble_switch_state(...) false
#define ble_set_switch(...)
#define ble_get_switch(...) false
#define change_ble_sta(...)

#define ble_get_build_id(void) "1234567"
#define ble_get_hash(void) "6551e797240051925b8a62615f4c8baa"
#define ble_build_id_state(...) false
#define ble_hash_state(...) false
#define ble_hw_ver_is_pure() true
#endif

#endif
