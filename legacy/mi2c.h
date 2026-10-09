#ifndef _mi2c_H_
#define _mi2c_H_

#include <stdint.h>
#include <string.h>

#include "sys.h"
#include "transport_limits.h"
#include "usart.h"

#define MI2C_DATA_MAX_LEN TRANSPORT_MAX_PAYLOAD
#define MI2C_BUF_MAX_LEN TRANSPORT_MAX_RESPONSE
#define MI2C_SEND_MAX_LEN TRANSPORT_MAX_RESPONSE

#define MI2CX I2C1

// master I2C gpio
#define GPIO_MI2C_PORT GPIOB

#ifdef NORMAL_PCB
// SE power IO
#define GPIO_SE_PORT GPIOB
#define GPIO_SE_POWER GPIO13
#else

// SE power IO
#define GPIO_SE_PORT GPIOC
#define GPIO_SE_POWER GPIO8

#endif

// power control SE
#define POWER_ON_SE() (gpio_set(GPIO_SE_PORT, GPIO_SE_POWER))
#define POWER_OFF_SE() (gpio_clear(GPIO_SE_PORT, GPIO_SE_POWER))

// master I2C addr
#define MI2C_ADDR 0x10
#define MI2C_READ 0x01
#define MI2C_WRITE 0x00

#define MI2C_XOR_LEN (1)

// #define	GET_MI2C_COMBUS	        (gpio_get(GPIO_MI2C_PORT, MI2C_COMBUS))

#if !EMULATOR
extern void vMI2CDRV_Init(void);
extern bool bMI2CDRV_ReceiveData(uint8_t *pucStr, uint16_t *pusRevLen);
extern bool bMI2CDRV_SendData(uint8_t *pucStr, uint16_t usStrLen);
extern bool bMI2CDRV_ReceiveDataRaw(uint8_t *data, uint16_t *data_len,
                                    uint16_t *sw1sw2, bool fatal);
extern bool bMI2CDRV_SendDataRaw(const uint8_t *data, uint16_t data_len,
                                 bool fatal);
extern uint16_t get_lasterror(void);
#else
#define vMI2CDRV_Init(...)
#define bMI2CDRV_SendData(...) true
#define bMI2CDRV_ReceiveData(...) true
#define bMI2CDRV_SendDataRaw(...) true
#define bMI2CDRV_ReceiveDataRaw(...) true
#endif

#endif
