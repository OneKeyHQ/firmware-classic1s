#ifndef COMPATIBLE_H
#define COMPATIBLE_H

#define OLED_SPI_BASE SPI1
#define RCC_OLED_SPI RCC_SPI1
#define RCC_OLED_DATA RCC_GPIOA  // data:Nss Sck Mosi
#define RCC_OLED_COTL RCC_GPIOB  // control: D/C and Reset

#define OLED_DC_PORT GPIOB
#define OLED_DC_PIN GPIO0  // PB0 | Data/Command
#define OLED_CS_PORT GPIOA
#define OLED_CS_PIN GPIO4  // PA4 | SPI Select
#define OLED_RST_PORT GPIOB
#define OLED_RST_PIN GPIO1   // PB1 | Reset display
#define OLED_SCK_PIN GPIO5   // PA5 | SPI CLK
#define OLED_MOSI_PIN GPIO7  // PA4 | SPI MOSI

// usb define
#define otgfs_usb_driver_onekey gd32f470_usb_driver
// usart define
#define BLE_UART USART2

// keys define
#define BTN_PORT GPIOC
#define BTN_PORT_NO BTN_POWER_PORT

#define BTN_PIN_YES GPIO2
#define BTN_PIN_NO BTN_POWER_PIN
#define BTN_PIN_UP GPIO3
#define BTN_PIN_DOWN GPIO5

// se chip define
#define GPIO_MI2C_SCL GPIO6
#define GPIO_MI2C_SDA GPIO7
#define MI2C_RETRYCNTS (5000)  // timeout 10 s
#define MI2C_TIMEOUT (40000)   // 5ms
#define MI2C_ADDR_ACK_TIMEOUT (1000)
// #define MI2C_TIMEOUT (32000)   // 4ms

#endif  // COMPATIBLE_H
