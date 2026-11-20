#ifndef SE050_BOARD_AT32F435_H
#define SE050_BOARD_AT32F435_H
/* 15118-BOARD-V1-5 sheet 2: PB8 -> U6.10, PB9 -> U6.9.
 * ENA is tied high; there is no host-controlled reset/enable GPIO. */
#define SE050_SCL_PIN GPIO_PINS_8
#define SE050_SDA_PIN GPIO_PINS_9
#define SE050_SCL_TIMEOUT_US 10000U
#endif
