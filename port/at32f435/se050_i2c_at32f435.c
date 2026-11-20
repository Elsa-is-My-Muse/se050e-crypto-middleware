#include "se050_board_at32f435.h"
#include "se050_port_i2c.h"
#include "se050_config.h"
#include "at32f435_437.h"
#include "i2c_a7.h"

static int initialized;
static int port_token;
static unsigned int bus_khz = SE050_I2C_DEFAULT_KHZ;
static uint32_t half_cycles;
unsigned int se050_i2c_get_speed(void)
{
    return bus_khz;
}
rt_err_t se050_i2c_set_speed(unsigned int khz)
{
    if (khz != 100u && khz != 400u)
        return -RT_EINVAL;
    bus_khz = khz;
    half_cycles = system_core_clock / (khz * 2000u);
    return RT_EOK;
}

static void half_delay(void)
{
    uint32_t start = DWT->CYCCNT;
    while ((uint32_t)(DWT->CYCCNT - start) < half_cycles)
    {
    }
}
static void sda(int high)
{
    gpio_bits_write(GPIOB, SE050_SDA_PIN, (confirm_state)(high != 0));
}
static void scl_low(void)
{
    gpio_bits_reset(GPIOB, SE050_SCL_PIN);
}
static int sda_read(void)
{
    return gpio_input_data_bit_read(GPIOB, SE050_SDA_PIN) == SET;
}

/* Open drain high means release. Always observe SCL for clock stretching. */
static int scl_high(void)
{
    uint32_t start = DWT->CYCCNT;
    uint32_t limit = (system_core_clock / 1000000U) * SE050_SCL_TIMEOUT_US;
    gpio_bits_set(GPIOB, SE050_SCL_PIN);
    while (gpio_input_data_bit_read(GPIOB, SE050_SCL_PIN) == RESET)
    {
        if ((uint32_t)(DWT->CYCCNT - start) >= limit)
            return 0;
    }
    return 1;
}

static int stop(void)
{
    sda(0);
    half_delay();
    if (!scl_high())
    {
        sda(1);
        return 0;
    }
    half_delay();
    sda(1);
    half_delay();
    return sda_read();
}

rt_err_t se050_i2c_recover(void)
{
    unsigned i;
    sda(1);
    for (i = 0; i < 9 && !sda_read(); ++i)
    {
        scl_low();
        half_delay();
        if (!scl_high())
            return -RT_ETIMEOUT;
        half_delay();
    }
    return stop() ? RT_EOK : -RT_EIO;
}

rt_err_t se050_i2c_init(void)
{
    gpio_init_type pins;
    if (initialized)
        return RT_EOK;
    (void)se050_i2c_set_speed(bus_khz);
    crm_periph_clock_enable(CRM_GPIOB_PERIPH_CLOCK, (confirm_state)1);
    gpio_default_para_init(&pins);
    pins.gpio_pins = SE050_SCL_PIN | SE050_SDA_PIN;
    pins.gpio_mode = GPIO_MODE_OUTPUT;
    pins.gpio_out_type = GPIO_OUTPUT_OPEN_DRAIN;
    pins.gpio_pull = GPIO_PULL_NONE; /* external 4.7 kOhm on the PCB */
    pins.gpio_drive_strength = GPIO_DRIVE_STRENGTH_STRONGER;
    gpio_bits_set(GPIOB, pins.gpio_pins);
    gpio_init(GPIOB, &pins);
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    if (se050_i2c_recover() != RT_EOK)
        return -RT_EIO;
    initialized = 1;
    return RT_EOK;
}

static i2c_error_t start_address(void)
{
    sda(1);
    if (!scl_high())
        return I2C_TIME_OUT;
    if (!sda_read())
        return I2C_BUSY;
    half_delay();
    sda(0);
    half_delay();
    scl_low();
    return I2C_OK;
}

static i2c_error_t write_byte(uint8_t value)
{
    unsigned bit;
    int ack;
    for (bit = 0; bit < 8; ++bit)
    {
        sda((value & 0x80U) != 0);
        value <<= 1;
        half_delay();
        if (!scl_high())
            return I2C_TIME_OUT;
        half_delay();
        scl_low();
    }
    sda(1);
    half_delay();
    if (!scl_high())
        return I2C_TIME_OUT;
    half_delay();
    ack = !sda_read();
    scl_low();
    half_delay();
    return ack ? I2C_OK : I2C_NACK_ON_DATA;
}

i2c_error_t axI2CInit(void **context, const char *name)
{
    (void)name;
    if (se050_i2c_init() != RT_EOK)
        return I2C_FAILED;
    if (context != RT_NULL)
        *context = &port_token; /* prevent double open */
    return I2C_OK;
}

void axI2CTerm(void *context, int mode)
{
    (void)context;
    (void)mode;
    sda(1);
    (void)scl_high();
}

/* Called exclusively under the session mutex in se050.c. */
i2c_error_t axI2CWrite(void *context, unsigned char bus, unsigned char address, unsigned char *data,
                       unsigned short length)
{
    i2c_error_t status;
    unsigned i;
    (void)context;
    (void)bus;
    if (data == RT_NULL || length == 0 || length > MAX_DATA_LEN)
        return I2C_FAILED;
    rt_tick_t started = rt_tick_get();
    status = start_address();
    if (status == I2C_OK)
    {
        status = write_byte(address & 0xFEU);
        if (status == I2C_NACK_ON_DATA)
            status = I2C_NACK_ON_ADDRESS;
    }
    for (i = 0; status == I2C_OK && i < length; ++i)
        status = write_byte(data[i]);
    if (!stop() && status == I2C_OK)
        status = I2C_TIME_OUT;
    se050_transport_note_io(
        1, length, status == I2C_NACK_ON_ADDRESS || status == I2C_NACK_ON_DATA,
        status != I2C_OK && status != I2C_NACK_ON_ADDRESS && status != I2C_NACK_ON_DATA, started);
    return status;
}

i2c_error_t axI2CRead(void *context, unsigned char bus, unsigned char address, unsigned char *data,
                      unsigned short length)
{
    i2c_error_t status;
    unsigned i, bit;
    (void)context;
    (void)bus;
    if (data == RT_NULL || length == 0 || length > MAX_DATA_LEN)
        return I2C_FAILED;
    rt_tick_t started = rt_tick_get();
    status = start_address();
    if (status == I2C_OK)
    {
        status = write_byte(address | 1U);
        if (status == I2C_NACK_ON_DATA)
            status = I2C_NACK_ON_ADDRESS;
    }
    for (i = 0; status == I2C_OK && i < length; ++i)
    {
        uint8_t value = 0;
        sda(1);
        for (bit = 0; bit < 8; ++bit)
        {
            half_delay();
            if (!scl_high())
            {
                status = I2C_TIME_OUT;
                break;
            }
            half_delay();
            value = (uint8_t)((value << 1) | sda_read());
            scl_low();
        }
        if (status != I2C_OK)
            break;
        data[i] = value;
        sda(i + 1 == length);
        half_delay();
        if (!scl_high())
        {
            status = I2C_TIME_OUT;
            break;
        }
        half_delay();
        scl_low();
        sda(1);
    }
    if (!stop() && status == I2C_OK)
        status = I2C_TIME_OUT;
    se050_transport_note_io(
        0, length, status == I2C_NACK_ON_ADDRESS || status == I2C_NACK_ON_DATA,
        status != I2C_OK && status != I2C_NACK_ON_ADDRESS && status != I2C_NACK_ON_DATA, started);
    return status;
}

rt_err_t se050_i2c_probe(void)
{
    i2c_error_t status;
    if (se050_i2c_init() != RT_EOK)
        return -RT_EIO;
    /* A previous failed exchange may have left the slave holding SDA. */
    if (se050_i2c_recover() != RT_EOK)
        return -RT_EIO;
    status = start_address();
    if (status == I2C_OK)
        status = write_byte(SE050_I2C_ADDRESS << 1);
    if (!stop() && status == I2C_OK)
        status = I2C_TIME_OUT;
    return status == I2C_OK ? RT_EOK : -RT_EIO;
}
