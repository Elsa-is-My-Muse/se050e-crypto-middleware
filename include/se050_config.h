/** @file se050_config.h
 * @brief Overridable build settings; existing safe/lab defaults are unchanged.
 */
#ifndef SSWL_SE050_CONFIG_H
#define SSWL_SE050_CONFIG_H

/* Library configuration. Board GPIOs live under port/<board>/. */
#ifndef SE050_I2C_ADDRESS
#define SE050_I2C_ADDRESS 0x48U
#endif
#ifndef SE050_I2C_DEFAULT_KHZ
#define SE050_I2C_DEFAULT_KHZ 100U
#endif
#ifndef SE050_APDU_MAX
#define SE050_APDU_MAX 1024U
#endif

/* Full bench integration after version/random have passed on the new PCB.
 * No software entropy/signing fallback when enabled. Provision the matching
 * SE050 key explicitly before TLS. Production also requires secure provisioning. */
#ifndef SE050_MBEDTLS_ENTROPY
#define SE050_MBEDTLS_ENTROPY 1
#endif
#ifndef SE050_TLS_PRIVATE_KEY
#define SE050_TLS_PRIVATE_KEY 1
#endif

/* Experimental paths are available in the normal project. Keep the existing
 * baseline at boot; enable independently between disconnected sessions using
 * se050 offload <verify:0|1> <tls13_ecdhe:0|1>. Changes reset on reboot.
 * Identity signing/entropy are independent of these two switches. */
#ifndef SE050_TLS_VERIFY
#define SE050_TLS_VERIFY 0
#endif
#ifndef SE050_TLS_ECDHE
#define SE050_TLS_ECDHE 0
#endif

#endif
