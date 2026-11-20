/** @file se050_port.h
 * @brief OS selection boundary. Every task-context caller must share the same port ABI.
 */
#ifndef SE050_PORT_H
#define SE050_PORT_H
#include <stddef.h>
#include <stdint.h>
/* Supply a different header and implementation for another RTOS/bare-metal port.
 * This default preserves the current BSP. Portable builds must explicitly select
 * their OS header; see port/template/se050_port_custom.h and README.md.
 * The selected port must provide signed errors, unsigned monotonic ticks,
 * real task exclusion and a stable unique task identity (never a global dummy).
 */
#ifndef SE050_PORT_HEADER
#define SE050_PORT_HEADER "se050_port_rtthread.h"
#endif
#include SE050_PORT_HEADER
#endif
