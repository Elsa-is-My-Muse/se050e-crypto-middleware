/* Allocator adapter: all OS dependencies pass through se050_port.h. */
#ifndef FSL_SSS_TYPES_H
#define FSL_SSS_TYPES_H
#include "se050_port.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define SSS_MALLOC se050_port_malloc
#define SSS_FREE se050_port_free
#define SSS_CALLOC se050_port_calloc
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif
#endif
