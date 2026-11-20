/** @file se050_library.h
 * @brief Complete PSA/TLS entry point. Use se050_core.h for a TLS-independent core.
 */
#ifndef SE050_LIBRARY_H
#define SE050_LIBRARY_H
/* Common SE050E backend for the existing ISO15118-2 and ISO15118-20 stacks.
 * This library supplies crypto/key storage, not a complete ISO15118 stack. */
#include "se050_core.h"
#include "se050_psa.h"
#include "se050_tls.h"
#define SE050_LIBRARY_VERSION "1.0.0" /* Existing API version; packaging cleanup only. */
typedef enum
{
    SE050_PROFILE_ISO15118_2 = 0,
    SE050_PROFILE_ISO15118_20 = 1
} se050_profile_t;
#endif
