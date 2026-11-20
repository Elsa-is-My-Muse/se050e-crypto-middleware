/*
 * Copyright 2010-2014,2018-2020,2023,2025-2026 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * DAL i2c port implementation for linux
 *
 * Project: Trusted ESE Linux
 *
 */
#include <stdlib.h>
#include <errno.h>
#include <phNxpEsePal_i2c.h>
#include <phEseStatus.h>
#include <string.h>
#include "i2c_a7.h"

#ifdef FLOW_VERBOSE
#define NX_LOG_ENABLE_SMCOM_DEBUG 1
#endif

#include "nxLog_smCom.h"
#include "sm_timer.h"
/* Local optional READ polling hook; see UPSTREAM.md. */
#include "se050.h"

#include "se05x_reset_apis.h"
#if defined(Android) || defined(LINUX)
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/i2c-dev.h>
#include <unistd.h>
#endif

#include <time.h>

#define MAX_RETRY_CNT 10

static int gBackoffDelay = 0;

/*******************************************************************************
**
** Function         phPalEse_i2c_back_off_delay_reset
**
** Description      Back off delay is reset to 0
**
** param[in]        None
**
** Returns          None
**
*******************************************************************************/
static void phPalEse_i2c_back_off_delay_reset()
{
    LOG_D("phPalEse_i2c_back_off_delay_reset");
    gBackoffDelay = 0;
}

/*******************************************************************************
**
** Function         phPalEse_i2c_back_off_delay_wait
**
** Description      Delay is incremented by 1 for every call
**
** param[in]        None
**
** Returns          None
**
*******************************************************************************/
static void phPalEse_i2c_back_off_delay_wait()
{
    if (gBackoffDelay < 200) {
        gBackoffDelay += 1;
    }
    LOG_D("phPalEse_i2c_back_off_delay_wait: %d ms", gBackoffDelay);
    sm_sleep(gBackoffDelay);
}

/*******************************************************************************
**
** Function         phPalEse_i2c_is_retryable_error
**
** Description      Check if the I2C error is retryable based on platform
**
** param[in]        ret - I2C error code
**
** Returns          1 if error is retryable, 0 otherwise
**
*******************************************************************************/
static int phPalEse_i2c_is_retryable_error(unsigned int ret)
{
    /* if platform returns different error codes, modify the check below.*/
#ifdef T1OI2C_RETRY_ON_I2C_FAILED
    if ((ret == I2C_FAILED) || (ret == I2C_NACK_ON_ADDRESS) || (ret == I2C_NACK_ON_DATA)) {
        return 1;
    }
#else
    if((ret == I2C_NACK_ON_ADDRESS)|| (ret == I2C_NACK_ON_DATA)) {
        return 1;
    }
#endif
    return 0;
}

/*******************************************************************************
**
** Function         phPalEse_i2c_close
**
** Description      Closes PN547 device
**
** param[in]        pDevHandle - device handle
**
** Returns          None
**
*******************************************************************************/
void phPalEse_i2c_close(void *pDevHandle)
{
#ifdef Android
    if (NULL != pDevHandle) {
        close((intptr_t)pDevHandle);
    }
#endif
    axI2CTerm(pDevHandle, 0);
    pDevHandle = NULL;

    return;
}

/*******************************************************************************
**
** Function         phPalEse_i2c_open_and_configure
**
** Description      Open and configure pn547 device
**
** param[in]        pConfig     - hardware information
**
** Returns          ESE status:
**                  ESESTATUS_SUCCESS            - open_and_configure operation success
**                  ESESTATUS_INVALID_DEVICE     - device open operation failure
**
*******************************************************************************/
ESESTATUS phPalEse_i2c_open_and_configure(pphPalEse_Config_t pConfig)
{
    void *conn_ctx = NULL;
    int retryCnt = 0;
    unsigned int i2c_ret = 0;

    // Initializing Global variable gBackoffDelay
    phPalEse_i2c_back_off_delay_reset();

    LOG_D("%s Opening port", __FUNCTION__);
retry:
    i2c_ret = axI2CInit(&conn_ctx, (const char *)pConfig->pDevName);
    if (i2c_ret != I2C_OK) {
        LOG_E("%s Failed retry ", __FUNCTION__);
        if (i2c_ret == I2C_BUSY) {
            retryCnt++;
            LOG_E("Retry open eSE driver, retry cnt : %d ", retryCnt);
            if (retryCnt < MAX_RETRY_CNT) {
                sm_sleep(ESE_POLL_DELAY_MS);
                goto retry;
            }
        }
        LOG_E("I2C init Failed: retval %x ", i2c_ret);
        pConfig->pDevHandle = NULL;
        return ESESTATUS_INVALID_DEVICE;
    }
    LOG_D("I2C driver Initialized :: fd = [%d] ", i2c_ret);
    pConfig->pDevHandle = conn_ctx;
    return ESESTATUS_SUCCESS;
}

/*******************************************************************************
**
** Function         phPalEse_i2c_read
**
** Description      Reads requested number of bytes from pn547 device into given buffer
**
** param[in]       pDevHandle       - valid device handle
** param[in]       pBuffer          - buffer for read data
** param[in]       nNbBytesToRead   - number of bytes requested to be read
**
** Returns          numRead   - number of successfully read bytes
**                  -1        - read operation failure
**
*******************************************************************************/
/* Local optional optimization: probe inside the SDK's existing backoff
 * window. All-NACK paths retain the same requested sleep budget and retry
 * counter (longer if ATR MPOT requires it). WRITE retries and protocol
 * recovery are deliberately unchanged.
 * Intermediate reads never occur less than the ATR's MPOT apart. */
static int se050_read_backoff_probe(void *handle, uint8_t *buffer, int length)
{
    unsigned int minimum = 0;
    unsigned int cap = se050_read_poll_limit(&minimum);
    unsigned int remaining;
    unsigned int ret;
    if (!cap) {
        phPalEse_i2c_back_off_delay_wait();
        return 0;
    }
    /* RTOS delay rounding can wake up to one tick before the nominal
     * interval. Keep that guard in addition to the ATR MPOT. */
    minimum += (1000u + SE050_TICKS_PER_SECOND - 1u) / SE050_TICKS_PER_SECOND;
    if (gBackoffDelay < 200) {
        gBackoffDelay += 1;
    }
    remaining = (unsigned int)gBackoffDelay;
    if (remaining < minimum) {
        remaining = minimum;
    }
    while (remaining > cap && remaining - cap >= minimum) {
        sm_sleep(cap);
        remaining -= cap;
        ret = axI2CRead(handle, I2C_BUS_0, SMCOM_I2C_ADDRESS, buffer, length);
        if (ret == I2C_OK) {
            return 1;
        }
        if (!phPalEse_i2c_is_retryable_error(ret)) {
            return -1;
        }
    }
    sm_sleep(remaining);
    return 0;
}

int phPalEse_i2c_read(void *pDevHandle, uint8_t *pBuffer, int nNbBytesToRead)
{
    unsigned int ret = 0;
    int retryCount = 0;
    int numRead = 0;

    LOG_D("%s Read Requested %d bytes ", __FUNCTION__, nNbBytesToRead);
    while (numRead != nNbBytesToRead) {
        ret = axI2CRead(pDevHandle, I2C_BUS_0, SMCOM_I2C_ADDRESS, pBuffer, nNbBytesToRead);
        if (ret != I2C_OK) {
            LOG_D("_i2c_read() error : %d ", ret);
            if (phPalEse_i2c_is_retryable_error(ret)) {
                int probe = se050_read_backoff_probe(pDevHandle, pBuffer, nNbBytesToRead);
                if (probe > 0) {
                    phPalEse_i2c_back_off_delay_reset();
                    return nNbBytesToRead;
                }
                if (probe < 0) {
                    return -1;
                }
                if(retryCount < MAX_RETRY_COUNT) {
                    retryCount++;
                    LOG_D("_i2c_read() failed. Going to retry, counter:%d  !", retryCount);
                    continue;
                }
            }
            return -1;
        }
        else {
            phPalEse_i2c_back_off_delay_reset();
            numRead = nNbBytesToRead;
            break;
        }
    }
    return numRead;
}

/*******************************************************************************
**
** Function         phPalEse_i2c_write
**
** Description      Writes requested number of bytes from given buffer into pn547 device
**
** param[in]       pDevHandle       - valid device handle
** param[in]       pBuffer          - buffer for read data
** param[in]       nNbBytesToWrite  - number of bytes requested to be written
**
** Returns          numWrote   - number of successfully written bytes
**                  -1         - write operation failure
**
*******************************************************************************/
int phPalEse_i2c_write(void *pDevHandle, uint8_t *pBuffer, int nNbBytesToWrite)
{
    unsigned int ret = I2C_OK;
    int retryCount = 0;
    int numWrote = 0;

    pBuffer[0] = 0x5A; //Recovery if stack forgot to add NAD byte.

    do {
        ret = axI2CWrite(pDevHandle, I2C_BUS_0, SMCOM_I2C_ADDRESS, pBuffer, nNbBytesToWrite);
        if (ret != I2C_OK) {
            LOG_D("_i2c_write() error : %d ", ret);
            if (phPalEse_i2c_is_retryable_error(ret) && (retryCount < MAX_RETRY_COUNT)) {
                /* Back-off delay wait with 1ms */
                phPalEse_i2c_back_off_delay_wait();
                retryCount++;
                LOG_D("_i2c_write() failed. Going to retry, counter:%d  !", retryCount);
                continue;
            }
            return -1;
        }
        else {
            phPalEse_i2c_back_off_delay_reset();
            numWrote = nNbBytesToWrite;
            break;
        }
    } while (ret != I2C_OK);

    return numWrote;
}
