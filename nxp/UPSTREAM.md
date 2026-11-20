# NXP transport subset

Source: the locally downloaded `se05x_mw_v04.08.01/simw-top` package.
Files retain their original NXP copyright and Apache-2.0 notices.
The Apache license text is provided in `LICENSE`.

Original locations:

- `hostlib/hostLib/libCommon/smCom/T1oI2C`: protocol/PAL C files and headers.
- `hostlib/hostLib/libCommon/smCom`: `smCom*` sources and headers.
- `hostlib/hostLib/libCommon/infra`, `libCommon/log`: shared transport headers.
- `hostlib/hostLib/platform/inc`, `hostlib/hostLib/inc`: platform declarations.

Only the transitive header subset required by the five C files is retained.
The full SSS API, SCP03 and NXP SDK are not included.

Vendor modification: `smComT1oI2C.c` no longer includes the unused
`sm_printf.h`, which otherwise imports an NXP MCU SDK debug console when
`AX_EMBEDDED=1`. Logging and delays are supplied by `../port/at32f435/se050_platform_at32f435.c`.
Allocators and the transport feature profile are local adapters in the parent
directory. `USE_RTOS=0` disables NXP FreeRTOS hooks only for this group;
the RT-Thread wrapper serializes complete sessions with its own mutex.

Local READ-polling experiment (2026-11-19): `phNxpEsePal_i2c.c` includes
`se050.h` and calls an optional intermediate-read probe inside the existing
backoff window. The power-on default (`se050 poll sdk`) follows the unmodified
SDK wait path. `se050 poll 2|5|10` requires a validated ATR MPOT plus a one-tick guard; it does not
change WRITE backoff, generic I2C error classification, retry counts or the
all-NACK requested sleep budget. Intermediate probes contain no new APDU.
Use `se050 poll sdk` to revert. Hardware timing/reliability remains to be tested.
