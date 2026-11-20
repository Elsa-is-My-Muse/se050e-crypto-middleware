/* Minimal feature definitions for the transport subset, not a full SSS build. */
#ifndef SSWL_SE050_FTR_H
#define SSWL_SE050_FTR_H
#define SSS_HAVE_APPLET_SE05X_IOT 1
/* SE050 profile; do not select the SE051 7.2 buffer/feature profile. */
#define SSS_HAVE_SE05X_VER_GTE_07_02 0
#define SSS_HAVE_HOSTCRYPTO_NONE 1
#endif
