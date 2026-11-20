# SE050E Crypto Middleware

[![CI](https://github.com/Elsa-is-My-Muse/se050e-crypto-middleware/actions/workflows/ci.yml/badge.svg)](https://github.com/Elsa-is-My-Muse/se050e-crypto-middleware/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![C99](https://img.shields.io/badge/C-99-blue.svg)](CMakeLists.txt)

**面向 NXP SE050E 安全芯片的可移植 C 密码学中间件。**

中文 | [English](README.en.md)

提供安全芯片会话、密钥对象管理、随机数、ECDSA 和可选 ECDH，并为现有
ISO 15118-2 / ISO 15118-20 工程提供 PSA / Mbed TLS 接入层。
核心库独立于 TLS；使用者需要接入自己的 MCU、操作系统和 I2C 实现。
本项目是独立维护的源代码库，不包含完整 ISO 15118 协议栈。

## 功能与支持范围

| 模块 | 内容 | 使用条件 |
| --- | --- | --- |
| 芯片核心 | 会话串行化、APDU、随机数、密钥对象生命周期 | 实现 OS 与板级接口 |
| ECC | P-256 / P-384 / P-521、ECDSA、DER 与原始签名转换、ECDH | 芯片 applet 支持对应功能 |
| PSA / TLS | opaque key、身份签名、CSR、可选验签与临时密钥交换 | 匹配的 Mbed TLS 4.0.0 / TF-PSA-Crypto 源树 |
| 参考移植 | AT32F435 + RT-Thread，I2C 默认 100 kHz | 外部 BSP / HAL / RTOS |
| 主机验证 | 会话、APDU、对象清理、轮询、CMake 链接、C++ API | Python、GCC/G++ 或 Clang、CMake |

TLS 栈内补丁绑定于 [指定基线与文件哈希](integration/mbedtls/manifest.json)，
不承诺兼容任意 Mbed TLS 版本。硬件熵源、证书链、RTC、身份注入和握手策略由宿主负责。

## 快速开始

### 1. 获取源码并运行主机验证

```sh
git clone https://github.com/Elsa-is-My-Muse/se050e-crypto-middleware.git
cd se050e-crypto-middleware
python -m pip install -r requirements-dev.txt
python tools/check_project.py
python tools/format.py --check
python tests/run.py
python tests/run_portable.py
python -m unittest discover -s tests -p "test_tools.py"
```

需要 Python 3.9+、CMake 3.19+、GCC/G++ 或 Clang/Clang++，以及 Ninja 或 Make。
可通过 `CC` / `CXX` 选择编译器；Windows 推荐 MinGW-w64 与 Ninja。
以上验证只使用 mock，不连接硬件、不注入密钥、不烧录固件。

### 2. 接入自己的平台

参考 [OS 移植模板](port/template/se050_port_custom.h) 实现 OS 接口，按
[板级接口约定](include/se050_port_i2c.h) 实现 I2C、延时与日志，并在父工程中选择平台：

```cmake
set(SE050_OS_PORT_HEADER "my_se050_port.h" CACHE STRING "")
set(SE050_PORT_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}/platform" CACHE STRING "")
set(SE050_PLATFORM_SOURCES
    "${PROJECT_SOURCE_DIR}/platform/my_se050_os.c;${PROJECT_SOURCE_DIR}/platform/my_se050_i2c.c;${PROJECT_SOURCE_DIR}/platform/my_se050_time_log.c"
    CACHE STRING "")
add_subdirectory(third_party/se050e-crypto-middleware)
target_link_libraries(my_application PRIVATE SE050::Core)
```

仅使用芯片 API 时包含 `se050_core.h`。需要 TLS 时阅读 [TLS 栈补丁说明](integration/mbedtls/README.md)，
再启用 `SE050_WITH_MBEDTLS`，配置匹配的头文件、编译宏与 TLS 库，链接 `SE050::MbedTLS`。
未选择完整 OS / 板级实现时，CMake 会明确报错。

### 3. 导出到其他工程

```sh
python tools/export_portable.py ../se050e-source
# 同时携带主机测试：
python tools/export_portable.py ../se050e-source-with-tests --with-tests
```

目标必须在当前源树之外且不存在或为空。导出只包含白名单源码与文档，逐文件校验 SHA256，
并生成 `PACKAGE_MANIFEST.json`；不携带私钥、测试 PKI、固件、Flash 备份或构建产物。

## 目录

```text
include/              公共核心与 PSA / TLS API
src/                  平台无关会话、APDU 与 ECC
middleware/mbedtls/    PSA / Mbed TLS 适配
port/                 AT32F435 / RT-Thread 参考实现和移植模板
nxp/                  带来源说明与许可证的 NXP 传输子集
integration/mbedtls/   版本绑定的栈内补丁与哈希
manifest.json         源文件、包含路径与编译宏清单
tests/                主机 mock、可移植构建和工具验证
tools/                格式、完整性检查和源码导出
.github/              CI、Issue / PR 模板和依赖更新配置
```

## 验证与维护

- [TLS 栈补丁说明](integration/mbedtls/README.md)：版本基线与宿主接入责任。
- [贡献指南](CONTRIBUTING.md) · [安全报告](SECURITY.md)。

主机测试和编译通过不代表实机握手通过。新板仍需验证电气时序、并发、错误恢复、
证书策略和真实双端握手；当前 plain-T1 传输不包含 SCP03 主机认证安全通道。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。NXP 厂商文件保留原始版权与许可证，
详见 [来源说明](nxp/UPSTREAM.md) 和 [NOTICE](NOTICE)。Mbed TLS / TF-PSA-Crypto
由宿主提供，并保留各自许可证。本项目与 NXP 无官方隶属关系。
