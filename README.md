# **BDAP E2E**

BDAP End-to-End (E2E) library is a portable and standalone library for elliptic-curve integrated encryption system for a multiple-user setting. The core of the library is written in C language (conforming to C99 standard) with a C++ wrapper (conforming to C++ 11 standard).

The components of BDAP E2E are given below:
* Ed25519/Curve25519

    The library accepts Ed25519 public and private keys, and they are converted to Curve25519 for internal operation, e.g. ephemeral key-exchange.

* 256-bit SHAKE Xof

    It is used for deriving AES symmetric keys, nonce and initialization-vectors.

* 256-bit AES-CTR

    It is used to encrypt the random ephemeral secret using key and initialization-vector pair derived from Curve25519 ephemeral key-exchange.

* 256-bit AES-GCM with 128-bit tag

    This encryption scheme is used to encrypt the actual message payload using the random ephemeral secret.

BDAP E2E library has no dependencies and it has been tested on the following platforms:
* 32-bit x86 Linux (Ubuntu 18.04),
* 64-bit x86-64 Linux (Ubuntu 18.04),
* 32-bit ARM Linux (Debian 9.4),
* 64-bit AARCH64 Linux (Debian 9.7),
* 64-bit OS X High-Sierra and Mojave,
* 32-bit Windows 10, and
* 64-bit Windows 10.

## **How to Build**

The instructions on how to build BDAP E2E library for various platforms are described below.

### **Linux and OS X**

In order to build the library, `make`, `gcc` and `g++` are required. Furthermore, the unit/component test of the library requires OpenSSL library version v1.0.2 or greater.

To build the library and the tests, adjust the variables `OPENSSL_PATH`, `OPENSSL_INC` and `OPENSSL_LIB` in `Makefile` accordingly, and execute the following command:
```bash
cd $BDAP_SOURCE
make
```
The above command shall produce BDAP E2E library as a static library in `lib/libbdap.a` and two test executables, namely:
* `bin/tests` is the component tests that requires OpenSSL library, and
* `bin/bdap_test` contains positive and negative tests as per BDAP E2E specification.

### **Windows**

In Windows environment, BDAP E2E library requires Visual C++ compiler. OpenSSL library (either static or dynamic library) is also required for unit/component testing. Open `Makefile.windows`, and adjust the variables `OPENSSL_PATH`, `OPENSSL_INC` and `OPENSSL_LIB` accordingly and build the library and the associated tests using Microsoft NMake as follows.
```
cd $BDAP_SOURCE
nmake -f Makefile.windows
```
The above command shall produce BDAP E2E library as a static library in `lib\bdap.lib` and two test
executables, namely:
* `bin\tests.exe` is the component tests that requires OpenSSL library, and
* `bin\bdap_test.exe` contains positive and negative tests as per BDAP E2E specification.
