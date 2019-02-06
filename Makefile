CC             = gcc
CXX            = g++
UNAME_S       := $(shell uname -s)
ifeq ($(UNAME_S), Linux)
 MAKELIB       = ar cr $@ $^ && ranlib $@
else
 MAKELIB       = libtool -static -o $@ $^
endif

# Compiler Flags

C_FLAGS        = -c -ansi -std=c99 -Iinclude
CXX_FLAGS      = -c -ansi -std=c++11 -Iinclude
LANG_FLAGS     = -fsigned-char
OPT_FLAGS      = -O3 -fomit-frame-pointer -fwrapv
WARN_FLAGS     = -Wall -Wextra -Wpedantic
LDFLAGS        = 

# Path to OpenSSL static library and development headers
ifeq ($(UNAME_S), Linux)
 OPENSSL_PATH  =
 OPENSSL_INC   =
 OPENSSL_LIB   = -lcrypto
else
 OPENSSL_PATH  = /usr/local/opt/openssl
 OPENSSL_INC   = -I$(OPENSSL_PATH)/include
 OPENSSL_LIB   = -L$(OPENSSL_PATH)/lib -lcrypto 
endif

C_BUILD_FLAGS  = $(C_FLAGS) $(OPT_FLAGS) $(LANG_FLAGS) $(WARN_FLAGS)
CXX_BUILD_FLAGS= $(CXX_FLAGS) $(OPT_FLAGS) $(LANG_FLAGS) $(WARN_FLAGS)

# The primary target
all: create_dirs libs tests

# Executable targets
TESTS          = bin/tests
BDAP_TEST      = bin/encryption_test
BDAP_LIB       = lib/lib_bdap_encryption.a

tests: $(TESTS) $(BDAP_TEST)
libs: $(BDAP_LIB)

# Misc targets

run: create_dirs $(TESTS) $(BDAP_TEST)
	@echo Executing BDAP component tests ... 
	@$(TESTS)
	@echo
	@echo Executing BDAP positive and negative tests
	@$(BDAP_TEST)

# create output directories
create_dirs:
	@[ -d obj ] || mkdir obj
	@[ -d lib ] || mkdir lib
	@[ -d bin ] || mkdir bin

# delete output directories
clean:
	@rm -rf obj lib bin

# Object Files
LIBOBJS = obj/aes256.obj obj/aes256ctr.obj obj/aes256gcm.obj \
	obj/encryption.obj obj/encryption_core.obj obj/encryption_error.obj obj/curve25519.obj \
	obj/ed25519.obj obj/fe.obj obj/ge.obj obj/os_rand.obj obj/rand.obj \
	obj/sha512.obj obj/shake256.obj obj/shake256_rand.obj obj/utils.obj

BDAP_TESTOBJS = obj/encryption_test.obj

TESTOBJS = obj/aes256_test.obj obj/aes256ctr_test.obj obj/aes256gcm_test.obj \
	obj/encryption_core_test.obj obj/curve25519_test.obj obj/convert_test.obj \
	obj/shake256_test.obj obj/test.obj

# Executable targets

$(BDAP_TEST): $(BDAP_LIB) $(BDAP_TESTOBJS)
	$(CXX) -o $@ $(LDFLAGS) $(BDAP_TESTOBJS) $(BDAP_LIB)

$(TESTS): $(BDAP_LIB) $(TESTOBJS)
	$(CC) -o $@ $(LDFLAGS) $(TESTOBJS) $(BDAP_LIB) $(OPENSSL_LIB)

# Library targets

$(BDAP_LIB): $(LIBOBJS)
	$(MAKELIB)

# Build Commands

obj/aes256.obj: src/aes256.c include/aes256.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/aes256.c -o $@

obj/aes256ctr.obj: src/aes256ctr.c include/aes256ctr.h include/aes256.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/aes256ctr.c -o $@

obj/aes256gcm.obj: src/aes256gcm.c include/aes256gcm.h include/aes256.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/aes256gcm.c -o $@

obj/encryption.obj: src/encryption.cpp include/encryption.h include/encryption_core.h
	$(CXX) $(CXX_BUILD_FLAGS) src/encryption.cpp -o $@

obj/encryption_core.obj: src/encryption_core.c include/aes256ctr.h include/aes256gcm.h include/encryption_core.h include/encryption_error.h include/curve25519.h include/ed25519.h include/rand.h include/shake256.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/encryption_core.c -o $@

obj/encryption_error.obj: src/encryption_error.c include/encryption_error.h
	$(CC) $(C_BUILD_FLAGS) src/encryption_error.c -o $@

obj/curve25519.obj: src/curve25519.c include/curve25519.h include/fe.h include/rand.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/curve25519.c -o $@

obj/ed25519.obj: src/ed25519.c include/ed25519.h include/curve25519.h include/ge.h include/rand.h include/sha512.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/ed25519.c -o $@

obj/fe.obj: src/fe.c include/fe.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/fe.c -o $@

obj/ge.obj: src/ge.c include/ge.h include/fe_25_5.h
	$(CC) $(C_BUILD_FLAGS) src/ge.c -o $@

obj/os_rand.obj: src/os_rand.c include/os_rand.h
	$(CC) $(C_BUILD_FLAGS) src/os_rand.c -o $@

obj/rand.obj: src/rand.c include/rand.h include/os_rand.h include/shake256_rand.h
	$(CC) $(C_BUILD_FLAGS) src/rand.c -o $@

obj/sha512.obj: src/sha512.c include/sha512.h
	$(CC) $(C_BUILD_FLAGS) src/sha512.c -o $@

obj/shake256.obj: src/shake256.c include/shake256.h
	$(CC) $(C_BUILD_FLAGS) src/shake256.c -o $@

obj/shake256_rand.obj: src/shake256_rand.c include/shake256_rand.h include/shake256.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/shake256_rand.c -o $@

obj/utils.obj: src/utils.c include/utils.h
	$(CC) $(C_BUILD_FLAGS) src/utils.c -o $@

# BDAP test source code
obj/encryption_test.obj: test/encryption_test.cpp include/aes256ctr.h include/aes256gcm.h include/encryption.h include/encryption_error.h include/curve25519.h include/ed25519.h include/rand.h include/shake256.h include/utils.h
	$(CXX) $(CXX_BUILD_FLAGS) test/encryption_test.cpp -o $@

# Additional test source code
obj/aes256_test.obj: test/aes256_test.c include/aes256.h include/rand.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) $(OPENSSL_INC) test/aes256_test.c -o $@

obj/aes256ctr_test.obj: test/aes256ctr_test.c include/aes256ctr.h include/rand.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) $(OPENSSL_INC) test/aes256ctr_test.c -o $@

obj/aes256gcm_test.obj: test/aes256gcm_test.c include/aes256gcm.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) $(OPENSSL_INC) test/aes256gcm_test.c -o $@

obj/encryption_core_test.obj: test/encryption_core_test.c include/encryption_core.h include/curve25519.h include/ed25519.h include/rand.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) $(OPENSSL_INC) test/encryption_core_test.c -o $@

obj/curve25519_test.obj: test/curve25519_test.c include/curve25519.h include/rand.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) $(OPENSSL_INC) test/curve25519_test.c -o $@
	
obj/convert_test.obj: test/convert_test.c include/curve25519.h include/ed25519.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) $(OPENSSL_INC) test/convert_test.c -o $@

obj/shake256_test.obj: test/shake256_test.c include/shake256_rand.h include/utils.h
	$(CC) $(C_BUILD_FLAGS) $(OPENSSL_INC) test/shake256_test.c -o $@

obj/test.obj: test/test.c include/shake256_rand.h
	$(CC) $(C_BUILD_FLAGS) $(OPENSSL_INC) test/test.c -o $@
