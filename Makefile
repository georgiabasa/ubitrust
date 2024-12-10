CROSS_COMPILE ?= 
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

CFLAGS_COMMON = -I$(INCLUDE_DIR) -I$(MBEDTLS_DIR)/include -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
                -Wstrict-prototypes -Wmissing-prototypes -Wformat=2 -Wpointer-arith \
                -Wcast-align -std=c11 -Wno-maybe-uninitialized


# Debug mode flags
DEBUG_FLAGS = -g -O0 -DDEBUG

# Optimization mode flags
OPTIMIZE_FLAGS = -O3 -Ofast -funroll-loops -finline-functions -flto -march=native \
                 -mtune=native -fgraphite-identity -floop-nest-optimize \
                 -fomit-frame-pointer -ffunction-sections -fdata-sections 

# Set CFLAGS based on MODE
ifeq ($(MODE),debug)
    CFLAGS = $(CFLAGS_COMMON) $(DEBUG_FLAGS)
else ifeq ($(MODE),optimize)
    CFLAGS = $(CFLAGS_COMMON) $(OPTIMIZE_FLAGS)
endif


# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
TEST_DIR = test

# Library output
STATIC_LIB = $(BUILD_DIR)/libUBI.a

# Source and object files
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_FILES))

# Test source files and binaries
TEST_FILES = $(wildcard $(TEST_DIR)/*.c)
TEST_BINS = $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/%, $(TEST_FILES))

# Installation directories
INSTALL_LIB_DIR = /usr/local/lib
INSTALL_INCLUDE_DIR = /usr/local/include

# Define the major mbed version we want
MBEDTLS_MAJOR_VERSION := 3.6

# Use GitHub API to find the latest mbed 3.6.x version
LATEST_VERSION_CMD := curl -s https://api.github.com/repos/Mbed-TLS/mbedtls/tags | grep -oP "\"name\": \"v$(MBEDTLS_MAJOR_VERSION)\.\d+\"" | head -1 | grep -oP "$(MBEDTLS_MAJOR_VERSION)\.\d+"
MBEDTLS_VERSION := $(shell $(LATEST_VERSION_CMD))

# Define mbed build paths
MBEDTLS_DIR := $(BUILD_DIR)/mbedtls-$(MBEDTLS_VERSION)
MBEDTLS_NAME := mbedtls-$(MBEDTLS_VERSION)
MBEDTLS_TAR := $(MBEDTLS_NAME).tar.bz2
MBEDTLS_URL := https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$(MBEDTLS_VERSION)/$(MBEDTLS_NAME).tar.bz2
MBEDTLS_SHA_URL := https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$(MBEDTLS_VERSION)/$(MBEDTLS_NAME)-sha256sum.txt

# Check if any existing mbedtls 3.6.x directory exists
EXISTING_DIR := $(shell find . -maxdepth 2 -type d -name "mbedtls-$(MBEDTLS_MAJOR_VERSION).*")

# External libraries to link
LDFLAGS = -L$(MBEDTLS_DIR)/library -lmbedtls -lmbedcrypto

.PHONY: all clean

# Targets
all: print-art $(BUILD_DIR) $(MBEDTLS_DIR)/Makefile lib


	
$(MBEDTLS_DIR)/Makefile: $(MBEDTLS_DIR)
	@$(MAKE) -C $(MBEDTLS_DIR) CROSS_COMPILE=$(CROSS_COMPILE) CC=$(CROSS_COMPILE)gcc AR=$(CROSS_COMPILE)ar > /dev/null

# Download the latest mbedtls version if it doesn't already exist
$(MBEDTLS_DIR):
	@{ \
		if [ -n "$(EXISTING_DIR)" ] && [ "$(EXISTING_DIR)" != "./$(MBEDTLS_DIR)" ]; then \
			echo "Found an outdated mbedtls directory: $(EXISTING_DIR). Removing it..."; \
			rm -rf $(EXISTING_DIR); \
		fi; \
		echo "Downloading mbedtls $(MBEDTLS_VERSION)..."; \
		wget -O "$(MBEDTLS_TAR)" "$(MBEDTLS_URL)"; \
		wget -O "$(MBEDTLS_NAME)-sha256sum.txt" "$(MBEDTLS_SHA_URL)"; \
		echo "Verifying checksum..."; \
		CHECKSUM_EXPECTED=$$(cat $(MBEDTLS_NAME)-sha256sum.txt); \
		CHECKSUM_ACTUAL=$$(sha256sum "$(MBEDTLS_TAR)" | awk '{print $$1}'); \
		if [ "$$CHECKSUM_EXPECTED" != "$$CHECKSUM_ACTUAL" ]; then \
			echo "Error: Checksum verification failed."; \
			rm "$(MBEDTLS_TAR)" "$(MBEDTLS_NAME)-sha256sum.txt"; \
			exit 1; \
		else \
			echo "Checksum verified successfully."; \
		fi; \
		echo "Extracting mbedtls..."; \
		tar -xjvf "$(MBEDTLS_TAR)" -C $(BUILD_DIR); \
		rm "$(MBEDTLS_TAR)" "$(MBEDTLS_NAME)-sha256sum.txt"; \
	} > /dev/null 2>&1


$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)


lib: $(OBJ_FILES)
	$(AR) rcs $(STATIC_LIB) $(OBJ_FILES)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%: $(TEST_DIR)/%.c $(STATIC_LIB)
	$(CC) $(CFLAGS) $< -o $@ -L$(BUILD_DIR) -lUBI $(LDFLAGS)

test: $(TEST_BINS)

print-art:
	@echo ""
	@echo "UUUUUUUU     UUUUUUUUBBBBBBBBBBBBBBBBB   IIIIIIIIIITTTTTTTTTTTTTTTTTTTTTTTRRRRRRRRRRRRRRRRR   UUUUUUUU     UUUUUUUU   SSSSSSSSSSSSSSS TTTTTTTTTTTTTTTTTTTTTTT"
	@echo "U::::::U     U::::::UB::::::::::::::::B  I::::::::IT:::::::::::::::::::::TR::::::::::::::::R  U::::::U     U::::::U SS:::::::::::::::ST:::::::::::::::::::::T"
	@echo "U::::::U     U::::::UB::::::BBBBBB:::::B I::::::::IT:::::::::::::::::::::TR::::::RRRRRR:::::R U::::::U     U::::::US:::::SSSSSS::::::ST:::::::::::::::::::::T"
	@echo "UU:::::U     U:::::UUBB:::::B     B:::::BII::::::IIT:::::TT:::::::TT:::::TRR:::::R     R:::::RUU:::::U     U:::::UUS:::::S     SSSSSSST:::::TT:::::::TT:::::T"
	@echo " U:::::U     U:::::U   B::::B     B:::::B  I::::I  TTTTTT  T:::::T  TTTTTT  R::::R     R:::::R U:::::U     U:::::U S:::::S            TTTTTT  T:::::T  TTTTTT"
	@echo " U:::::D     D:::::U   B::::B     B:::::B  I::::I          T:::::T          R::::R     R:::::R U:::::D     D:::::U S:::::S                    T:::::T        "
	@echo " U:::::D     D:::::U   B::::BBBBBB:::::B   I::::I          T:::::T          R::::RRRRRR:::::R  U:::::D     D:::::U  S::::SSSS                 T:::::T        "
	@echo " U:::::D     D:::::U   B:::::::::::::BB    I::::I          T:::::T          R:::::::::::::RR   U:::::D     D:::::U   SS::::::SSSSS            T:::::T        "
	@echo " U:::::D     D:::::U   B::::BBBBBB:::::B   I::::I          T:::::T          R::::RRRRRR:::::R  U:::::D     D:::::U     SSS::::::::SS          T:::::T        "
	@echo " U:::::D     D:::::U   B::::B     B:::::B  I::::I          T:::::T          R::::R     R:::::R U:::::D     D:::::U        SSSSSS::::S         T:::::T        "
	@echo " U:::::D     D:::::U   B::::B     B:::::B  I::::I          T:::::T          R::::R     R:::::R U:::::D     D:::::U             S:::::S        T:::::T        "
	@echo " U::::::U   U::::::U   B::::B     B:::::B  I::::I          T:::::T          R::::R     R:::::R U::::::U   U::::::U             S:::::S        T:::::T        "
	@echo " U:::::::UUU:::::::U BB:::::BBBBBB::::::BII::::::II      TT:::::::TT      RR:::::R     R:::::R U:::::::UUU:::::::U SSSSSSS     S:::::S      TT:::::::TT      "
	@echo "  UU:::::::::::::UU  B:::::::::::::::::B I::::::::I      T:::::::::T      R::::::R     R:::::R  UU:::::::::::::UU  S::::::SSSSSS:::::S      T:::::::::T      "
	@echo "    UU:::::::::UU    B::::::::::::::::B  I::::::::I      T:::::::::T      R::::::R     R:::::R    UU:::::::::UU    S:::::::::::::::SS       T:::::::::T      "
	@echo "      UUUUUUUUU      BBBBBBBBBBBBBBBBB   IIIIIIIIII      TTTTTTTTTTT      RRRRRRRR     RRRRRRR      UUUUUUUUU       SSSSSSSSSSSSSSS         TTTTTTTTTTT      "
	@echo ""

install: lib
	cp $(STATIC_LIB) $(INSTALL_LIB_DIR)/
	mkdir -p $(INSTALL_INCLUDE_DIR)/ubi_common
	mkdir -p $(INSTALL_INCLUDE_DIR)/ubi_crypt
	cp $(INCLUDE_DIR)/ubi_common/* $(INSTALL_INCLUDE_DIR)/ubi_common/
	cp $(INCLUDE_DIR)/ubi_crypt/* $(INSTALL_INCLUDE_DIR)/ubi_crypt/

uninstall:
	rm -f $(INSTALL_LIB_DIR)/$(notdir $(STATIC_LIB))
	rm -rf $(INSTALL_INCLUDE_DIR)

# If the test flag is set, include the test target in all
ifeq ($(BUILD_TEST),1)
all: test
endif

clean:
ifeq ($(CLEAN_MBEDTLS),1)
	@echo "Cleaning mbedtls-related files..."
	rm -rf $(MBEDTLS_DIR) $(MBEDTLS_TAR) $(MBEDTLS_NAME)-sha256sum.txt
else
	@echo "Cleaning general build artifacts..."
	rm -rf $(BUILD_DIR) valgrind_logs
endif

