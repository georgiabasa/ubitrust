#!/bin/bash

# Configuration
BUILD_DIR="./../../build"
LOG_DIR="./gramine_logs"
MAKEFILE="gramine_makefile"
gramine-sgx-gen-private-key


# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Clear any previous log files
rm -f "$LOG_DIR"/*
rm -f ubitrust_test.manifest
rm -f ubitrust_test.manifest.sgx
rm -f ubitrust_test.sig

# Check if the build directory exists
if [[ ! -d "$BUILD_DIR" ]]; then
    echo "Build directory $BUILD_DIR does not exist."
    exit 1
fi

# Iterate over each file in the build directory
for binary in "$BUILD_DIR"/*; do
    if [[ -x "$binary" && ! -d "$binary" ]]; then
        # Get the binary name for logging
        binary_name=$(basename "$binary")
        log_file="$LOG_DIR/${binary_name}_gramine.log"

        echo "Processing binary: $binary"

        # Run makefile target with ENTRYPOINT set to the binary
        make -f "$MAKEFILE" ENTRYPOINT=$(realpath "$binary") all >> "$log_file" 2>&1
        gramine-sgx ubitrust_test >> "$log_file" 2>&1

        # Check for success
        if [[ $? -eq 0 ]]; then
            echo "Successfully tested $binary. Logs saved in $log_file."
        else
            echo "Error testing $binary. Check logs in $log_file for details."
        fi
    else
        echo "Skipping non-executable file: $binary"
    fi
done

echo "ALL TRUSTED APPS TESTED. Logs are saved in $LOG_DIR."
