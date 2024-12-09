#!/bin/bash

# Directory containing binaries
BUILD_DIR="./build"
LOG_DIR="./valgrind_logs"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Clear any previous log files
rm -f "$LOG_DIR"/*

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
        log_file="$LOG_DIR/${binary_name}_valgrind.log"

        echo "Running Valgrind on $binary..."

        # Run Valgrind with specified options, save output to log file
        valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
                 --verbose "$binary" &> "$log_file"

        # Check if any errors were reported
        if grep -q "ERROR SUMMARY: [^0]" "$log_file"; then
            echo "Valgrind reported errors for $binary (see $log_file)"
        else
            echo "No errors detected for $binary."
        fi
    else
        echo "Skipping non-executable file: $binary"
    fi
done

echo "Valgrind checks completed. Logs are saved in $LOG_DIR."
