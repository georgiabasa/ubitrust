# UBIlib Build and Testing Instructions

## Variables

### Toolchain
- **`CROSS_COMPILE`**: Optional variable for cross-compilation. If set, it prefixes the compiler and archiver commands.
- **`CC`**: The C compiler to use. Defaults to `gcc`, or `$(CROSS_COMPILE)gcc` if `CROSS_COMPILE` is set.
- **`AR`**: The archiver to use. Defaults to `ar`, or `$(CROSS_COMPILE)ar` if `CROSS_COMPILE` is set.

### Compiler Flags

#### Common Flags (`CFLAGS_COMMON`)
These flags are included in all build modes:
- `-I$(INCLUDE_DIR)`: Include directory for project headers.
- `-I$(MBEDTLS_DIR)/include`: Include directory for mbedTLS headers.
- Warning and standard enforcement flags:
  - `-Wall`: Enable most warnings.
  - `-Wextra`: Enable extra warnings.
  - `-Werror`: Treat warnings as errors.
  - `-Wno-null-dereference`, `-Wno-missing-profile`, `-Wno-maybe-uninitialized`: Suppress specific warnings.
- `-std=c11`: Enforce the C11 standard.

#### Debugging Flags (`DEBUG_FLAGS`)
Used for debugging builds:
- `-g`: Generate debug information for use with debuggers like GDB.
- `-O0`: Disable optimizations for easier debugging.
- `-DDEBUG`: Define the `DEBUG` macro.

#### Optimization Flags (`OPTIMIZE_FLAGS`)
Used for optimized builds:
- Optimization:
  - `-O3`, `-Ofast`: Aggressive optimizations.
  - `-funroll-loops`, `-finline-functions`: Loop unrolling and function inlining.
  - `-flto`: Link-time optimization for improved performance.
- Loop optimizations:
  - `-fgraphite-identity`, `-floop-nest-optimize`: Use Graphite framework for loop optimizations.
- Miscellaneous:
  - `-fomit-frame-pointer`: Exclude the frame pointer to reduce overhead.
  - `-ffunction-sections`, `-fdata-sections`: Place each function and data item in its own section for better dead-code elimination.
  - `-fprofile-generate`, `-fprofile-use`: Enable profile-guided optimizations.

### Setting `CFLAGS`
The `CFLAGS` variable is determined by the `MODE` setting:
- **`MODE=debug`**: Includes `CFLAGS_COMMON` and `DEBUG_FLAGS`.
- **`MODE=optimize`**: Includes `CFLAGS_COMMON` and `OPTIMIZE_FLAGS`.

---

## Directories
- **`SRC_DIR`**: Directory containing source files (`src`).
- **`INCLUDE_DIR`**: Directory containing header files (`include`).
- **`BUILD_DIR`**: Directory for compiled output files (`build`).
- **`TEST_DIR`**: Directory for test files (`test`).

---

## Build Instructions

### For Debugging
To build the project with debugging options:
```bash
make MODE=debug
```

# TESTING
To build and run the test binaries:
```bash
make MODE=debug BUILD_TEST=1
./debug 
```
To check the logs go to the valgrind_logs directory 