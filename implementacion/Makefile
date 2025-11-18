# Makefile for GFRX+COFB Implementation
# Supports multiple targets including test, benchmark, and library

CC = cc
CFLAGS = -Wall -Wextra -O2 -std=c99 -I./include
DEBUG_FLAGS = -g -O0 -fsanitize=address -fsanitize=undefined
PROFILE_FLAGS = -pg -O2
LDFLAGS = -lssl -lcrypto

# Detect OpenSSL location (macOS Homebrew support)
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # Check for Homebrew OpenSSL (Apple Silicon)
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo "")
    ifneq ($(OPENSSL_PREFIX),)
        CFLAGS += -I$(OPENSSL_PREFIX)/include
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib
    endif
endif

# Directories
SRC_DIR = src
INC_DIR = include
TEST_DIR = test
BUILD_DIR = build
BIN_DIR = bin

# Source files
SRCS = $(SRC_DIR)/gfrx.c $(SRC_DIR)/cofb.c $(SRC_DIR)/utils.c
OBJS = $(BUILD_DIR)/gfrx.o $(BUILD_DIR)/cofb.o $(BUILD_DIR)/utils.o
COMP_SRCS = $(SRC_DIR)/ascon.c $(SRC_DIR)/aes_gcm.c $(SRC_DIR)/gift.c $(SRC_DIR)/gift_cofb.c
COMP_OBJS = $(BUILD_DIR)/ascon.o $(BUILD_DIR)/aes_gcm.o $(BUILD_DIR)/gift.o $(BUILD_DIR)/gift_cofb.o
TEST_SRCS = $(TEST_DIR)/test_gfrx_cofb.c

# Output files
LIB_STATIC = $(BUILD_DIR)/libgfrx_cofb.a
TEST_BIN = $(BIN_DIR)/test_gfrx_cofb
DEBUG_BIN = $(BIN_DIR)/test_gfrx_cofb_debug
PROFILE_BIN = $(BIN_DIR)/test_gfrx_cofb_profile
EJEMPLO_BIN = $(BIN_DIR)/ejemplo
TOOL_BIN = $(BIN_DIR)/gfrx-tool
BENCHMARK_BIN = $(BIN_DIR)/benchmark
COMPARISON_BIN = $(BIN_DIR)/comparison_benchmark

# Default target
all: dirs $(LIB_STATIC) $(TEST_BIN) $(EJEMPLO_BIN) $(TOOL_BIN) $(BENCHMARK_BIN) $(COMPARISON_BIN)

# Create necessary directories
dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

# Static library
$(LIB_STATIC): $(OBJS)
	@echo "Creating static library..."
	ar rcs $@ $^
	@echo "Library created: $@"

# Object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Test executable
$(TEST_BIN): $(TEST_SRCS) $(OBJS)
	@echo "Building test executable..."
	$(CC) $(CFLAGS) $^ -o $@
	@echo "Test binary created: $@"

# Ejemplo executable
$(EJEMPLO_BIN): ejemplo.c $(OBJS)
	@echo "Building ejemplo..."
	$(CC) $(CFLAGS) $^ -o $@
	@echo "Ejemplo created: $@"

# CLI tool
$(TOOL_BIN): gfrx-tool.c $(OBJS)
	@echo "Building gfrx-tool..."
	$(CC) $(CFLAGS) $^ -o $@
	@echo "Tool created: $@"

# Benchmark executable
$(BENCHMARK_BIN): benchmark.c $(OBJS)
	@echo "Building benchmark..."
	$(CC) $(CFLAGS) $^ -o $@
	@echo "Benchmark created: $@"

# Comparison benchmark executable (requires OpenSSL)
$(COMPARISON_BIN): comparison_benchmark.c $(OBJS) $(COMP_OBJS)
	@echo "Building comparison benchmark..."
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "Comparison benchmark created: $@"

# Debug build
debug: dirs
	@echo "Building debug version..."
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(SRCS) $(TEST_SRCS) -o $(DEBUG_BIN)
	@echo "Debug binary created: $(DEBUG_BIN)"

# Profile build
profile: dirs
	@echo "Building profiling version..."
	$(CC) $(CFLAGS) $(PROFILE_FLAGS) $(SRCS) $(TEST_SRCS) -o $(PROFILE_BIN)
	@echo "Profile binary created: $(PROFILE_BIN)"

# Run tests
test: $(TEST_BIN)
	@echo "Running tests..."
	@echo ""
	@$(TEST_BIN)

# Run with valgrind for memory checking
memcheck: debug
	@echo "Running memory check with Valgrind..."
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes $(DEBUG_BIN)

# Run profiling
gprof: profile
	@echo "Running profiling..."
	$(PROFILE_BIN)
	gprof $(PROFILE_BIN) gmon.out > analysis.txt
	@echo "Profile analysis saved to analysis.txt"

# Assembly output for optimization analysis
asm: dirs
	@echo "Generating assembly output..."
	$(CC) $(CFLAGS) -S $(SRC_DIR)/gfrx.c -o $(BUILD_DIR)/gfrx.s
	$(CC) $(CFLAGS) -S $(SRC_DIR)/cofb.c -o $(BUILD_DIR)/cofb.s
	@echo "Assembly files generated in $(BUILD_DIR)/"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR) gmon.out analysis.txt

# Install library (optional)
PREFIX ?= /usr/local
install: $(LIB_STATIC)
	@echo "Installing library..."
	@mkdir -p $(PREFIX)/lib $(PREFIX)/include
	@cp $(LIB_STATIC) $(PREFIX)/lib/
	@cp $(INC_DIR)/gfrx_cofb.h $(PREFIX)/include/
	@echo "Installation complete"

# Uninstall
uninstall:
	@echo "Uninstalling library..."
	@rm -f $(PREFIX)/lib/libgfrx_cofb.a
	@rm -f $(PREFIX)/include/gfrx_cofb.h
	@echo "Uninstallation complete"

# Help
help:
	@echo "GFRX+COFB Makefile targets:"
	@echo "  make          - Build library and all executables"
	@echo "  make test     - Run test suite"
	@echo "  make debug    - Build with debug symbols and sanitizers"
	@echo "  make profile  - Build with profiling support"
	@echo "  make memcheck - Run Valgrind memory check"
	@echo "  make gprof    - Run profiling analysis"
	@echo "  make asm      - Generate assembly output"
	@echo "  make clean    - Remove all build artifacts"
	@echo "  make install  - Install library system-wide"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "Executables:"
	@echo "  ./bin/test_gfrx_cofb        - Run test suite (1,656 tests)"
	@echo "  ./bin/ejemplo               - Interactive demo"
	@echo "  ./bin/gfrx-tool             - CLI tool for file encryption"
	@echo "  ./bin/benchmark             - Performance benchmarks (GFRX+COFB)"
	@echo "  ./bin/comparison_benchmark  - AEAD comparison (GFRX+COFB vs ASCON vs AES-GCM)"

.PHONY: all dirs test debug profile memcheck gprof asm clean install uninstall help
