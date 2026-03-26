# C-Miner Makefile
# Simple build system using GCC

# ============================================================================
# Configuration
# ============================================================================

# Project name
PROJECT_NAME := cminer

# Directories
OBJ_DIR := obj
BIN_DIR := bin
DEP_DIR := $(OBJ_DIR)/.deps

# Source files
SOURCES := main.c \
           base/tools.c \
           base/hash.c \
           crypto/astrobwt/astrobwt.c \
           crypto/fnv1a/fnv1a.c \
           crypto/salsa/salsa.c \
           crypto/siphash/siphash.c \
           crypto/xxhash/xxhash.c \
           crypto/astrobwt/sais.c

# Object files
OBJECTS := $(SOURCES:%.c=$(OBJ_DIR)/%.o)

# Dependency files
DEPS := $(SOURCES:%.c=$(DEP_DIR)/%.d)

# ============================================================================
# Compiler Configuration
# ============================================================================

CC := gcc
CFLAGS := -D_GNU_SOURCE -O3 -I.
LDFLAGS := -lpthread -lcrypto -lssl -lcjson -lgmp

# Target binary
TARGET := $(BIN_DIR)/$(PROJECT_NAME)

# ============================================================================
# Build Rules
# ============================================================================

.PHONY: all build clean help

# Default target
all: build

# Build the binary
build: $(TARGET)
	@echo "✓ Build complete: $(TARGET)"

# Link the executable
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	@echo "Linking: $@"
	@$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

# Compile source files to object files
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR) $(DEP_DIR)
	@mkdir -p $(dir $@) $(dir $(DEP_DIR)/$*.d)
	@echo "Compiling: $<"
	@$(CC) $(CFLAGS) -MMD -MP -MF $(DEP_DIR)/$*.d -c $< -o $@

# Create directories
$(BIN_DIR) $(OBJ_DIR) $(DEP_DIR):
	@mkdir -p $@

# Include dependency files
-include $(DEPS)

# ============================================================================
# Cleaning
# ============================================================================

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

# ============================================================================
# Help
# ============================================================================

help:
	@echo "C-Miner Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make              Build the project"
	@echo "  make clean        Remove build artifacts"
	@echo "  make help         Show this help message"
