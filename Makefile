# ─── OS Detection ────────────────────────────────────────────────
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    EXT := .exe
    RM_FILE := rm -f
	RM_DIR := rm -rf
    RUN_PREFIX := ./
else
    DETECTED_OS := $(shell uname -s)
    EXT := 
    RM_FILE := rm -f
	RM_DIR := rm -rf
    RUN_PREFIX := ./
endif

# ─── Variables ───────────────────────────────────────────────────
CXX      := g++
STD      := -std=c++23
INCLUDE  := -Iinclude

# Base flags (Threading + Standard + Include paths)
BASE_FLAGS := -pthread $(STD) $(INCLUDE)

TARGET   := EmailDetector$(EXT)
SRC      := EmailDetector.cpp

# ─── Paths (Must be defined AFTER TARGET) ────────────────────────
DEBUG_PATH := build/debug/$(TARGET)
RELEASE_PATH := build/release/$(TARGET)

# ─── Build Targets ──────────────────────────────────────────────
.PHONY: all build build_release clean run run_cmake run_release_cmake

all: build

# Debug Build
# -g:       Generates debug information (symbols) for GDB/LLDB.
# -O0:      Disables all optimization. Crucial for stepping through code line-by-line.
# -Wall:    Enables almost all standard compiler warnings.
# -Wextra:  Enables some extra warning flags that -Wall misses.
build:
	@printf "\033[1;32m🔧 Building C++ project (Debug) on $(DETECTED_OS)...\033[0m\n"
	$(CXX) -g -O0 -Wall -Wextra $(BASE_FLAGS) $(SRC) -o $(TARGET)

# Release Build
# -O3:            Highest safe optimization level.
# -march=native:  Optimizes for your specific CPU (makes it non-portable but fast).
# -flto=auto:     Link Time Optimization.
# -DNDEBUG:       Disables assertions.
build_release:
	@printf "\033[1;32m🔧 Building C++ project (Release) on $(DETECTED_OS)...\033[0m\n"
	$(CXX) -O3 -march=native -flto=auto -DNDEBUG $(BASE_FLAGS) $(SRC) -o $(TARGET)

# ─── CMake Targets ──────────────────────────────────────────────
build_cmake:
	@printf "\033[1;32m🔧 Building CMake project (Debug)...\033[0m\n"
	cmake -S . -B build/debug -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug
	cmake --build build/debug

build_release_cmake:
	@printf "\033[1;32m🔧 Building CMake project (Release)...\033[0m\n"
	cmake -S . -B build/release -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
	cmake --build build/release --config Release

# ─── Application Run ────────────────────────────────────────────
run:
	@printf "\033[1;32m🚀 Running application (Makefile build)...\033[0m\n"
	$(RUN_PREFIX)$(TARGET)

run_cmake:
	@printf "\033[1;32m🚀 Running application (CMake Debug build)...\033[0m\n"
	$(RUN_PREFIX)$(DEBUG_PATH)

run_release_cmake:
	@printf "\033[1;32m🚀 Running application (CMake Release build)...\033[0m\n"
	$(RUN_PREFIX)$(RELEASE_PATH)

clean:
	@printf "\033[1;31m🗑️ Cleaning up...\033[0m\n"
	-$(RM_FILE) $(TARGET)
	-$(RM_DIR) "build"