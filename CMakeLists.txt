cmake_minimum_required(VERSION 3.20)
project(EmailDetector VERSION 1.0)

# 1. Set C++ Standard (-std=c++23)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 2. Find Threading Library (-pthread)
find_package(Threads REQUIRED)

# 3. Create the Executable
add_executable(EmailDetector EmailDetector.cpp)

# 4. Link Libraries
# Links the threading library found in step 2
target_link_libraries(EmailDetector PRIVATE Threads::Threads)

# 5. Add Include Directories
# This tells CMake to look inside the "include" folder for header files.
# This allows you to use: #include "ankerl_unordered_dense.h"
target_include_directories(EmailDetector PRIVATE ${CMAKE_SOURCE_DIR}/include)

# 6. Apply Your Optimization Flags
if(MSVC)
    target_compile_options(EmailDetector PRIVATE
        /O2          # Maximize Speed (MSVC equivalent of -O3)
        /Ob2         # Aggressive Inlining
        /Oi          # Intrinsic functions
        /Ot          # Favor fast code
        /arch:AVX2   # Use /arch:AVX512 only if you are 100% sure your CPU has it
        /GL          # Whole Program Optimization (Compile-step LTO)
        /DNDEBUG     # Disable debug assertions
    )
    target_link_options(EmailDetector PRIVATE 
        /LTCG        # Link Time Code Generation (Link-step LTO)
    )
else()
    target_compile_options(EmailDetector PRIVATE
        -O3             # High optimization
        -march=native   # Optimize for your specific CPU architecture
        -flto=auto      # Link Time Optimization
        -DNDEBUG        # Disable debug assertions
    )
    target_link_options(EmailDetector PRIVATE -flto=auto -O3)
endif()
