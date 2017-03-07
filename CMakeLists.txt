# CMakeLists.txt -- Make CMake file for project SodiumTester.
#
# Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Usage:
#   $ mkdir build
#   $ cd build
#   $ cmake ..
#   $ make
#   $ ./sodiumtester
#   $ tests/test_{<YOURTEST>}
#   $ cd ..
#   $ rm -rf build

cmake_minimum_required ( VERSION 2.8 )

project ( sodiumtester )

set ( CMAKE_CXX_STANDARD 11 )
set ( CMAKE_CXX_STANDARD_REQUIRED ON )
set ( CMAKE_CXX_CFLAGS "${CMAKE_CXX_CFLAGS} -std=c++11 -stdlib=libc++ -Wall" )

# We would like pkg-config --{cflags|libs} libsodium without -I or -L...
set ( LOCAL_INCLUDE_DIR "/usr/local/include" )
set ( LOCAL_LIB_DIR "/usr/local/lib" )

# --------------- Build library libwrapsodium.so -------------------------

# Find source files of libwrapsodium.so:
file (GLOB SOURCES src/*.cpp)

# Include header files
include_directories ( ${CMAKE_CURRENT_SOURCE_DIR}/include
		      ${LOCAL_INCLUDE_DIR} )

# Create shared library
add_library (wrapsodium SHARED ${SOURCES})

# Install library (XXX: not tested)
install (TARGETS wrapsodium DESTINATION lib/wrapsodium)

# --------------- Build sodiumtester ------------------------------------

file (GLOB SOURCES_TESTER srctest/*.cpp)

find_library ( SODIUM_LIB sodium ${MY_LIB_DIR} )
find_library ( WRAPSODIUM_LIB wrapsodium )

add_executable (sodiumtester ${SOURCES_TESTER})
target_link_libraries ( sodiumtester wrapsodium ${SODIUM_LIB} )

# --------------- Build test suite --------------------------------------
#
# This is (modified) from:
#    http://neyasystems.com/an-engineers-guide-to-unit-testing-cmake-and-boost-unit-tests/
#
# See also http://stackoverflow.com/questions/16857517/cmake-how-to-add-boost-test-cases-with-relative-directories
#
# See cmake-variables(7) man page for list of all CMAKE_* variables

# Setup CMake to run tests
enable_testing()

# Prep ourselves for compiling boost
find_package (Boost COMPONENTS unit_test_framework REQUIRED)
include_directories (${Boost_INCLUDE_DIRS})

# I like to keep test files in a separate source directory called tests
file (GLOB TEST_SRCS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} tests/*.cpp)

# Run through each source
foreach (testSrc ${TEST_SRCS})
        # Extract the filename without an extension (NAME_WE)
        get_filename_component (testName ${testSrc} NAME_WE)

        # Add compile target
        add_executable (${testName} ${testSrc})

        # link to Boost libraries AND your targets and dependencies
        target_link_libraries (${testName} ${Boost_LIBRARIES}
			       wrapsodium
			       ${SODIUM_LIB})

        # I like to move testing binaries into a tests/ subdirectory
        set_target_properties (${testName} PROPERTIES 
            RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR}/tests)

        # Finally add it to test execution - 
        # Notice the WORKING_DIRECTORY and COMMAND
        add_test (NAME ${testName} 
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/testBin 
                  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/testBin/${testName} )
endforeach(testSrc)

