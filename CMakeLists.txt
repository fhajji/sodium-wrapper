# CMakeLists.txt -- Make CMake file for project SodiumTester.
#
# ISC License
#
# Copyright (c) 2017 Farid Hajji <farid@hajji.name>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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

project ( sodiumwrapper )

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

