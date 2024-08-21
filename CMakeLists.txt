# CMakeLists.txt -- Make CMake file for project sodium-wrapper.
#
# ISC License
#
# Copyright (c) 2018 Farid Hajji <farid@hajji.name>
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

# When compiling on Windows, don't forget to invoke cmake with these -D variables,
# or to set them in CMakeSettings.json when using Visual Studio 2017's cmake
# integration:
#   CMAKE_TOOLCHAIN_FILE <ROOTPATH_OF_VCPKG>\\scripts\\buildsystems\\vcpkg.cmake
#   CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE
# See also:
#   https://github.com/Microsoft/vcpkg
#   https://blog.kitware.com/create-dlls-on-windows-without-declspec-using-new-cmake-export-all-feature/
#   https://stackoverflow.com/questions/33062728/cmake-link-shared-library-on-windows
# 
# When compiling on Unix, choose between a Debug or Release Build
# by setting CMAKE_BUILD_TYPE to Debug or Release, e.g.:
# 
#    cmake -DCMAKE_BUILD_TYPE=Release ..

cmake_minimum_required ( VERSION 3.11 )

project ( sodium-wrapper )

set ( CMAKE_CXX_STANDARD 17 )
set ( CMAKE_CXX_STANDARD_REQUIRED ON )
set ( CMAKE_CXX_EXTENSIONS OFF )

set(BOOST_LIB_DIR "C:/boost/" CACHE STRING "It's a path to boost lib")
set(SODIUM_LIB_DIR "C:/Sodium/" CACHE STRING "It's a path to sodium lib")

# --------------- Find dependencies --------------------------------------
set (CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR})
find_package(sodium 1.0.16 REQUIRED PATH ${SODIUM_LIB_DIR} NO_DEFAULT_PATH)
find_package(Boost REQUIRED COMPONENTS unit_test_framework PATH ${BOOST_LIB_DIR} NO_DEFAULT_PATH)

if (sodium_FOUND)
    set (LOCAL_INCLUDE_DIR ${LOCAL_INCLUDE_DIR} ${sodium_INCLUDE_DIR})
	# Findsodium.cmake auto-adds this:
	# add_library (sodium SHARED IMPORTED)
endif()

if (Boost_FOUND)
	set (LOCAL_INCLUDE_DIR ${LOCAL_INCLUDE_DIR} ${Boost_INCLUDE_DIRS})
endif()

# --------------- Crank up warnings to the max --------------------------------
if (MSVC)
    # add_compile_options (/Wall)
    add_compile_options (/W2) # /Wall is too much for now.
else()
    add_compile_options (-Wall -Wextra -Wpedantic)
endif()

# --------------- Special OS/Compile cases -------------------------------
if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        add_compile_options (-stdlib=libc++)
    elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        message("FreeBSD:g++ ${CMAKE_CXX_COMPILER_VERSION}")
        # if multiple g++ versions are installed, pick the right libraries
        # XXX this is brittle: update for g++7, g++8, ...
        if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER "8.0.0")
            message("Supported GCC detected")
            add_compile_options (-nostdinc++ -I/usr/include/c++/v1)
	    set (CMAKE_EXE_LINKER_FLAGS "-nodefaultlibs -lc++ -lm -lc -lgcc_s -lgcc")
            set (CMAKE_EXE_LINKER_FLAGS "-Wl,-rpath=/usr/local/lib/gcc8 ${CMAKE_EXE_LINKER_FLAGS}")
        endif()
    else()
        message("FreeBSD:unknown")
    endif()
endif()

# --------------- General settings --------------------------------------

# Include header files
include_directories ( ${CMAKE_CURRENT_SOURCE_DIR}/include
                      ${LOCAL_INCLUDE_DIR} )

# --------------- Build sodiumtester ------------------------------------

file (GLOB SOURCES_TESTER srctest/*.cpp)

# find_library ( SODIUM_LIB sodium ${MY_LIB_DIR} )

add_executable (sodiumtester ${SOURCES_TESTER})
target_link_libraries ( sodiumtester sodium )

# --------------- Build test suite --------------------------------------

# Setup CMake to run tests
enable_testing()

# Keep test files in a separate source directory called tests
file (GLOB TEST_SRCS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} tests/*.cpp)

# Run through each source
foreach (testSrc ${TEST_SRCS})
        # Extract the filename without an extension (NAME_WE)
        get_filename_component (testName ${testSrc} NAME_WE)

        # Add compile target
        add_executable (${testName} ${testSrc})

        # link to Boost libraries AND your targets and dependencies
        target_link_libraries (${testName} ${Boost_LIBRARIES}
			       sodium)

        # I like to move testing binaries into a tests/ subdirectory
        set_target_properties (${testName} PROPERTIES 
            RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR}/tests)

        # Finally add it to test execution - 
        # Notice the WORKING_DIRECTORY and COMMAND
        add_test (NAME ${testName} 
                  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests
                  COMMAND ${CMAKE_BINARY_DIR}/tests/${testName} )
endforeach(testSrc)
