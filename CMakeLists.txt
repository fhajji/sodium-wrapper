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
#   $ cmake -DBUILD_SYSTEM="FreeBSD-clang++" -DCMAKE_CXX_COMPILER="clang++" ..
#   $ make                               (OR make -k) (OR make [-k] VERBOSE=1)
#   $ ./sodiumtester
#   $ tests/test_{<YOURTEST>}
#   $ cd ..
#   $ rm -rf build
#
# BUILD_SYSTEM can be one of
#    FreeBSD-clang++, FreeBSD-g++, FreeBSD-g++6
#    Linux-clang++, Linux-g++-libc++, Linux-g++-stdlibc++
#    something else
#
# CMAKE_CXX_COMPILER can be one of
#    clang++ or g++ or g++6
# and must match BUILD_SYSTEM

cmake_minimum_required ( VERSION 3.1 )

project ( sodiumwrapper )

# When compiling on Windows, don't forget to invoke cmake with these -D variables,
# or to set them in CMakeSettings.json when using Visual Studio 2017's cmake
# integration:
#   CMAKE_TOOLCHAIN_FILE <ROOTPATH_OF_VCPKG>\\scripts\\buildsystems\\vcpkg.cmake
#   CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE
# See also:
#   https://github.com/Microsoft/vcpkg
#   https://blog.kitware.com/create-dlls-on-windows-without-declspec-using-new-cmake-export-all-feature/
#   https://stackoverflow.com/questions/33062728/cmake-link-shared-library-on-windows

# only clang++ for now; g++ not supported yet. (must come before project line)
# IF (NOT DEFINED CMAKE_CXX_COMPILER)
#   set ( CMAKE_CXX_COMPILER "clang++" )
# ENDIF (NOT DEFINED CMAKE_CXX_COMPILER)

# only clang for now; gcc not supported yet. (must come before project line)
# But C compiler not used yet...
# IF (NOT DEFINED CMAKE_C_COMPILER)
#   set ( CMAKE_C_COMPILER "clang" )
# ENDIF (NOT DEFINED CMAKE_C_COMPILER)

# code is explicitely for C++11 and later
set ( CMAKE_CXX_STANDARD 11 )
set ( CMAKE_CXX_STANDARD_REQUIRED ON )
set ( CMAKE_CXX_EXTENSIONS OFF )

# enable_cxx_compiler_flag_if_supported("-Wall")
# enable_cxx_compiler_flag_if_supported("-Wextra")
# enable_cxx_compiler_flag_if_supported("-pedantic")

# enable linker -v flag to show how it is invoked
# set ( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -v" )

### must check CMAKE_SYSTEM_NAME _after_ project()
# message ( "CMAKE_SYSTEM_NAME == ${CMAKE_SYSTEM_NAME}" )

# This is better than extending CMAKE_CXX_FLAGS which doesn't work:
# message ("BUILD_SYSTEM == ${BUILD_SYSTEM}")

# if ( BUILD_SYSTEM STREQUAL "FreeBSD-clang++" )
#   # clang++ and libc++ on FreeBSD
#   # Status: OK
#   add_compile_options ( -Wall -stdlib=libc++ )
# elseif ( BUILD_SYSTEM STREQUAL "FreeBSD-g++" )
#   # g++ and libc++ on FreeBSD
#   # Status: OK
#   # See also: http://libcxx.llvm.org/docs/UsingLibcxx.html
#   add_compile_options ( -Wall -nostdinc++ -I/usr/include/c++/v1 )
#   set ( CMAKE_EXE_LINKER_FLAGS "-nodefaultlibs -lc++ -lm -lc -lgcc_s -lgcc" )
# elseif ( BUILD_SYSTEM STREQUAL "FreeBSD-g++6" )
#   # g++6 and libc++ on FreeBSD
#   # Status: OK
#   # See also: http://libcxx.llvm.org/docs/UsingLibcxx.html
#   add_compile_options ( -Wall -nostdinc++ -I/usr/include/c++/v1 )
#   set ( CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath=/usr/local/lib/gcc6 -nodefaultlibs -lc++ -lm -lc -lgcc_s -lgcc" )
# elseif ( BUILD_SYSTEM STREQUAL "Linux-clang++" )
#   # clang++ and libc++ on Linux
#   # Status: OK
#   # See also: http://stackoverflow.com/questions/37096062/get-a-basic-c-program-to-compile-using-clang-on-ubuntu-16/38385967#38385967
#   #   + Need to modify /usr/include/c++/v1/string as explained
#   #     at the line number reported by the error message
#   #     (see also patches/libc++-string-linux.patch)
#   #     (see patches/README)
#   #   + Need to ln -s /usr/include/libcxxabi/__cxxabi_config.h /usr/include/c++/v1/__cxxabi_config.h
#   add_compile_options ( -Wall -stdlib=libc++ -I/usr/include/c++/v1 )
#   set ( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++ -lc++abi" )
# elseif ( BUILD_SYSTEM STREQUAL "Linux-g++-libc++" )
#   # g++ and libc++ on Linux
#   # Status: BROKEN
#   # See also: http://libcxx.llvm.org/docs/UsingLibcxx.html
#   add_compile_options ( -Wall -nostdinc++ -I/usr/include/c++/v1 )
#   set ( CMAKE_EXE_LINKER_FLAGS "-nodefaultlibs -stdlib=libc++ -lm -lc -lc++abi -lgcc_s -lgcc" )
# elseif ( BUILD_SYSTEM STREQUAL "Linux-g++-stdlibc++" )
#   # g++ and stdlibc++ on Linux
#   # Status: OK
#   add_compile_options ( -Wall )
# else ()
#   # Any other combination of C++ compiler and platform
#   # most likely g++ and libstdc++ on Unix != (FreeBSD || Linux)
#   add_compile_options ( -Wall )
# endif ()

# --------------- Find dependencies --------------------------------------
set (CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR})
find_package(sodium 1.0.12 REQUIRED)
find_package(Boost REQUIRED COMPONENTS unit_test_framework)

if (sodium_FOUND)
    set (LOCAL_INCLUDE_DIR ${LOCAL_INCLUDE_DIR} ${sodium_INCLUDE_DIR})
	# Findsodium.cmake auto-adds this:
	# add_library (sodium SHARED IMPORTED)
endif()

if (Boost_FOUND)
	set (LOCAL_INCLUDE_DIR ${LOCAL_INCLUDE_DIR} ${Boost_INCLUDE_DIRS})
endif()

# Install libsodium-1.0.12+ in --prefix /usr/local...
# We would like pkg-config --{cflags|libs} libsodium without -I or -L...
# set ( LOCAL_INCLUDE_DIR "/usr/local/include" )
# set ( LOCAL_LIB_DIR "/usr/local/lib" )

# --------------- Build library libwrapsodium.so -------------------------

# Find source files of libwrapsodium.so:
file (GLOB SOURCES src/*.cpp)

# Include header files
include_directories ( ${CMAKE_CURRENT_SOURCE_DIR}/include
		      ${LOCAL_INCLUDE_DIR} )

# Create shared library
add_library (wrapsodium SHARED ${SOURCES})
# add_library (wrapsodium_interface INTERFACE)
target_link_libraries(wrapsodium sodium)

# Install library (XXX: not tested)
# install (TARGETS wrapsodium DESTINATION lib/wrapsodium)

# --------------- Build sodiumtester ------------------------------------

file (GLOB SOURCES_TESTER srctest/*.cpp)

# find_library ( SODIUM_LIB sodium ${MY_LIB_DIR} )

add_executable (sodiumtester ${SOURCES_TESTER})
target_link_libraries ( sodiumtester wrapsodium sodium )

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
# find_package (Boost REQUIRED COMPONENTS unit_test_framework)
# if (Boost_FOUND)
#     include_directories (${Boost_INCLUDE_DIRS})
# endif()

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
			       sodium)

        # I like to move testing binaries into a tests/ subdirectory
        set_target_properties (${testName} PROPERTIES 
            RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_BINARY_DIR}/tests)

        # Finally add it to test execution - 
        # Notice the WORKING_DIRECTORY and COMMAND
        add_test (NAME ${testName} 
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/testBin 
                  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/testBin/${testName} )
endforeach(testSrc)

