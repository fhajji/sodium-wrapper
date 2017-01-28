# CMakeLists.txt -- Make CMake file for project SodiumTester.
#
# Usage: $ cmake .
#        $ make

cmake_minimum_required ( VERSION 3.7 )

project ( sodiumtester )

set ( CMAKE_CXX_STANDARD 11 )
set ( CMAKE_CXX_STANDARD_REQUIRED ON )
set ( CMAKE_CXX_CFLAGS "${CMAKE_CXX_CFLAGS} -std=c++11 -Wall" )

# We would like pkg-config --{cflags|libs} libsodium without -I or -L...
set ( MY_INCLUDE_DIR "/usr/local/include" )
set ( MY_LIB_DIR "/usr/local/lib" )

include_directories ( ${MY_INCLUDE_DIR} )

set ( SOURCE_FILES main.cpp )

find_library ( SODIUM_LIB sodium ${MY_LIB_DIR} )

add_executable (sodiumtester ${SOURCE_FILES})
target_link_libraries ( sodiumtester "${SODIUM_LIB}" )

