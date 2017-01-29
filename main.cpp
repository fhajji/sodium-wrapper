// main.cpp -- test libsodium library
//
// c++ -std=c++11 -Wall -I/usr/local/include -L/usr/local/lib -o sodiumtester main.cpp sodiumtester.cpp -lsodium
//
// or, better yet, use CMake w/ CMakeLists.txt like this:
//   $ cmake .
//   $ make

#include "sodiumtester.h"

#include <cstdlib>
#include <stdexcept>
#include <string>
#include <iostream>

int main()
{
  try {
    SodiumTester st {};

    std::string plaintext;
    std::string cyphertext;
    
    std::cout << "Enter plaintext: ";
    std::getline(std::cin, plaintext);
    
    cyphertext = st.test0(plaintext);
    std::cout << "crypto_secretbox_easy(): " << cyphertext << std::endl;
  }
  catch (std::runtime_error e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  
  return EXIT_SUCCESS;
}
