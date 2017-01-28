// main.cpp -- test libsodium library
//
// c++ -std=c++11 -Wall -I/usr/local/include -L/usr/local/lib -o sodiumtester main.cpp sodiumtester.cpp -lsodium

#include "sodiumtester.h"

#include <cstdlib>
#include <exception>
#include <iostream>

int main()
{
  try {
    SodiumTester st {};
  }
  catch (std::runtime_error e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  
  std::cout << "libsodium library successfully initialized" << std::endl;
  
  return EXIT_SUCCESS;
}
