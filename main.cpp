// main.cpp -- test libsodium library
//
// c++ -std=c++11 -Wall -I/usr/local/include -L/usr/local/lib -o sodiumtester main.cpp -lsodium

#include "sodium.h"

#include <cstdlib>

int main()
{
  if (sodium_init() == -1)
    return EXIT_FAILURE;
  
  return EXIT_SUCCESS;
}
