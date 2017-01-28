// sodiumtester.cpp -- implementation of class SodiumTester

#include "sodiumtester.h"

#include "sodium.h"
#include <stdexcept>

SodiumTester::SodiumTester()
{
  if (sodium_init() == -1)
    throw std::runtime_error {"sodium_init() failed"} ;
}
