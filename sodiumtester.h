// sodiumtester.h -- main class SodiumTester

#ifndef _SODIUMTESTER_H_
#define _SODIUMTESTER_H_

#include <string>

class SodiumTester
{  
 public:
  SodiumTester();
  SodiumTester(const SodiumTester &) = delete; // NoCopy
  SodiumTester & operator= (const SodiumTester &) = delete; // NoCopy

  std::string test0(const std::string &plaintext);
};

#endif // _SODIUMTESTER_H_
