// sodiumtester.h -- main class SodiumTester

#ifndef _SODIUMTESTER_H_
#define _SODIUMTESTER_H_

class SodiumTester
{  
 public:
  SodiumTester();
  SodiumTester(const SodiumTester &) = delete; // NoCopy
  SodiumTester & operator= (const SodiumTester &) = delete; // NoCopy
};

#endif // _SODIUMTESTER_H_
