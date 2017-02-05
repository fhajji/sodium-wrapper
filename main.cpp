// main.cpp -- Test libsodium library with custom C++ wrappers
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
//
// Use CMake w/ CMakeLists.txt like this:
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
    std::string ciphertext;
    
    std::cout << "Enter plaintext: ";
    std::getline(std::cin, plaintext);
    
    ciphertext = st.test0(plaintext);
    std::cout << "crypto_secretbox_easy(): " << ciphertext << std::endl;

    bool res1 = st.test1(plaintext);
    std::cout << "crypto_auth()/crypto_auth_verify(): " << res1 << std::endl;

    std::string pwhash_pw1, pwhash_pw2;
    std::cout << "crypto_pwhash() test -- password #1: ";
    std::getline(std::cin, pwhash_pw1);
    std::cout << "crypto_pwhash() test -- password #2: ";
    std::getline(std::cin, pwhash_pw2);
        
    bool res2 = st.test2(plaintext, pwhash_pw1, pwhash_pw2);
    std::cout << "crypto_pwhash(): " << res2 << std::endl;

    std::string res3 = st.test3();
    std::cout << "nonce test: " << res3 << std::endl;
  }
  catch (std::runtime_error e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  
  return EXIT_SUCCESS;
}
