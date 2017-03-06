// main.cpp -- Test libsodium library with custom C++ wrappers
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.
//
// Use CMake w/ CMakeLists.txt like this:
//   $ mkdir build
//   $ cd build
//   $ cmake ..
//   $ make
//   $ ./sodiumtester
//   $ cd ..
//   $ rm -rf build

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
    
    // ----- test #0 -----
    ciphertext = st.test0(plaintext);
    std::cout << "crypto_secretbox_easy(): " << ciphertext << std::endl;
    
    // ----- test #1 -----
    bool res1 = st.test1(plaintext);
    std::cout << "crypto_auth()/crypto_auth_verify(): " << res1 << std::endl;

    // ----- test #2 -----
    std::string pwhash_pw1, pwhash_pw2;
    std::cout << "crypto_pwhash() test -- password #1: ";
    std::getline(std::cin, pwhash_pw1);
    std::cout << "crypto_pwhash() test -- password #2: ";
    std::getline(std::cin, pwhash_pw2);

    bool res2 = st.test2(plaintext, pwhash_pw1, pwhash_pw2);
    std::cout << "crypto_pwhash(): " << res2 << std::endl;

    // ----- test #3 -----
    std::string res3 = st.test3();
    std::cout << "nonce test: " << res3 << std::endl;

    // ----- test #4 -----
    std::string header;
    std::cout << "Enter header: ";
    std::getline(std::cin, header);
    std::string res4 = st.test4(plaintext, header);
    std::cout << "AEAD test: " << res4 << std::endl;

    // ----- test #5 -----
    std::string filename;
    std::cout << "Enter filename: ";
    std::cin  >> filename;
    bool res5 = st.test5(filename);
    std::cout << "stream cryptor test: " << res5 << std::endl;

    // ----- test #6 -----
    bool res6 = st.test6(filename);
    std::cout << "file cryptor test: " << res6 << std::endl;
    
  }
  catch (std::runtime_error e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  
  return EXIT_SUCCESS;
}
