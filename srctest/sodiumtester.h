// sodiumtester.h -- Test Harness SodiumTester.
//
// ISC License
//
// Copyright (C) 2018 Farid Hajji <farid@hajji.name>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#pragma once

#include "common.h"
#include <string>

class SodiumTester
{
  public:
    using bytes = sodium::bytes; // shorthand notation...

    SodiumTester();
    SodiumTester(const SodiumTester&) = delete;            // NoCopy
    SodiumTester& operator=(const SodiumTester&) = delete; // NoCopy

    // Here go the test functions for the C++ libsodium wrappers:
    std::string test0(const std::string& plaintext);
    bool test1(const std::string& plaintext);
    bool test2(const std::string& plaintext,
               const std::string& pw1,
               const std::string& pw2);
    std::string test3();
    std::string test4(const std::string& plaintext, const std::string& header);
    bool test5(const std::string& filename);
    bool test6(const std::string& filename);
};