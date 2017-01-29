// sodiumtester.cpp -- implementation of class SodiumTester

#include "sodiumtester.h"

#include <stdexcept>
#include <string>
#include <algorithm>

#include <sodium.h>

SodiumTester::SodiumTester()
{
  if (sodium_init() == -1)
    throw std::runtime_error {"sodium_init() failed"};
}

std::string
SodiumTester::test0(const std::string &plaintext)
{
  // copy the bytes of the plaintext into a buffer of unsigned char bytes
  unsigned char *plainbuf = new unsigned char[plaintext.size()];
  std::copy (plaintext.cbegin(), plaintext.cend(), plainbuf);
    
  // get a random nonce and a random key
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof nonce);
  unsigned char key[crypto_secretbox_KEYBYTES];
  randombytes_buf(key, sizeof key);

  // make space for MAC and encrypted message
  unsigned char *cypherbuf = new unsigned char[crypto_secretbox_MACBYTES +
					       plaintext.size()];

  // let's encrypt now!
  crypto_secretbox_easy (cypherbuf,
			 plainbuf, plaintext.size(),
			 nonce,
			 key);

  // put [cypherbuf, cypherbuf+plaintext.size()] into cyphertext
  std::string cyphertext {cypherbuf,
      cypherbuf + crypto_secretbox_MACBYTES + plaintext.size()+1};

  // proof of correctness: let's try to decrypt!
  unsigned char *decryptbuf = new unsigned char[plaintext.size()];
  if (crypto_secretbox_open_easy (decryptbuf, cypherbuf,
				  crypto_secretbox_MACBYTES + plaintext.size(),
				  nonce, key) != 0)
    throw std::runtime_error {"test0() message forged (sodium test)"};

  if (! std::equal (plainbuf, plainbuf+plaintext.size()+1,
		    decryptbuf))
    throw std::runtime_error {"test0() message forged (own test)"};
  
  delete[] plainbuf;
  delete[] cypherbuf;
  delete[] decryptbuf;
  
  return cyphertext;
}
