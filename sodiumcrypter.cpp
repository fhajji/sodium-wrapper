// sodiumcrypter.cpp -- implements SodiumCrypter class

#include "sodiumcrypter.h"

#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

SodiumCrypter::data_t
SodiumCrypter::encrypt (const data_t &plaintext,
		        const key_t  &key,
		        const data_t &nonce)
{
  std::size_t plaintext_size  = plaintext.size();
  std::size_t cyphertext_size = crypto_secretbox_MACBYTES + plaintext_size;
  std::size_t key_size        = crypto_secretbox_KEYBYTES;
  std::size_t nonce_size      = crypto_secretbox_NONCEBYTES;

  // some sanity checks
  if (key.size() != key_size)
    throw std::runtime_error {"SodiumCrypter::encrypt() key has wrong size"};
  if (nonce.size() != nonce_size)
    throw std::runtime_error {"SodiumCrypter::encrypt() nonce has wrong size"};

  // make space for MAC and encrypted message
  data_t cyphertext(cyphertext_size);
  
  // let's encrypt now!
  crypto_secretbox_easy (cyphertext.data(),
			 plaintext.data(), plaintext.size(),
			 nonce.data(),
			 key.data());

  // return the encrypted bytes
  return cyphertext;
}

SodiumCrypter::data_t
SodiumCrypter::decrypt (const data_t &cyphertext,
		        const key_t  &key,
		        const data_t &nonce)
{
  std::size_t cyphertext_size = cyphertext.size();
  std::size_t key_size        = key.size();
  std::size_t nonce_size      = nonce.size();
  std::size_t plaintext_size  = cyphertext_size - crypto_secretbox_MACBYTES;
  
  // some sanity checks
  if (key_size != crypto_secretbox_KEYBYTES)
    throw std::runtime_error {"SodiumCrypter::decrypt() key has wrong size"};
  if (nonce_size != crypto_secretbox_NONCEBYTES)
    throw std::runtime_error {"SodiumCrypter::decrypt() nonce has wrong size"};
  if (plaintext_size <= 0)
    throw std::runtime_error {"SodiumCrypter::decrypt() plaintext negative size"};

  // make space for decrypted buffer
  data_t decryptedtext(plaintext_size);

  // and now decrypt!
  if (crypto_secretbox_open_easy (decryptedtext.data(),
				  cyphertext.data(), cyphertext_size,
				  nonce.data(),
				  key.data()) != 0)
    throw std::runtime_error {"SodiumCrypter::decrypt() message forged (sodium test)"};

  return decryptedtext;
}

std::string
SodiumCrypter::tohex (const data_t &cyphertext)
{
  std::size_t cyphertext_size = cyphertext.size();
  std::size_t hex_size        = cyphertext_size * 2 + 1;

  std::vector<char> hexbuf(hex_size);
  
  // convert [cypherbuf, cypherbuf + cyphertext_size] into hex:
  if (! sodium_bin2hex(hexbuf.data(), hex_size,
		       cyphertext.data(), cyphertext_size))
    throw std::runtime_error {"SodiumCrypter::tohex() overflowed"};

  // XXX: is copying hexbuf into a string really necessary here?
  
  // return hex output as a string:
  std::string outhex {hexbuf.data(), hexbuf.data() + hex_size};
  return outhex;
}
