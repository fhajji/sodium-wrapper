// sodiumcrypter.h -- symmetric encryption/decryption with MAC class

#ifndef _SODIUMCRYPTER_H_
#define _SODIUMCRYPTER_H_

#include "sodiumalloc.h"

#include <vector>
#include <string>

class SodiumCrypter
{
 public:
  using data_t = std::vector<unsigned char>;
  using key_t  = std::vector<unsigned char, SodiumAlloc<unsigned char>>;
  
  data_t encrypt(const data_t &plaintext,
		 const key_t  &key,
		 const data_t &nonce);

  data_t decrypt(const data_t &cyphertext,
		 const key_t  &key,
		 const data_t &nonce);

  std::string tohex(const data_t &cyphertext);
};

#endif // _SODIUMCRYPTER_H_
