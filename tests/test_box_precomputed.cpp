// test_box_precomputed.cpp -- Test sodium::box_precomputed
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

// To see some timing output, run this test like this:
//   ./test_box_precomputed --log_level=message

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE sodium::box_precomputed Test
#include <boost/test/included/unit_test.hpp>

#include "box.h"
#include "box_precomputed.h"
#include "keypair.h"

#include <string>
#include <sstream>
#include <chrono>
#include <typeinfo>

#include <sodium.h>

using namespace std::chrono;

using sodium::keypair;
using sodium::box;
using sodium::box_precomputed;

using bytes = sodium::bytes;

template <typename BT=bytes>
bool
test_of_correctness(const std::string &plaintext)
{
  keypair<BT> keypair_alice;
  keypair<BT> keypair_bob;
  typename box_precomputed<BT>::nonce_type nonce;

  box_precomputed<BT> sc_alice(keypair_alice.private_key(),
				   keypair_bob.public_key());
  box_precomputed<BT> sc_bob(keypair_bob.private_key(),
				   keypair_alice.public_key());

  BT plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. alice uses the shared key with bob to encrypt and sign
  //    a message:
  
  BT ciphertext_from_alice_to_bob =
    sc_alice.encrypt(plainblob, nonce);

  // 2. bob uses the shared key with alice to decrypt the message
  //    and verify alice's signature:
  
  BT decrypted_by_bob_from_alice =
    sc_bob.decrypt(ciphertext_from_alice_to_bob, nonce);

  // 3. if decryption (MAC or signature) fails, decrypt() would throw,
  // but we manually check anyway.
  
  BOOST_TEST(plainblob == decrypted_by_bob_from_alice);

  // 4. bob echoes the messages back to alice. Remember to increment nonce!

  nonce.increment(); // IMPORTANT! before calling encrypt() again

  BT ciphertext_from_bob_to_alice =
    sc_bob.encrypt(decrypted_by_bob_from_alice, nonce);

  // 5. alice attempts to decrypt again (also with the incremented nonce)
  BT decrypted_by_alice_from_bob =
    sc_alice.decrypt(ciphertext_from_bob_to_alice, nonce);

  // 6. if decryption (MAC or signature) fails, decrypt() would throw,
  // but we manually check anyway. We assume that bob echoed the
  // plaintext without modifying it.

  BOOST_TEST(plainblob == decrypted_by_alice_from_bob);
  
  return plainblob == decrypted_by_alice_from_bob;
}

template <typename BT = bytes>
bool
test_of_correctness_detached(const std::string &plaintext)
{
	keypair<BT> keypair_alice;
	keypair<BT> keypair_bob;
	typename box_precomputed<BT>::nonce_type nonce;

	box_precomputed<BT> sc_alice(keypair_alice.private_key(),
		keypair_bob.public_key());
	box_precomputed<BT> sc_bob(keypair_bob.private_key(),
		keypair_alice.public_key());

	BT plainblob{ plaintext.cbegin(), plaintext.cend() };

	BT mac(box_precomputed<BT>::MACSIZE);

	// 1. alice uses the shared key with bob to encrypt and sign
	//    a message:

	BT ciphertext_from_alice_to_bob =
		sc_alice.encrypt(plainblob, nonce, mac);

	// 2. bob uses the shared key with alice to decrypt the message
	//    and verify alice's signature:

	BT decrypted_by_bob_from_alice =
		sc_bob.decrypt(ciphertext_from_alice_to_bob, nonce, mac);

	// 3. if decryption (MAC or signature) fails, decrypt() would throw,
	// but we manually check anyway.

	BOOST_TEST(plainblob == decrypted_by_bob_from_alice);

	// 4. bob echoes the messages back to alice. Remember to increment nonce!

	nonce.increment(); // IMPORTANT! before calling encrypt() again

	BT ciphertext_from_bob_to_alice =
		sc_bob.encrypt(decrypted_by_bob_from_alice, nonce, mac);

	// 5. alice attempts to decrypt again (also with the incremented nonce)
	BT decrypted_by_alice_from_bob =
		sc_alice.decrypt(ciphertext_from_bob_to_alice, nonce, mac);

	// 6. if decryption (MAC or signature) fails, decrypt() would throw,
	// but we manually check anyway. We assume that bob echoed the
	// plaintext without modifying it.

	BOOST_TEST(plainblob == decrypted_by_alice_from_bob);

	return plainblob == decrypted_by_alice_from_bob;
}

template <typename BT=bytes>
bool
falsify_mac(const std::string &plaintext)
{
  keypair<BT> keypair_alice;
  typename box_precomputed<BT>::nonce_type nonce;
  box_precomputed<BT> sc(keypair_alice);
  
  BT plainblob {plaintext.cbegin(), plaintext.cend()};

  BT ciphertext = sc.encrypt(plainblob, nonce);

  BOOST_TEST(ciphertext.size() >= box_precomputed<BT>::MACSIZE);

  // falsify mac, which starts before the ciphertext proper
  ++ciphertext[0];

  try {
    BT decrypted = sc.decrypt(ciphertext, nonce);
  }
  catch (std::exception & /* e */) {
    // decryption failed as expected: test passed.
    return true;
  }

  // No expection caught: decryption went ahead, eventhough we've
  // modified the mac. Test failed.

  return false;
}

template <typename BT = bytes>
bool
falsify_mac_detached(const std::string &plaintext)
{
	keypair<BT> keypair_alice;
	typename box_precomputed<BT>::nonce_type nonce;
	box_precomputed<BT> sc(keypair_alice);

	BT plainblob{ plaintext.cbegin(), plaintext.cend() };

	BT mac(box_precomputed<BT>::MACSIZE);
	BT ciphertext = sc.encrypt(plainblob, nonce, mac);

	BOOST_TEST(ciphertext.size() == plainblob.size());
	BOOST_TEST(mac.size() == box_precomputed<BT>::MACSIZE);

	// falsify mac, which is conveniently detached
	++mac[0];

	try {
		BT decrypted = sc.decrypt(ciphertext, nonce, mac);
	}
	catch (std::exception & /* e */) {
		// decryption failed as expected: test passed.
		return true;
	}

	// No expection caught: decryption went ahead, eventhough we've
	// modified the mac. Test failed.

	return false;
}

template <typename BT=bytes>
bool
falsify_ciphertext(const std::string &plaintext)
{
  // before even bothering falsifying a ciphertext, check that the
  // corresponding plaintext is not emptry!
  BOOST_CHECK_MESSAGE(! plaintext.empty(),
		      "Nothing to falsify, empty plaintext");
  
  keypair<BT> keypair_alice;
  typename box_precomputed<BT>::nonce_type nonce;
  box_precomputed<BT> sc(keypair_alice);
  
  BT plainblob {plaintext.cbegin(), plaintext.cend()};

  // encrypt to self
  BT ciphertext = sc.encrypt(plainblob, nonce);

  BOOST_TEST(ciphertext.size() > box_precomputed<BT>::MACSIZE);

  // falsify ciphertext, which starts just after MAC
  ++ciphertext[box_precomputed<BT>::MACSIZE];

  try {
    BT decrypted = sc.decrypt(ciphertext, nonce);
  }
  catch (std::exception & /* e */) {
    // Exception caught as expected. Test passed.
    return true;
  }

  // Expection not caught: decryption went ahead, eventhough we've
  // modified the ciphertext. Test failed.

  return false;
}

template <typename BT = bytes>
bool
falsify_ciphertext_detached(const std::string &plaintext)
{
	// before even bothering falsifying a ciphertext, check that the
	// corresponding plaintext is not emptry!
	BOOST_CHECK_MESSAGE(!plaintext.empty(),
		"Nothing to falsify, empty plaintext");

	keypair<BT> keypair_alice;
	typename box_precomputed<BT>::nonce_type nonce;
	box_precomputed<BT> sc(keypair_alice);

	BT plainblob{ plaintext.cbegin(), plaintext.cend() };

	BT mac(box_precomputed<BT>::MACSIZE);

	// encrypt to self
	BT ciphertext = sc.encrypt(plainblob, nonce, mac);

	BOOST_TEST(ciphertext.size() == plainblob.size());
	BOOST_TEST(mac.size() == box_precomputed<BT>::MACSIZE);

	// falsify ciphertext; MAC is not part of it, since detached
	++ciphertext[0];

	try {
		BT decrypted = sc.decrypt(ciphertext, nonce, mac);
	}
	catch (std::exception & /* e */) {
		// Exception caught as expected. Test passed.
		return true;
	}

	// Expection not caught: decryption went ahead, eventhough we've
	// modified the ciphertext. Test failed.

	return false;
}

template <typename BT=bytes>
bool
falsify_sender(const std::string &plaintext)
{
  keypair<BT> keypair_alice; // recipient
  keypair<BT> keypair_bob;   // impersonated sender
  keypair<BT> keypair_oscar; // real sender
  typename box_precomputed<BT>::nonce_type nonce;

  box_precomputed<BT> sc_alice(keypair_alice.private_key(),
							   keypair_bob.public_key());
  box_precomputed<BT> sc_bob  (keypair_bob.private_key(),
				               keypair_alice.public_key());
  box_precomputed<BT> sc_oscar(keypair_oscar.private_key(),
				               keypair_alice.public_key());

  BT plainblob {plaintext.cbegin(), plaintext.cend()};

  // 1. Oscar encrypts a plaintext that looks as if it was written by Bob
  // with Alice's public key, and signs it with his own private key.
  
  BT ciphertext = sc_oscar.encrypt(plainblob, nonce);

  // 2. Oscar prepends forged headers to the ciphertext, making it appear
  // as if the message (= headers + ciphertext) came indeed from Bob,
  // and sends the whole message, i.e. the envelope, to Alice.
  // Not shown here.

  // 3. Alice receives the message. Because of the envelope's headers,
  // she thinks the message came from Bob. Not shown here.
  
  // 4. Alice decrypts the message with her own private key. She
  // tries to verify the signature with Bob's public key. This is
  // the place where decryption MUST fail.

  try {
    BT decrypted = sc_alice.decrypt(ciphertext, nonce);

    // if decryption succeeded, Oscar was successful in impersonating Bob.
    // The test therefore failed!

    return false;
  }
  catch (std::exception & /* e */) {
    // decryption failed; either because ciphertext was modified
    // en route, or, more likely here, because keypair_bob.pubkey()
    // doesn't match keypair_oscar.privkey(). Oscar was not able to
    // impersonate Bob. Test was successful.

    return true;
  }

  // NOTREACHED
  return true;
}

template <typename BT = bytes>
bool
falsify_sender_detached(const std::string &plaintext)
{
	keypair<BT> keypair_alice; // recipient
	keypair<BT> keypair_bob;   // impersonated sender
	keypair<BT> keypair_oscar; // real sender
	typename box_precomputed<BT>::nonce_type nonce;

	box_precomputed<BT> sc_alice(keypair_alice.private_key(),
		keypair_bob.public_key());
	box_precomputed<BT> sc_bob(keypair_bob.private_key(),
		keypair_alice.public_key());
	box_precomputed<BT> sc_oscar(keypair_oscar.private_key(),
		keypair_alice.public_key());

	BT plainblob{ plaintext.cbegin(), plaintext.cend() };

	BT mac(box_precomputed<BT>::MACSIZE);

	// 1. Oscar encrypts a plaintext that looks as if it was written by Bob
	// with Alice's public key, and signs it with his own private key.

	BT ciphertext = sc_oscar.encrypt(plainblob, nonce, mac);

	// 2. Oscar prepends forged headers to the ciphertext, making it appear
	// as if the message (= headers + ciphertext) came indeed from Bob,
	// and sends the whole message, i.e. the envelope, to Alice.
	// Not shown here.

	// 3. Alice receives the message. Because of the envelope's headers,
	// she thinks the message came from Bob. Not shown here.

	// 4. Alice decrypts the message with her own private key. She
	// tries to verify the signature with Bob's public key. This is
	// the place where decryption MUST fail.

	try {
		BT decrypted = sc_alice.decrypt(ciphertext, nonce, mac);

		// if decryption succeeded, Oscar was successful in impersonating Bob.
		// The test therefore failed!

		return false;
	}
	catch (std::exception & /* e */) {
		// decryption failed; either because ciphertext was modified
		// en route, or, more likely here, because keypair_bob.pubkey()
		// doesn't match keypair_oscar.privkey(). Oscar was not able to
		// impersonate Bob. Test was successful.

		return true;
	}

	// NOTREACHED
	return true;
}

template <typename BT=bytes>
bool
destroy_shared_key_then_encrypt(const BT &plaintext)
{
  keypair<BT> keypair_alice {};
  typename box_precomputed<BT>::nonce_type nonce {};
  box_precomputed<BT> sc_alice(keypair_alice);
  
  // 1. alice panics and destroys the shared key:
  sc_alice.destroy_shared_key();

  try {
    BT ciphertext = sc_alice.encrypt(plaintext, nonce);

    // 2. encryption succeeded despite destroyed shared key.
    // test failed.
    return false;
  }
  catch (std::exception & /* e */) {
    // 3. encryption failed as expected because of destroyed shared key.
    // test succeeded.
    return true;
  }

  // NOTREACHED
  return true;
}

template <typename BT = bytes>
bool
destroy_shared_key_then_encrypt_detached(const BT &plaintext)
{
	keypair<BT> keypair_alice{};
	typename box_precomputed<BT>::nonce_type nonce{};
	box_precomputed<BT> sc_alice(keypair_alice);

	BT mac(box_precomputed<BT>::MACSIZE);

	// 1. alice panics and destroys the shared key:
	sc_alice.destroy_shared_key();

	try {
		BT ciphertext = sc_alice.encrypt(plaintext, nonce, mac);

		// 2. encryption succeeded despite destroyed shared key.
		// test failed.
		return false;
	}
	catch (std::exception & /* e */) {
		// 3. encryption failed as expected because of destroyed shared key.
		// test succeeded.
		return true;
	}

	// NOTREACHED
	return true;
}

template <typename BT=bytes>
bool
destroy_shared_key_then_decrypt(const BT &ciphertext,
				const keypair<BT> &keypair,
				const typename box_precomputed<BT>::nonce_type &nonce)
{
  box_precomputed<BT> sc_alice(keypair);
  
  // 1. alice panics and destroys the shared key:
  sc_alice.destroy_shared_key();

  try {
    BT decrypted = sc_alice.decrypt(ciphertext, nonce);

    // 2. decryption succeeded despite destroyed shared key.
    // test failed.
    return false;
  }
  catch (std::exception & /* e */) {
    // 3. decryption failed as expected, probably because of
    // destroyed shared key. test succeeded.
    return true;
  }

  // NOTREACHED
  return true;
}

template <typename BT = bytes>
bool
destroy_shared_key_then_decrypt_detached(const BT &ciphertext,
	const keypair<BT> &keypair,
	const typename box_precomputed<BT>::nonce_type &nonce,
	const BT &mac)
{
	box_precomputed<BT> sc_alice(keypair);

	// 1. alice panics and destroys the shared key:
	sc_alice.destroy_shared_key();

	try {
		BT decrypted = sc_alice.decrypt(ciphertext, nonce, mac);

		// 2. decryption succeeded despite destroyed shared key.
		// test failed.
		return false;
	}
	catch (std::exception & /* e */) {
		// 3. decryption failed as expected, probably because of
		// destroyed shared key. test succeeded.
		return true;
	}

	// NOTREACHED
	return true;
}

template <typename BT=bytes>
void
time_encrypt(const unsigned long nr_of_messages)
{
  keypair<BT>                  keypair_alice   {};
  typename box_precomputed<BT>::nonce_type nonce_multi     {};
  typename box<BT>::nonce_type      nonce_single    {};
  box<BT>                  sc_single_alice {};
  box_precomputed<BT>      sc_multi_alice  (keypair_alice);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BT plainblob {plaintext.cbegin(), plaintext.cend()};
  BT ciphertext_multi (plaintext.size() + box_precomputed<BT>::MACSIZE);
  BT ciphertext_single(plaintext.size() + box<BT>::MACSIZE);

  std::ostringstream os;
 
  using bytes_type = BT;
  os << "Timing encrypt " << typeid(bytes_type).name() << "...\n";

  // 1. time encrypting nr_of_messages with box_precomputed<BT>
  auto t00 = system_clock::now();
  for (unsigned long i=0; i!=nr_of_messages; ++i) {
    ciphertext_multi = sc_multi_alice.encrypt(plainblob,
					      nonce_multi);
    nonce_multi.increment();
  }
  auto t01 = system_clock::now();
  auto tmulti = duration_cast<milliseconds>(t01-t00).count();

  os << "Encrypting " << nr_of_messages << " messages (multi ): "
     << tmulti << " milliseconds." << std::endl;
  
  // 2. time encrypting nr_of_messages with box
  auto t10 = system_clock::now();
  for (unsigned long i=0; i!=nr_of_messages; ++i) {
    ciphertext_single = sc_single_alice.encrypt(plainblob,
						keypair_alice,
						nonce_single);
    nonce_single.increment();
  }
  auto t11 = system_clock::now();
  auto tsingle = duration_cast<milliseconds>(t11-t10).count();

  os << "Encrypting " << nr_of_messages << " messages (single): "
     << tsingle << " milliseconds." << std::endl;

  BOOST_TEST_MESSAGE(os.str());
  
  BOOST_CHECK_MESSAGE(tmulti < tsingle,
		      "sodium::box_precomputed::encrypt() slower than sodium::box::encrypt()");
}

template <typename BT = bytes>
void
time_encrypt_detached(const unsigned long nr_of_messages)
{
	keypair<BT>                  keypair_alice{};
	typename box_precomputed<BT>::nonce_type nonce_multi{};
	typename box<BT>::nonce_type      nonce_single{};
	box<BT>                  sc_single_alice{};
	box_precomputed<BT>      sc_multi_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	BT plainblob{ plaintext.cbegin(), plaintext.cend() };
	BT ciphertext_multi(plaintext.size());
	BT ciphertext_single(plaintext.size() + box<BT>::MACSIZE);

	BT mac_multi(box_precomputed<BT>::MACSIZE);
	BT mac_single(box<BT>::MACSIZE);

	std::ostringstream os;

	using bytes_type = BT;
	os << "Timing encrypt " << typeid(bytes_type).name() << "...\n";

	// 1. time encrypting nr_of_messages with box_precomputed<BT>
	auto t00 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		ciphertext_multi = sc_multi_alice.encrypt(plainblob,
			nonce_multi, mac_multi);
		nonce_multi.increment();
	}
	auto t01 = system_clock::now();
	auto tmulti = duration_cast<milliseconds>(t01 - t00).count();

	os << "Encrypting " << nr_of_messages << " messages (multi ): "
		<< tmulti << " milliseconds." << std::endl;

	// 2. time encrypting nr_of_messages with box
	auto t10 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		ciphertext_single = sc_single_alice.encrypt(plainblob,
			keypair_alice,
			nonce_single,
			mac_single);
		nonce_single.increment();
	}
	auto t11 = system_clock::now();
	auto tsingle = duration_cast<milliseconds>(t11 - t10).count();

	os << "Encrypting(detached) " << nr_of_messages << " messages (single): "
		<< tsingle << " milliseconds." << std::endl;

	BOOST_TEST_MESSAGE(os.str());

	BOOST_CHECK_MESSAGE(tmulti < tsingle,
		"sodium::box_precomputed::encrypt() slower than sodium::box::encrypt()");
}

template <typename BT=bytes>
void
time_decrypt(const unsigned long nr_of_messages)
{
  keypair<BT>                  keypair_alice   {};
  typename box<BT>::nonce_type      nonce_single    {};
  typename box_precomputed<BT>::nonce_type nonce_multi     {};
  box<BT>                  sc_single_alice {};
  box_precomputed<BT>      sc_multi_alice  (keypair_alice);

  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BT plainblob {plaintext.cbegin(), plaintext.cend()};
  BT decrypted_multi (plaintext.size());
  BT decrypted_single(plaintext.size());

  // 0. encrypt once the plaintext without timing
  BT ciphertext_multi  = sc_multi_alice.encrypt(plainblob, nonce_multi);
  BT ciphertext_single = sc_single_alice.encrypt(plainblob,
					      keypair_alice,
					      nonce_single);
  
  std::ostringstream os;

  using bytes_type = BT;
  os << "Timing decrypt " << typeid(bytes_type).name() << "...\n";

  // 1. time decrypting nr_of_messages with box_precomputed
  auto t00 = system_clock::now();
  for (unsigned long i=0; i!=nr_of_messages; ++i) {
    decrypted_multi = sc_multi_alice.decrypt(ciphertext_multi,
					     nonce_multi);
    // since we decrypt over and over the same ciphertext message,
    // we don't nonce_multi.increment() here.
  }
  auto t01 = system_clock::now();
  auto tmulti = duration_cast<milliseconds>(t01-t00).count();

  os << "Decrypting " << nr_of_messages << " messages (multi ): "
     << tmulti << " milliseconds." << std::endl;
  
  // 2. time decrypting nr_of_messages with box
  auto t10 = system_clock::now();
  for (unsigned long i=0; i!=nr_of_messages; ++i) {
    decrypted_single = sc_single_alice.decrypt(ciphertext_single,
					       keypair_alice,
					       nonce_single);
    // since we decrypt over and over the same ciphtertext message,
    // we don't nonce_single.increment() here.
  }
  auto t11 = system_clock::now();
  auto tsingle = duration_cast<milliseconds>(t11-t10).count();

  os << "Decrypting " << nr_of_messages << " messages (single): "
     << tsingle << " milliseconds." << std::endl;

  BOOST_TEST_MESSAGE(os.str());
  
  BOOST_CHECK_MESSAGE(tmulti < tsingle,
		      "sodium::box_precomputed::decrypt() slower than Sodium::box::decrypt()");
}

template <typename BT = bytes>
void
time_decrypt_detached(const unsigned long nr_of_messages)
{
	keypair<BT>                  keypair_alice{};
	typename box<BT>::nonce_type      nonce_single{};
	typename box_precomputed<BT>::nonce_type nonce_multi{};
	box<BT>                  sc_single_alice{};
	box_precomputed<BT>      sc_multi_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	BT plainblob{ plaintext.cbegin(), plaintext.cend() };
	BT decrypted_multi(plaintext.size());
	BT decrypted_single(plaintext.size());

	BT mac_multi(box_precomputed<BT>::MACSIZE);
	BT mac_single(box<BT>::MACSIZE);

	// 0. encrypt once the plaintext without timing
	BT ciphertext_multi = sc_multi_alice.encrypt(plainblob, nonce_multi, mac_multi);
	BT ciphertext_single = sc_single_alice.encrypt(plainblob,
		keypair_alice,
		nonce_single,
		mac_single);

	std::ostringstream os;

	using bytes_type = BT;
	os << "Timing decrypt " << typeid(bytes_type).name() << "...\n";

	// 1. time decrypting nr_of_messages with box_precomputed
	auto t00 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		decrypted_multi = sc_multi_alice.decrypt(ciphertext_multi,
			nonce_multi,
			mac_multi);
		// since we decrypt over and over the same ciphertext message,
		// we don't nonce_multi.increment() here.
	}
	auto t01 = system_clock::now();
	auto tmulti = duration_cast<milliseconds>(t01 - t00).count();

	os << "Decrypting " << nr_of_messages << " messages (multi ): "
		<< tmulti << " milliseconds." << std::endl;

	// 2. time decrypting nr_of_messages with box
	auto t10 = system_clock::now();
	for (unsigned long i = 0; i != nr_of_messages; ++i) {
		decrypted_single = sc_single_alice.decrypt(ciphertext_single,
			keypair_alice,
			nonce_single,
			mac_single);
		// since we decrypt over and over the same ciphtertext message,
		// we don't nonce_single.increment() here.
	}
	auto t11 = system_clock::now();
	auto tsingle = duration_cast<milliseconds>(t11 - t10).count();

	os << "Decrypting(detached) " << nr_of_messages << " messages (single): "
		<< tsingle << " milliseconds." << std::endl;

	BOOST_TEST_MESSAGE(os.str());

	BOOST_CHECK_MESSAGE(tmulti < tsingle,
		"sodium::box_precomputed::decrypt() slower than Sodium::box::decrypt()");
}

struct SodiumFixture {
  SodiumFixture()  {
    BOOST_REQUIRE(sodium_init() != -1);
    // BOOST_TEST_MESSAGE("SodiumFixture(): sodium_init() successful.");
  }
  ~SodiumFixture() {
    // BOOST_TEST_MESSAGE("~SodiumFixture(): teardown -- no-op.");
  }
};

BOOST_FIXTURE_TEST_SUITE ( sodium_test_suite, SodiumFixture )

// 1. sodium::bytes --------------------------------------------------------

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_full_plaintext_bytes )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  BOOST_TEST(test_of_correctness<>(plaintext));
  BOOST_TEST(test_of_correctness_detached<>(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_empty_plaintext_bytes )
{
  std::string plaintext {};
  BOOST_TEST(test_of_correctness<>(plaintext));
  BOOST_TEST(test_of_correctness_detached<>(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_cryptomultipk_test_encrypt_to_self_bytes )
{
  keypair<> keypair_alice;
  typename box_precomputed<>::nonce_type nonce;
  box_precomputed<> sc_alice(keypair_alice);
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  bytes ciphertext = sc_alice.encrypt(plainblob, nonce);

  BOOST_TEST(ciphertext.size() == plainblob.size() + box_precomputed<>::MACSIZE);

  bytes decrypted = sc_alice.decrypt(ciphertext, nonce);

  // if the ciphertext (with MAC) was modified, or came from another
  // source, decryption would have thrown. But we manually check anyway.

  BOOST_TEST(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE(sodium_cryptomultipk_test_encrypt_to_self_bytes_detached)
{
	keypair<> keypair_alice;
	typename box_precomputed<>::nonce_type nonce;
	box_precomputed<> sc_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	bytes plainblob{ plaintext.cbegin(), plaintext.cend() };

	bytes mac(box_precomputed<>::MACSIZE);

	bytes ciphertext = sc_alice.encrypt(plainblob, nonce, mac);

	BOOST_TEST(ciphertext.size() == plainblob.size());
	BOOST_TEST(mac.size() == box_precomputed<>::MACSIZE);

	bytes decrypted = sc_alice.decrypt(ciphertext, nonce, mac);

	// if the ciphertext (or MAC) was modified, or came from another
	// source, decryption would have thrown. But we manually check anyway.

	BOOST_TEST(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_detect_wrong_sender_fulltext_bytes )
{
  std::string plaintext {"Hi Alice, this is Bob!"};

  BOOST_TEST(falsify_sender<>(plaintext));
  BOOST_TEST(falsify_sender_detached<>(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_detect_wrong_sender_empty_text_bytes)
{
  std::string plaintext {};

  BOOST_TEST(falsify_sender<>(plaintext));
  BOOST_TEST(falsify_sender_detached<>(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_falsify_ciphertext_bytes )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_TEST(falsify_ciphertext<>(plaintext));
  BOOST_TEST(falsify_ciphertext_detached<>(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_falsify_mac_fulltext_bytes )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};

  BOOST_TEST(falsify_mac<>(plaintext));
  BOOST_TEST(falsify_mac_detached<>(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_falsify_mac_empty_bytes )
{
  std::string plaintext {};

  BOOST_TEST(falsify_mac<>(plaintext));
  BOOST_TEST(falsify_mac_detached<>(plaintext));
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_destroysharedkey_encrypt_bytes )
{
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};

  BOOST_TEST(destroy_shared_key_then_encrypt<>(plainblob));
  BOOST_TEST(destroy_shared_key_then_encrypt_detached<>(plainblob));
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_destroysharedkey_decrypt_bytes )
{
  keypair<> keypair_alice;
  typename box_precomputed<>::nonce_type nonce;
  box_precomputed<> sc_alice(keypair_alice);
  
  std::string plaintext {"the quick brown fox jumps over the lazy dog"};
  bytes plainblob {plaintext.cbegin(), plaintext.cend()};
  bytes ciphertext = sc_alice.encrypt(plainblob, nonce);

  BOOST_TEST(destroy_shared_key_then_decrypt(ciphertext,
					      keypair_alice,
					      nonce));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_destroysharedkey_decrypt_bytes_detached)
{
	keypair<> keypair_alice;
	typename box_precomputed<>::nonce_type nonce;
	box_precomputed<> sc_alice(keypair_alice);

	bytes mac(box_precomputed<>::MACSIZE);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	bytes plainblob{ plaintext.cbegin(), plaintext.cend() };
	bytes ciphertext = sc_alice.encrypt(plainblob, nonce, mac);

	BOOST_TEST(destroy_shared_key_then_decrypt_detached(ciphertext,
		keypair_alice,
		nonce,
		mac));
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_time_multimessages_encrypt_bytes )
{
  time_encrypt<>(1000);
  time_encrypt<>(10000);
  time_encrypt_detached<>(1000);
  time_encrypt_detached<>(10000);
}

BOOST_AUTO_TEST_CASE( sodium_box_precomputed_test_time_multimessages_decrypt_bytes )
{
  time_decrypt<>(1000);
  time_decrypt<>(10000);
  time_decrypt_detached<>(1000);
  time_decrypt_detached<>(10000);
}

// 2. sodium::bytes_protected ---------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_full_plaintext_bytes_protected)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(plaintext));
	BOOST_TEST(test_of_correctness_detached<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_empty_plaintext_bytes_protected)
{
	std::string plaintext{};
	BOOST_TEST(test_of_correctness<sodium::bytes_protected>(plaintext));
	BOOST_TEST(test_of_correctness_detached<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_cryptomultipk_test_encrypt_to_self_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair_alice;
	typename box_precomputed<sodium::bytes_protected>::nonce_type nonce;
	box_precomputed<sodium::bytes_protected> sc_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };

	sodium::bytes_protected ciphertext = sc_alice.encrypt(plainblob, nonce);

	BOOST_TEST(ciphertext.size() == plainblob.size() + box_precomputed<sodium::bytes_protected>::MACSIZE);

	sodium::bytes_protected decrypted = sc_alice.decrypt(ciphertext, nonce);

	// if the ciphertext (with MAC) was modified, or came from another
	// source, decryption would have thrown. But we manually check anyway.

	BOOST_TEST(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE(sodium_cryptomultipk_test_encrypt_to_self_bytes_protected_detached)
{
	keypair<sodium::bytes_protected> keypair_alice;
	typename box_precomputed<sodium::bytes_protected>::nonce_type nonce;
	box_precomputed<sodium::bytes_protected> sc_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };

	sodium::bytes_protected mac(box_precomputed<sodium::bytes_protected>::MACSIZE);

	sodium::bytes_protected ciphertext = sc_alice.encrypt(plainblob, nonce, mac);

	BOOST_TEST(ciphertext.size() == plainblob.size());
	BOOST_TEST(mac.size() == box_precomputed<sodium::bytes_protected>::MACSIZE);

	sodium::bytes_protected decrypted = sc_alice.decrypt(ciphertext, nonce, mac);

	// if the ciphertext (or MAC) was modified, or came from another
	// source, decryption would have thrown. But we manually check anyway.

	BOOST_TEST(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_detect_wrong_sender_fulltext_bytes_protected)
{
	std::string plaintext{ "Hi Alice, this is Bob!" };

	BOOST_TEST(falsify_sender<sodium::bytes_protected>(plaintext));
	BOOST_TEST(falsify_sender_detached<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_detect_wrong_sender_empty_text_bytes_protected)
{
	std::string plaintext{};

	BOOST_TEST(falsify_sender<sodium::bytes_protected>(plaintext));
	BOOST_TEST(falsify_sender_detached<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_falsify_ciphertext_bytes_protected)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

	BOOST_TEST(falsify_ciphertext<sodium::bytes_protected>(plaintext));
	BOOST_TEST(falsify_ciphertext_detached<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_falsify_mac_fulltext_bytes_protected)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

	BOOST_TEST(falsify_mac<sodium::bytes_protected>(plaintext));
	BOOST_TEST(falsify_mac_detached<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_falsify_mac_empty_bytes_protected)
{
	std::string plaintext{};

	BOOST_TEST(falsify_mac<sodium::bytes_protected>(plaintext));
	BOOST_TEST(falsify_mac_detached<sodium::bytes_protected>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_destroysharedkey_encrypt_bytes_protected)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };

	BOOST_TEST(destroy_shared_key_then_encrypt<sodium::bytes_protected>(plainblob));
	BOOST_TEST(destroy_shared_key_then_encrypt_detached<sodium::bytes_protected>(plainblob));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_destroysharedkey_decrypt_bytes_protected)
{
	keypair<sodium::bytes_protected> keypair_alice;
	typename box_precomputed<sodium::bytes_protected>::nonce_type nonce;
	box_precomputed<sodium::bytes_protected> sc_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };
	sodium::bytes_protected ciphertext = sc_alice.encrypt(plainblob, nonce);

	BOOST_TEST(destroy_shared_key_then_decrypt(ciphertext,
		keypair_alice,
		nonce));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_destroysharedkey_decrypt_bytes_protected_detached)
{
	keypair<sodium::bytes_protected> keypair_alice;
	typename box_precomputed<sodium::bytes_protected>::nonce_type nonce;
	box_precomputed<sodium::bytes_protected> sc_alice(keypair_alice);

	sodium::bytes_protected mac(box_precomputed<sodium::bytes_protected>::MACSIZE);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::bytes_protected plainblob{ plaintext.cbegin(), plaintext.cend() };
	sodium::bytes_protected ciphertext = sc_alice.encrypt(plainblob, nonce, mac);

	BOOST_TEST(destroy_shared_key_then_decrypt_detached(ciphertext,
		keypair_alice,
		nonce,
		mac));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_time_multimessages_encrypt_bytes_protected)
{
	time_encrypt<sodium::bytes_protected>(1000);
	time_encrypt<sodium::bytes_protected>(10000);
	time_encrypt_detached<sodium::bytes_protected>(1000);
	time_encrypt_detached<sodium::bytes_protected>(10000);
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_time_multimessages_decrypt_bytes_protected)
{
	time_decrypt<sodium::bytes_protected>(1000);
	time_decrypt<sodium::bytes_protected>(10000);
	time_decrypt_detached<sodium::bytes_protected>(1000);
	time_decrypt_detached<sodium::bytes_protected>(10000);
}

// 3. sodium::chars --------------------------------------------------------

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_full_plaintext_chars)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	BOOST_TEST(test_of_correctness<sodium::chars>(plaintext));
	BOOST_TEST(test_of_correctness_detached<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_empty_plaintext_chars)
{
	std::string plaintext{};
	BOOST_TEST(test_of_correctness<sodium::chars>(plaintext));
	BOOST_TEST(test_of_correctness_detached<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_cryptomultipk_test_encrypt_to_self_chars)
{
	keypair<sodium::chars> keypair_alice;
	typename box_precomputed<sodium::chars>::nonce_type nonce;
	box_precomputed<sodium::chars> sc_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::chars plainblob{ plaintext.cbegin(), plaintext.cend() };

	sodium::chars ciphertext = sc_alice.encrypt(plainblob, nonce);

	BOOST_TEST(ciphertext.size() == plainblob.size() + box_precomputed<sodium::chars>::MACSIZE);

	sodium::chars decrypted = sc_alice.decrypt(ciphertext, nonce);

	// if the ciphertext (with MAC) was modified, or came from another
	// source, decryption would have thrown. But we manually check anyway.

	BOOST_TEST(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE(sodium_cryptomultipk_test_encrypt_to_self_chars_detached)
{
	keypair<sodium::chars> keypair_alice;
	typename box_precomputed<sodium::chars>::nonce_type nonce;
	box_precomputed<sodium::chars> sc_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::chars plainblob{ plaintext.cbegin(), plaintext.cend() };

	sodium::chars mac(box_precomputed<sodium::chars>::MACSIZE);

	sodium::chars ciphertext = sc_alice.encrypt(plainblob, nonce, mac);

	BOOST_TEST(ciphertext.size() == plainblob.size());
	BOOST_TEST(mac.size() == box_precomputed<sodium::chars>::MACSIZE);

	sodium::chars decrypted = sc_alice.decrypt(ciphertext, nonce, mac);

	// if the ciphertext (or MAC) was modified, or came from another
	// source, decryption would have thrown. But we manually check anyway.

	BOOST_TEST(plainblob == decrypted);
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_detect_wrong_sender_fulltext_chars)
{
	std::string plaintext{ "Hi Alice, this is Bob!" };

	BOOST_TEST(falsify_sender<sodium::chars>(plaintext));
	BOOST_TEST(falsify_sender_detached<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_detect_wrong_sender_empty_text_chars)
{
	std::string plaintext{};

	BOOST_TEST(falsify_sender<sodium::chars>(plaintext));
	BOOST_TEST(falsify_sender_detached<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_falsify_ciphertext_chars)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

	BOOST_TEST(falsify_ciphertext<sodium::chars>(plaintext));
	BOOST_TEST(falsify_ciphertext_detached<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_falsify_mac_fulltext_chars)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };

	BOOST_TEST(falsify_mac<sodium::chars>(plaintext));
	BOOST_TEST(falsify_mac_detached<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_falsify_mac_empty_chars)
{
	std::string plaintext{};

	BOOST_TEST(falsify_mac<sodium::chars>(plaintext));
	BOOST_TEST(falsify_mac_detached<sodium::chars>(plaintext));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_destroysharedkey_encrypt_chars)
{
	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::chars plainblob{ plaintext.cbegin(), plaintext.cend() };

	BOOST_TEST(destroy_shared_key_then_encrypt<sodium::chars>(plainblob));
	BOOST_TEST(destroy_shared_key_then_encrypt_detached<sodium::chars>(plainblob));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_destroysharedkey_decrypt_chars)
{
	keypair<sodium::chars> keypair_alice;
	typename box_precomputed<sodium::chars>::nonce_type nonce;
	box_precomputed<sodium::chars> sc_alice(keypair_alice);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::chars plainblob{ plaintext.cbegin(), plaintext.cend() };
	sodium::chars ciphertext = sc_alice.encrypt(plainblob, nonce);

	BOOST_TEST(destroy_shared_key_then_decrypt(ciphertext,
		keypair_alice,
		nonce));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_destroysharedkey_decrypt_chars_detached)
{
	keypair<sodium::chars> keypair_alice;
	typename box_precomputed<sodium::chars>::nonce_type nonce;
	box_precomputed<sodium::chars> sc_alice(keypair_alice);

	sodium::chars mac(box_precomputed<sodium::chars>::MACSIZE);

	std::string plaintext{ "the quick brown fox jumps over the lazy dog" };
	sodium::chars plainblob{ plaintext.cbegin(), plaintext.cend() };
	sodium::chars ciphertext = sc_alice.encrypt(plainblob, nonce, mac);

	BOOST_TEST(destroy_shared_key_then_decrypt_detached(ciphertext,
		keypair_alice,
		nonce,
		mac));
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_time_multimessages_encrypt_chars)
{
	time_encrypt<sodium::chars>(1000);
	time_encrypt<sodium::chars>(10000);
	time_encrypt_detached<sodium::chars>(1000);
	time_encrypt_detached<sodium::chars>(10000);
}

BOOST_AUTO_TEST_CASE(sodium_box_precomputed_test_time_multimessages_decrypt_chars)
{
	time_decrypt<sodium::chars>(1000);
	time_decrypt<sodium::chars>(10000);
	time_decrypt_detached<sodium::chars>(1000);
	time_decrypt_detached<sodium::chars>(10000);
}

BOOST_AUTO_TEST_SUITE_END ()
