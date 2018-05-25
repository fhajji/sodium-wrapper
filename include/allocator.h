// allocator.h -- An allocator for wired / protected memory
//
// ISC License
// 
// Copyright (c) 2018 Farid Hajji <farid@hajji.name>
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

// Uncommend the following #define line, or pass it via command line
// if you want (additional) calls to sodium_init() in sodium::allocator's
// ctor.
// 
// This is normally unnecessary if you call sodium_init() in your
// program before using libsodium or its wrapper(s). It is also
// not necessary in the unit tests, since sodium_init() is normally
// invoked in the test harness there, before the tests start.
// 
// #define SODIUM_INIT_IN_ALLOCATOR

#pragma once

#include <sodium.h>

#include <new>
#include <stdexcept>

#ifndef NDEBUG
#include <iostream>
#endif // ! NDEBUG

/**
 * This custom allocator doles out "secure memory" using libsodium's
 * malloc*() utility functions.  The idea is to store sensitive key
 * material in a std::vector<unsigned char, sodium::allocator<unsigned char>>
 * and let C++11's STL allocator magic work behind the scenes to grab
 * and safely release memory in mprotect()ed vitual pages of memory.
 *
 * We implement a custom allocator template and override:
 *
 *   - the constructor, to initialize sodium_init()... once more,
 *     just to be safe
 *     (only if SODIUM_INIT_IN_ALLOCATOR is #define(d))
 *   - allocate(), to grab mprotected memory for num T elements
 *     using sodium_allocarray()
 *   - deallocate(), to release and zero memory automatically
 *     using sodium_free()
 *
 * Furthermore, we provide 3 additional functions not part of the
 * usual allocator interface, to manipulate the access rights of
 * the virtual page where the ptr points into:
 * 
 *   - noaccess() disables read/write access completely, but
 *     retains the memory (useful if we still need the key later)
 *   - readonly() makes the page read-only, to prevent key-changes
 *   - readwrite() makes the page read-write again
 *
 * These functions can be accessed indirectly by calling
 *   keyvector.get_allocator().noaccess(keyvector.data());
 *   keyvector.get_allocator().readonly(keyvector.data());
 **/

namespace sodium {

	template <typename T>
	class allocator
	{
	public:
		using value_type = T;

		/**
		 * Initialize the libsodium library by calling sodium_init()
		 * at least once.  We throw a std::runtime_error if the library
		 * can't be initialized.
		 **/

		allocator() {
#ifdef SODIUM_INIT_IN_ALLOCATOR
			// safe to call sodium_init() more than once, but must be called
			// at least once before using other libsodium functions.
			if (sodium_init() == -1)
				throw std::runtime_error{ "sodium::allocator::allocator() can't sodium_init()" };
#endif // SODIUM_INIT_IN_ALLOCATOR
		}

		template <typename U>
		allocator(const allocator<U> &) {}

		~allocator() {}

		/**
		 * Allocate memory for num elements of type T, without constructing
		 * them.  We therefore need num * sizeof(T) bytes of memory.
		 *
		 * We get those bytes from sodium_allocarray(), which gets multiple
		 * virtual pages of memory per call (!), mprotect()s guard pages,
		 * places a canary that will be checked on deallocation, and so on.
		 *
		 * If sodium_allocarray() fails, we throw a std::bad_alloc, else
		 * we cast the pointer returned by it to a T* and return that, then
		 * we're done.
		 **/

		T* allocate(std::size_t num) {
#ifndef NDEBUG
			std::cerr << "DEBUG: sodium::allocator::allocate(" << num << ") -> ";
#endif // ! NDEBUG

			// XXX slowly increase num until we reach at least 64 bytes
			// while (num * sizeof(T) <= 64) ++num;

			void *ptr = sodium_allocarray(num, sizeof(T));

#ifndef NDEBUG
			std::cerr << static_cast<void *>(ptr) << std::endl;
#endif // ! NDEBUG

			if (ptr == NULL)
				throw std::bad_alloc{};
			else
				return static_cast<T*>(ptr);
		}

		/**
		 * Deallocate memory pointed to by ptr, and that was reserved
		 * for num elements of type T (the num is not needed).
		 *
		 * We deallocate by calling sodium_free(ptr), which:
		 *   - safely zeroes the memory
		 *   - checks the canary, and crashes/aborts if it was touched
		 *   - munprotects the virtual pages
		 *   - removes the virtual pages
		 *
		 **/

		void deallocate(T* ptr,
#ifndef NDEBUG
			std::size_t num)
#else
			std::size_t /* num */)
#endif // ! NDEBUG
		{
#ifndef NDEBUG
			std::cerr << "DEBUG: sodium::allocator::deallocate("
				<< static_cast<void *>(ptr)
				<< ", " << num
				<< ")" << std::endl;
#endif // ! NDEBUG

			sodium_free(ptr);
		}

		/**
		 * Make the region pointed to by ptr (temporarily) inaccessible.
		 *
		 * Always call this when a key is not in use. When needed, call
		 * readonly() or readwrite() to regain access.
		 *
		 * noaccess() throws an std::runtime_error if the underlying
		 * mprotect() call failed.
		 **/
		void noaccess(T* ptr) {
#ifndef NDEBUG
			std::cerr << "DEBUG: sodium::allocator::noaccess("
				<< static_cast<void *>(ptr)
				<< ")" << std::endl;
#endif // ! NDEBUG

			if (sodium_mprotect_noaccess(ptr) == -1)
				throw std::runtime_error{ "sodium::allocator::noaccess() failed" };
		}

		/**
		 * Make the region pointed to by ptr read-only
		 *
		 * Always call this for key material after a key has been entered
		 * or generated, or when you need to regain access after noaccess().
		 *
		 * readonly() throws a std::runtime_error if the underlying
		 * mprotect() call failed.
		 **/
		void readonly(T* ptr) {
#ifndef NDEBUG
			std::cerr << "DEBUG: sodium::allocator::readonly("
				<< static_cast<void *>(ptr)
				<< ")" << std::endl;
#endif // ! NDEBUG

			if (sodium_mprotect_readonly(ptr) == -1)
				throw std::runtime_error{ "sodium::allocator::readonly() failed" };
		}

		/**
		 * Make the region pointed to by ptr read-write
		 *
		 * Call this to make a region previously made read-only with readonly()
		 * or inaccessiable with noaccess() read-writable again.
		 *
		 * readwrite() throws a std::runtime_error if the underlying
		 * mprotect() call failed.
		 **/
		void readwrite(T* ptr) {
#ifndef NDEBUG
			std::cerr << "DEBUG: sodium::allocator::readwrite("
				<< static_cast<void *>(ptr)
				<< ")" << std::endl;
#endif // ! NDEBUG

			if (sodium_mprotect_readwrite(ptr) == -1)
				throw std::runtime_error{ "sodium::allocator::readwrite() failed" };
		}
	};

	// Two sodium::allocator allocators of different value types are always equal
	template <typename T1, typename T2>
	bool operator== (const allocator<T1>&,
		const allocator<T2>&) noexcept
	{
		return true;
	}

	template <typename T1, typename T2>
	bool operator!= (const allocator<T1>&,
		const allocator<T2>&) noexcept
	{
		return false;
	}

} // namespace sodium
