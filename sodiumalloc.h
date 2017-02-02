// sodiumalloc.h -- An allocator for keys in wired memory
//
// Copyright (C) 2017 Farid Hajji <farid@hajji.name>. All rights reserved.

#ifndef _SODIUMALLOC_H_
#define _SODIUMALLOC_H_

#include <sodium.h>

#include <cstddef>
#include <new>
#include <stdexcept>

/**
 * This custom allocator doles out "secure memory" using libsodium's
 * malloc*() utility functions.  The idea is to store sensitive key
 * material in a std::vector<unsigned char, SodiumAlloc<unsigned char>>
 * and let C++11's STL allocator magic work behind the scenes to grab
 * and safely release memory in mprotect()ed vitual pages of memory.
 *
 * We this implement a custom allocator template and override:
 *
 *   - the constructor, to initialize sodium_init()... once more,
 *     just to be safe.
 *   - allocate(), to grab mprotected memory for num T elements
 *     using sodium_allocarray()
 *   - deallocate(), to release and zero memory automatically
 *     using sodium_free()
 *
 * Furthermore, we provide 3 additional functions not part of the
 * usual allocator interface, to manipulate the access rights of
 * the virutal page where the ptr resides into:
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

template <typename T>
class SodiumAlloc
{
 public:
  typedef T value_type;

  /**
   * Initialize the libsodium library by calling sodium_init()
   * at least once.  We throw a std::runtime_error if the library
   * can't be initialized.
   **/
  
  SodiumAlloc() {
    // safe to call sodium_init() more than once, but must be called
    // at least once before using other libsodium functions.
    if (sodium_init() == -1)
      throw std::runtime_error {"SodiumAlloc::SodiumAlloc() can't sodium_init()"};
  }

  SodiumAlloc(const SodiumAlloc &) = default;
  SodiumAlloc & operator= (const SodiumAlloc &) = delete; // for now
  
  ~SodiumAlloc() {}

  /**
   * Allocate memory for num elements of type T, without constructing
   * them.  We therefore need num * sizeof(T) bytes of memory.
   *
   * We get those bytes from sodium_allocarray(), which gets multiple
   * virtual pages of memory per call (!), mprotect()s guard pages,
   * places a canary that will be checked on deallocation, and so on.
   *
   * If sodium_allocarray() fails, we throw a std::bad_alloc, else
   * we cast the pointer retured by it to a T* and return that, then
   * we're done.
   **/
  
  T* allocate (std::size_t num) {
    // XXX: should we round up to at least 64 bytes?
    // XXX: for now, we use this for 32 bytes keys, which is not enough...
    
    void *ptr = sodium_allocarray(num, sizeof(T));
    if (ptr == NULL)
      throw std::bad_alloc {};
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
  
  void deallocate (T* ptr, std::size_t num) {
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
  void noaccess  (T* ptr) {
    if (sodium_mprotect_noaccess(ptr) == -1)
      throw std::runtime_error {"SodiumAlloc::noaccess() failed"};
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
  void readonly  (T* ptr) {
    if (sodium_mprotect_readonly(ptr) == -1)
      throw std::runtime_error {"SodiumAlloc::readonly() failed"};
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
  void readwrite (T* ptr) {
    if (sodium_mprotect_readwrite(ptr) == -1)
      throw std::runtime_error {"SodiumAlloc::readwrite() failed"};
  }
};

// Two SodiumAlloc allocators of different value types are always equal
template <typename T1, typename T2>
bool operator== (const SodiumAlloc<T1>&,
		 const SodiumAlloc<T2>&) noexcept {
  return true;
}

template <typename T1, typename T2>
bool operator!= (const SodiumAlloc<T1>&,
		 const SodiumAlloc<T2>&) noexcept {
  return false;
}

#endif // _SODIUMALLOC_H_
