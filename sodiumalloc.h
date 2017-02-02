// sodiumalloc.h -- an allocator for keys in wired memory

#ifndef _SODIUMALLOC_H_
#define _SODIUMALLOC_H_

#include <cstddef>
#include <new>
#include <stdexcept>
#include <sodium.h>

template <typename T>
class SodiumAlloc
{
 public:
  typedef T value_type;
    
  SodiumAlloc() {
    // safe to call sodium_init() more than once, but must be called
    // at least once before using other libsodium functions.
    if (sodium_init() == -1)
      throw std::runtime_error {"SodiumAlloc::SodiumAlloc() can't sodium_init()"};
  }

  SodiumAlloc(const SodiumAlloc &) = default;
  SodiumAlloc & operator= (const SodiumAlloc &) = delete; // for now
  
  ~SodiumAlloc() {}

  T* allocate (std::size_t num) {
    // XXX: should we round up to at least 64 bytes?
    // XXX: for now, we use this for 32 bytes keys, which is not enough...
    
    void *ptr = sodium_allocarray(num, sizeof(T));
    if (ptr == NULL)
      throw std::bad_alloc {};
    else
      return static_cast<T*>(ptr);
  }
  
  void deallocate (T* ptr, std::size_t num) {
    sodium_free(ptr);
  }

  // The following functions make a region read-only, r/w, or inaccessible
  void noaccess  (T* ptr) {
    if (sodium_mprotect_noaccess(ptr) == -1)
      throw std::runtime_error {"SodiumAlloc::noaccess() failed"};
  }
  
  void readonly  (T* ptr) {
    if (sodium_mprotect_readonly(ptr) == -1)
      throw std::runtime_error {"SodiumAlloc::readonly() failed"};
  }
  
  void readwrite (T* ptr) {
    if (sodium_mprotect_readwrite(ptr) == -1)
      throw std::runtime_error {"SodiumAlloc::readwrite() failed"};
  }
};

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
