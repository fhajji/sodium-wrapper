// sodiumalloc.h -- an allocator for keys in wired memory

#ifndef _SODIUMALLOC_H_
#define _SODIUMALLOC_H_

#include <cstddef>
#include <sodium.h>

template <typename T>
class SodiumAlloc
{
 public:
  typedef T value_type;
    
  SodiumAlloc() {}

  SodiumAlloc(const SodiumAlloc &) = default; // for now
  SodiumAlloc & operator= (const SodiumAlloc &) = delete; // for now
  
  ~SodiumAlloc() {}

  T* allocate (std::size_t num) {
    return static_cast<T*>(sodium_allocarray(num, sizeof(T)));
  }
  void deallocate (T* ptr, std::size_t num) {
    sodium_free(ptr);
  }

  // The following functions make a region read-only, r/w, or inaccessible
  int noaccess  (T* ptr) { return sodium_mprotect_noaccess(ptr); }
  int readonly  (T* ptr) { return sodium_mprotect_readonly(ptr); }
  int readwrite (T* ptr) { return sodium_mprotect_readwrite(ptr); }
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
