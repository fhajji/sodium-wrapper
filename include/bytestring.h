// bytestring.h -- Specializations for 'unsigned char' strings
//
// ISC License
// 
// Copyright (c) 2017 Farid Hajji <farid@hajji.name>
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

#ifndef _BYTESTRING_H_
#define _BYTESTRING_H_

#include <boost/predef.h> // detect library and compiler...

// bytestring.h supports only libc++ (-stdlib=libc++) for now.

#if BOOST_LIB_STD_CXX    // are we using lic++?

#include <locale>  // std::ctype_base, std::ctype<char>, ...
#include <string>  // std::char_traits<char>
#include <cstddef> // EOF etc.

/**
 * UGLY HACK! DOESN'T WORK (YET) WITH g++. ONLY clang++ FOR NOW!
 * 
 * Skeleton implementation of
 *   std::char_traits<unsigned char>
 *   std::ctype<unsigned char>
 * which are specializations NOT specified by C++11
 * 
 * This is barely enough in order to compile
 * an std::basic_istream<unsigned char>-like class created by
 *   boost::iostreams::filtering_istream<boost::iostreams::input,
 *                                       unsigned char>.
 * 
 * We need that for code like this:
 * 
 *   namespace io = boost::iostreams;
 *   io::filtering_istream<io::input, unsigned char>::read(...);
 *
 * Should a later C++ standard implement these, or if there's a
 * (Boost?) library that provides a replacement, this file can be
 * substituted by the provided #include(s).
 * For now, we'll have to make do with it.
 **/

/**
 * std::char_traits<unsigned char> is a specialization of char_traits
 * for unsigned char.  We shamelessly borrow the implementation of
 * std::char_traits<char> from LLVM39/CLANG39, and use it nearly
 * unchanged for unsigned char.
 **/

#ifndef _LIBCPP_ALWAYS_INLINE
#define _LIBCPP_ALWAYS_INLINE inline
#endif // ! _LIBCPP_ALWAYS_INLINE

#if BOOST_COMP_GNUC // && ! BOOST_COMP_CLANG
namespace std {

template<>
struct char_traits<unsigned char> : public char_traits<char>
#else
  
template<>
struct std::char_traits<unsigned char> : public std::char_traits<char>
#endif
{
  typedef unsigned char char_type; // unsigned char instead of char!
  typedef int int_type;
  typedef streamoff off_type;
  typedef streampos pos_type;
  typedef mbstate_t state_type;
  
  static void assign (char_type & c1, const char_type & c2) noexcept {
    c1 = c2;
  }
  
  static bool eq(const char_type & c1, const char_type & c2) noexcept {
    return c1 == c2;
  }
  
  static bool lt(const char_type & c1, const char_type & c2) noexcept {
    return c1 < c2;
  }
  
  static int compare(const char_type * s1, const char_type * s2, std::size_t n) {
    for (; n; --n, ++s1, ++s2) {
      if (lt(*s1, *s2))
	return -1;
      if (lt(*s2, *s1))
	return 1;
    }
    return 0;
  }
  
  static std::size_t length(const char_type * s) {
    std::size_t len = 0;
    for (; !eq(*s, char_type(0)); ++s)
      ++len;
    return len;
  }
  
  static const char_type * find(const char_type * s, std::size_t n,
				const char_type & a) {
    for (; n; --n) {
      if (eq(*s, a))
	return s;
      ++s;
    }
    return 0;
  }

  static char_type * move(char_type * s1, const char_type * s2,
			  std::size_t n) {
    char_type *r = s1;
    if (s1 < s2) {
      for (; n; --n, ++s1, ++s2)
	assign(*s1, *s2);
    }
    else if (s2 < s1) {
      s1 += n;
      s2 += n;
      for (; n; --n)
	assign(*--s1, *--s2);
    }
    return r;
  }
  
  static char_type * copy(char_type * s1, const char_type * s2,
			  std::size_t n) {
    if (! (s2 < s1 || s2 >= s1+n))
      throw std::runtime_error {"std::char_traits<unsigned char>::copy() overlapped range"};

    char_type *r = s1;
    for (; n; --n, ++s1, ++s2)
      assign(*s1, *s2);
    return r;
  }
  
  static char_type * assign(char_type * s, std::size_t n, char_type a) {
    char_type *r = s;
    for (; n; --n, ++s)
      assign(*s, a);
    return r;
  }
  
  static int_type not_eof(const int_type & c) noexcept {
    return eq_int_type(c, eof()) ? ~eof() : c;
  }
  
  static char_type to_char_type(const int_type & c) noexcept {
    return char_type(c);
  }
  
  static int_type to_int_type(const char_type & c) noexcept {
    return int_type(c);
  }
  
  static bool eq_int_type (const int_type & c1, const int_type & c2) noexcept {
    return c1 == c2;
  }

  static int_type eof () noexcept {
    return int_type(EOF);
  }
}; // std::char_traits<unsigned char>

#if BOOST_COMP_GNUC // && ! BOOST_COMP_CLANG
} // namespace std
#endif
  
/**
 * std::ctype<unsigned char> is a specialization of std::ctype for
 * unsigned char.  We shamelessly take the implementation of
 * std::ctype<char> from LLVM39/CLANG39 and use it unchanged for
 * unsigned chars.
 **/

#if BOOST_COMP_GNUC // && ! BOOST_COMP_CLANG
namespace std {

template<>
class ctype<unsigned char> :
  public locale::facet, public ctype_base
#else
  
template<>
class std::ctype<unsigned char> :
  public std::locale::facet, public std::ctype_base
#endif
{
  const mask* tab;
  bool        del;
 public:
  typedef unsigned char char_type; // unsigned char instead of char!

  explicit ctype(const mask* tab=0, bool del=false, std::size_t refs=0) {
    // ...
  }

  bool is(mask m, char_type c) const {
    return isascii(c) ?
      (tab[static_cast<int>(c)] & m) != 0 : false;
  }

  const char_type* is(const char_type *low, const char_type *high, mask* vec) const {
    for (; low != high; ++low, ++vec)
      *vec = isascii(*low) ? tab[static_cast<int>(*low)] : 0;
    return low;
  }

  const char_type* scan_is(mask m, const char_type *low, const char_type *high) const {
    for (; low != high; ++low)
      if (isascii(*low) && (tab[static_cast<int>(*low)] & m))
	break;
    return low;
  }

  const char_type* scan_not(mask m, const char_type* low, const char_type *high) const {
    for (; low != high; ++low)
      if (!(isascii(*low) && (tab[static_cast<int>(*low)] & m)))
	break;
    return low;
  }

  char_type toupper(char_type c) const {
    return do_toupper(c);
  }

  const char_type* toupper(char_type* low, const char_type *high) const {
    return do_toupper(low, high);
  }

  char_type tolower(char_type c) const {
    return do_tolower(c);
  }

  const char_type* tolower(char_type* low, const char_type *high) const {
    return do_tolower(low, high);
  }

  char_type widen(char c) const {
    return do_widen(c);
  }

  const char* widen(const char* low, const char* high, char_type* to) const {
    return do_widen(low, high, to);
  }

  char narrow(char_type c, char dfault) const {
    return do_narrow(c, dfault);
  }

  const char* narrow(const char_type* low, const char_type* high,
		     char dfault, char* to) const {
    return do_narrow(low, high, dfault, to);
  }

  static std::locale::id id;

#ifdef _CACHED_RUNES
  static const std::size_t table_size = _CACHED_RUNES;
#else
  static const std::size_t table_size = 256;  // FIXME: Don't hardcode this.
#endif
  _LIBCPP_ALWAYS_INLINE const mask* table() const /* noexcept */ {return tab;}
  static const mask* classic_table()  noexcept;
#if defined(__GLIBC__) || defined(__EMSCRIPTEN__)
  static const int* __classic_upper_table() noexcept;
  static const int* __classic_lower_table() noexcept;
#endif
#if defined(__NetBSD__)
  static const short* __classic_upper_table() noexcept;
  static const short* __classic_lower_table() noexcept;
#endif

 protected:
  ~ctype();
  virtual char_type do_toupper(char_type c) const;
  virtual const char_type* do_toupper(char_type* low, const char_type* high) const;
  virtual char_type do_tolower(char_type c) const;
  virtual const char_type* do_tolower(char_type* low, const char_type* high) const;
  virtual char_type do_widen(char c) const;
  virtual const char* do_widen(const char* low, const char* high, char_type* to) const;
  virtual char do_narrow(char_type c, char dfault) const;
  virtual const char* do_narrow(const char_type* low, const char_type* high,
				char dfault, char* to) const;
}; // std::ctype<unsigned char>

#if BOOST_COMP_GNUC // && ! BOOST_COMP_CLANG
} // namespace std
#endif
 
#if BOOST_COMP_GNUC // && ! BOOST_COMP_CLANG
namespace std {

template<>
class ctype_byname<unsigned char>
  : public ctype<unsigned char>
#else  
  
template<>
class std::ctype_byname<unsigned char>
  : public std::ctype<unsigned char>
#endif
{
  locale_t __l;

public:
  explicit ctype_byname(const char*, std::size_t = 0); // NOT unsigned char here!
  explicit ctype_byname(const string&, std::size_t = 0);

protected:
  ~ctype_byname();
  virtual char_type do_toupper(char_type) const;
  virtual const char_type* do_toupper(char_type* low, const char_type* high) const;
  virtual char_type do_tolower(char_type) const;
  virtual const char_type* do_tolower(char_type* low, const char_type* high) const;
};

#if BOOST_COMP_GNUC // && ! BOOST_COMP_CLANG
} // namespace std
#endif
 
#if BOOST_COMP_GNUC // && ! BOOST_COMP_CLANG
namespace std {

locale::id ctype<unsigned char>::id;
#else

std::locale::id std::ctype<unsigned char>::id;
#endif

#if BOOST_COMP_GNUC // && ! BOOST_COMP_CLANG
} // namespace std
#endif
 
#else // ! BOOST_LIB_STD_CXX
#error "bytestring.h supports only libc++ for now"

#endif // BOOST_LIB_STD_CXX

#endif // _BYTESTRING_H_
