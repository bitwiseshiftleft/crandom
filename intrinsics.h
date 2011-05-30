#ifndef __CRANDOM_INTRINSICS_H__
#define __CRANDOM_INTRINSICS_H__

#include <sys/types.h>

#define INTRINSIC \
  static inline __attribute__((__gnu_inline__, __always_inline__))

#define GEN    1
#define SSE2   2
#define SSSE3  4
#define AESNI  8
#define XOP    16

#ifdef __SSE2__
#  define MIGHT_HAVE_SSE2 1
#  ifndef MUST_HAVE_SSE2
#    define MUST_HAVE_SSE2 0
#  endif

#  include <emmintrin.h>
   typedef __m128i ssereg;
#  define pslldq _mm_slli_epi32
#  define pshufd _mm_shuffle_epi32

INTRINSIC ssereg sse2_rotate(int r, ssereg a) {
  return _mm_slli_epi32(a, r) ^ _mm_srli_epi32(a, 32-r);
}

#else
#  define MIGHT_HAVE_SSE2 0
#  define MUST_HAVE_SSE2  0
#endif

#ifdef __SSSE3__
#  include <tmmintrin.h>
#  define MIGHT_HAVE_SSSE3 1
#  ifndef MUST_HAVE_SSSE3
#    define MUST_HAVE_SSSE3 0
#  endif
#else
#  define MIGHT_HAVE_SSSE3 0
#  define MUST_HAVE_SSSE3 0
#endif

#ifdef __AES__
/* don't include intrinsics file, because not all platforms have it */
#  define MIGHT_HAVE_AESNI 1
#  ifndef MUST_HAVE_AESNI
#    define MUST_HAVE_AESNI 0
#  endif

INTRINSIC ssereg aeskeygenassist(int rc, ssereg x) {
  ssereg out;
  asm("aeskeygenassist %2, %1, %0" : "=x"(out) : "x"(x), "g"(rc));
  return out;
}

INTRINSIC ssereg aesenc(ssereg subkey, ssereg block) {
  ssereg out = block;
  asm("aesenc %1, %0" : "+x"(out) : "x"(subkey));
  return out;
}

INTRINSIC ssereg aesenclast(ssereg subkey, ssereg block) {
  ssereg out = block;
  asm("aesenclast %1, %0" : "+x"(out) : "x"(subkey));
  return out;
}

#else
#  define MIGHT_HAVE_AESNI 0
#  define MUST_HAVE_AESNI 0
#endif



#ifdef __XOP__
/* don't include intrinsics file, because not all platforms have it */
#  define MIGHT_HAVE_XOP 1
#  ifndef MUST_HAVE_XOP
#    define MUST_HAVE_XOP 0
#  endif
INTRINSIC ssereg xop_rotate(int amount, ssereg x) {
  ssereg out;
  asm ("vprotd %1, %2, %0" : "=x"(out) : "x"(x), "g"(amount));
  return out;
}
#else
#  define MIGHT_HAVE_XOP 0
#  define MUST_HAVE_XOP 0
#endif

#define MIGHT_MASK \
  ( SSE2  * MIGHT_HAVE_SSE2   \
  | SSSE3 * MIGHT_HAVE_SSSE3  \
  | AESNI * MIGHT_HAVE_AESNI  \
  | XOP   * MIGHT_HAVE_XOP )

#define MUST_MASK \
  ( SSE2  * MUST_HAVE_SSE2   \
  | SSSE3 * MUST_HAVE_SSSE3  \
  | AESNI * MUST_HAVE_AESNI  \
  | XOP   * MUST_HAVE_XOP )

#define MIGHT_HAVE(feature) ((MIGHT_MASK & feature) == feature)
#define MUST_HAVE(feature) ((MUST_MASK & feature) == feature)

#ifdef __cplusplus
#  define extern_c extern "C"
#else
#  define extern_c
#endif

extern_c
unsigned int crandom_detect_features();

#ifndef likely
#  define likely(x)       __builtin_expect((x),1)
#  define unlikely(x)     __builtin_expect((x),0)
#endif

extern unsigned int crandom_features;
static inline int HAVE(unsigned int feature) {
  if (!MIGHT_HAVE(feature)) return 0;
  if (MUST_HAVE(feature))   return 1;
  if (unlikely(!crandom_features))
    crandom_features = crandom_detect_features();
  return likely((crandom_features & feature) == feature);
}

#endif // __CRANDOM_INTRINSICS_H__