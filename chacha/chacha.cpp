#include <sys/types.h>
#include "chacha.hpp"

// ------------------------------- Vectorized code -------------------------------
#ifdef __SSE2__
#include <emmintrin.h>
typedef __m128i ssereg;

#define shuffle(x,i) _mm_shuffle_epi32(x, \
  i + ((i+1)&3)*4 + ((i+2)&3)*16 + ((i+3)&3)*64)
  
static inline ssereg add(ssereg a, ssereg b) {
  return _mm_add_epi32(a,b);
}
static inline ssereg add64(ssereg a, ssereg b) {
  return _mm_add_epi64(a,b);
}

template<int r>
static inline ssereg rotate(ssereg a) {
  return add(_mm_slli_epi32(a, r), _mm_srli_epi32(a, 32-r));
}

#ifdef __SSSE3__
# include <tmmintrin.h>
  static const ssereg shuffle8  = { 0x0605040702010003ull, 0x0E0D0C0F0A09080Bull };
  static const ssereg shuffle16 = { 0x0504070601000302ull, 0x0D0C0F0E09080B0Aull };
  
  template<>
  static inline ssereg rotate<8>(ssereg a) {
    return _mm_shuffle_epi8(a, shuffle8);
  }
  
  template<>
  static inline ssereg rotate<16>(ssereg a) {
    return _mm_shuffle_epi8(a, shuffle16);
  }
#endif // __SSSE3__
#endif // __SSE2__
// -------------------------------------------------------------------------------

static inline u_int32_t add(u_int32_t a, u_int32_t b) {
  return a+b;
}

template<int r>
static inline u_int32_t rotate(u_int32_t a) {
  return a<<r ^ a>>(32-r);
}

template<class t>
static inline void
quarter_round(t &a, t &b, t &c, t &d) {
  a = add(a,b); d = rotate<16>(d^a);
  c = add(c,d); b = rotate<12>(b^c);
  a = add(a,b); d = rotate<8>(d^a);
  c = add(c,d); b = rotate<7>(b^c);
}

namespace crandom {

void chacha_expand(const unsigned char *key_,
                   u_int64_t iv,
                   u_int64_t ctr,
                   int nr,
                   int output_size,
                   unsigned char *output_) {
# ifdef __SSE2__
    ssereg *key = (ssereg *)key_;
    ssereg *output = (ssereg *)output_;
                     
    ssereg a1 = key[0], a2 = a1, aa = a1,
           b1 = key[1], b2 = b1, bb = b1,
           c1 = {iv, ctr}, c2 = {iv, ctr+1}, cc = c1,
           d1 = {0x3320646e61707865ull, 0x6b20657479622d32ull}, d2 = d1, dd = d1,
           p = {0, 1};
     
    int i,r;
    for (i=0; i<output_size; i+=128) {
      for (r=nr; r>0; r-=2) {
      
        quarter_round(a1,b1,c1,d1);
        quarter_round(a2,b2,c2,d2);
        b1 = shuffle(b1,1);
        c1 = shuffle(c1,2);
        d1 = shuffle(d1,3);
        b2 = shuffle(b2,1);
        c2 = shuffle(c2,2);
        d2 = shuffle(d2,3);
        
        quarter_round(a1,b1,c1,d1);
        quarter_round(a2,b2,c2,d2);
        b1 = shuffle(b1,3);
        c1 = shuffle(c1,2);
        d1 = shuffle(d1,1);
        b2 = shuffle(b2,3);
        c2 = shuffle(c2,2);
        d2 = shuffle(d2,1);
      }
  
      output[0] = add(a1,aa);
      output[1] = add(b1,bb);
      output[2] = add(c1,cc);
      output[3] = add(d1,dd);
      output[4] = add(a2,aa);
      output[5] = add(b2,bb);
      output[6] = add(c2,add(cc,p));
      output[7] = add(d2,dd);
  
      output += 8;
      
      cc = add64(add64(cc,p), p);
      a1 = a2 = aa;
      b1 = b2 = bb;
      c1 = cc; c2 = add64(cc,p);
      d1 = d2 = dd;
    }
# else // __SSE2__
    const u_int32_t *key = (const u_int32_t *)key_;
    u_int32_t
      x[16],
      input[16] = {
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        iv, iv>>32, ctr, ctr>>32,
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
      },
      *output = (u_int32_t *)output_;
    int i, r;
  
    for (i=0; i<output_size; i+= 64) {
      for (r=0; r<16; r++) {
        x[r] = input[r];
      }
      for (r=nr; r>0; r-=2) {
        quarter_round(x[0], x[4],  x[8], x[12]);
        quarter_round(x[1], x[5],  x[9], x[13]);
        quarter_round(x[2], x[6], x[10], x[14]);
        quarter_round(x[3], x[7], x[11], x[15]);
        
        quarter_round(x[0], x[5], x[10], x[15]);
        quarter_round(x[1], x[6], x[11], x[12]);
        quarter_round(x[2], x[7],  x[8], x[13]);
        quarter_round(x[3], x[4],  x[9], x[14]);
      }
      for (r=0; r<16; r++) {
        output[r] = x[r] + input[r];
      }
      
      output += 16;
      input[11] ++;
      if (!input[11]) input[12]++;
    }
#endif // __SSE2__
}



} // namespace crandom
