#include <emmintrin.h>
#include "chacha.hpp"

typedef __m128i ssereg;

#ifdef __SSSE3__
#include <tmmintrin.h>
static const ssereg shuffle8  = { 0x0605040702010003ull, 0x0E0D0C0F0A09080Bull };
static const ssereg shuffle16 = { 0x0504070601000302ull, 0x0D0C0F0E09080B0Aull };
#define PSHUFB(x,y) _mm_shuffle_epi8(x,y)
#endif

#define ADD _mm_add_epi32
#define ADD64 _mm_add_epi64
#define XOR _mm_xor_si128
#define LOAD(x) _mm_loadu_si128(&x)
#define STORE(x,y) _mm_storeu_si128(&x,y)
#define SHUFFLE(x,i) _mm_shuffle_epi32(x, \
  i + ((i+1)&3)*4 + ((i+2)&3)*16 + ((i+3)&3)*64)

static inline ssereg
rotate(const ssereg &a, int amount) {
  return ADD(_mm_slli_epi32(a, amount), _mm_srli_epi32(a, 32-amount));
}


static inline void
quarter_round(ssereg &a, ssereg &b, ssereg &c, ssereg &d) {
#ifdef __SSSE3__
  a = ADD(a,b); d = PSHUFB(XOR(d,a), shuffle16);
  c = ADD(c,d); b = rotate(XOR(b,c), 12);
  a = ADD(a,b); d = PSHUFB(XOR(d,a), shuffle8);
  c = ADD(c,d); b = rotate(XOR(b,c), 7);
#else
  a = ADD(a,b); d = rotate(XOR(d,a), 16);
  c = ADD(c,d); b = rotate(XOR(b,c), 12);
  a = ADD(a,b); d = rotate(XOR(d,a), 8);
  c = ADD(c,d); b = rotate(XOR(b,c), 7);
#endif
}

void chacha_expand(const unsigned char *key_,
                   u_int64_t iv,
                   u_int64_t ctr,
                   int nr,
                   int niter,
                   unsigned char *output_) {
  ssereg *key = (ssereg *)key_;
  ssereg *output = (ssereg *)output_;
                   
  ssereg a1 = LOAD(key[0]), a2 = a1, aa = a1,
         b1 = LOAD(key[1]), b2 = b1, bb = b1,
         c1 = {iv, ctr}, c2 = {iv, ctr+1}, cc = c1,
         d1 = {0x3320646e617080ull, 0x6b20657479622d32ull}, d2 = d1, dd = d1,
         p = {0, 1};
   
  int i,r;
  for (i=0; i<niter; i+=2) {
    for (r=nr; r>0; r-=2) {
    
      quarter_round(a1,b1,c1,d1);
      quarter_round(a2,b2,c2,d2);
      b1 = SHUFFLE(b1,1);
      c1 = SHUFFLE(c1,2);
      d1 = SHUFFLE(d1,3);
      b2 = SHUFFLE(b2,1);
      c2 = SHUFFLE(c2,2);
      d2 = SHUFFLE(d2,3);
      
      quarter_round(a1,b1,c1,d1);
      quarter_round(a2,b2,c2,d2);
      b1 = SHUFFLE(b1,3);
      c1 = SHUFFLE(c1,2);
      d1 = SHUFFLE(d1,1);
      b2 = SHUFFLE(b2,3);
      c2 = SHUFFLE(c2,2);
      d2 = SHUFFLE(d2,1);
    }

    STORE(output[0], ADD(a1,aa));
    STORE(output[1], ADD(b1,bb));
    STORE(output[2], ADD(c1,cc));
    STORE(output[3], ADD(d1,dd));
    STORE(output[4], ADD(a2,aa));
    STORE(output[5], ADD(b2,bb));
    STORE(output[6], ADD(c2,ADD(cc,p)));
    STORE(output[7], ADD(d2,dd));
    output += 8;
    
    cc = ADD64(ADD64(cc,p), p);
    a1 = a2 = aa;
    b1 = b2 = bb;
    c1 = cc; c2 = ADD64(cc,p);
    d1 = d2 = dd;
  } 
}

