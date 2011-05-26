#include <xmmintrin.h>
#include <stdio.h>

typedef __m128i block;
#define shift4(_x) _mm_slli_si128(_x,4)
#define shift8(_x) _mm_slli_si128(_x,8)
#define pslldq _mm_slli_epi32
#define int2block _mm_cvtsi64_si128
#define shuffle _mm_shuffle_epi32

inline volatile block
assist0 (const block &in) {
  block out;
  asm __volatile__
      ( "aeskeygenassist $0, %[in], %[out]"
      : [out]"=x"(out) : [in]"x"(in)
      );
  return out;
}

inline block
assistU (const block &in, block &rc) {
  block out = assist0(in) ^ rc;
  rc = pslldq(rc,1);
  return out;
}

inline void __attribute__((__gnu_inline__, __always_inline__))
aes_enc (const block &subkey, block &bl) {
  asm __volatile__
      ( "aesenc %[subkey], %[bl]"
      : [bl]"+x"(bl) : [subkey]"x"(subkey)
      );
}

inline void __attribute__((__gnu_inline__, __always_inline__))
aes_enc_last (const block &subkey, block &bl) {
  asm __volatile__
      ( "aesenclast %[subkey], %[bl]"
      : [bl]"+x"(bl) : [subkey]"x"(subkey)
      );
}

const int N=8;

extern "C" void aes_expand(unsigned long long iv, unsigned long long ctr, const block key[2], block data[N]) {
  (void) ctr;
  block x = key[0], z=key[1], rc={1,0}, tmp = { 0, iv };
  
  block
    data0 = { ctr, 0 },
    data1 = { ctr+1, 0 },
    data2 = { ctr+2, 0 },
    data3 = { ctr+3, 0 },
    data4 = { ctr+4, 0 },
    data5 = { ctr+5, 0 },
    data6 = { ctr+6, 0 },
    data7 = { ctr+7, 0 };
    
  tmp ^= x;
  data0 ^= tmp;
  data1 ^= tmp;
  data2 ^= tmp;
  data3 ^= tmp;
  data4 ^= tmp;
  data5 ^= tmp;
  data6 ^= tmp;
  data7 ^= tmp;
  
  for (int i=7;;) {
    block t = assist0(z), u;
    aes_enc(z, data0);
    aes_enc(z, data1);
    aes_enc(z, data2);
    aes_enc(z, data3);
    aes_enc(z, data4);
    aes_enc(z, data5);
    aes_enc(z, data6);
    aes_enc(z, data7);
    t = shuffle(t, 0xff);
    x ^= rc;
    rc = pslldq(rc,1);
    u = shift4(x); x ^= u;
    u = shift4(u); x ^= u;
    u = shift4(u); x ^= u;
    x ^= t;
    
    if (!--i) break;
    
    t = assist0(x);
    aes_enc(x, data0);
    aes_enc(x, data1);
    aes_enc(x, data2);
    aes_enc(x, data3);
    aes_enc(x, data4);
    aes_enc(x, data5);
    aes_enc(x, data6);
    aes_enc(x, data7);
    t = shuffle(t, 0xaa);
    u = shift4(z); z ^= u;
    u = shift4(u); z ^= u;
    u = shift4(u); z ^= u;
    z ^= t;
  }
  
  aes_enc_last(x, data0); data[0] = data0;
  aes_enc_last(x, data1); data[1] = data1;
  aes_enc_last(x, data2); data[2] = data2;
  aes_enc_last(x, data3); data[3] = data3;
  aes_enc_last(x, data4); data[4] = data4;
  aes_enc_last(x, data5); data[5] = data5;
  aes_enc_last(x, data6); data[6] = data6;
  aes_enc_last(x, data7); data[7] = data7;
}