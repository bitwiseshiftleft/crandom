#include <xmmintrin.h>
#include <stdio.h>

typedef __m128i block;
#define shift4(_x) _mm_slli_si128(_x,4)
#define shift8(_x) _mm_slli_si128(_x,8)
#define pslldq _mm_slli_epi32
#define int2block _mm_cvtsi64_si128
#define shuffle _mm_shuffle_epi32

void pvec(const block &x) {
  for(int i=0; i<16; i++) {
    printf("%02x", ((unsigned char *) &x)[i]);
    if ((i&3) == 3) printf(" ");
  }
  printf("\n");
}

inline block
assist0 (const block &in) {
  block out;
  asm ( "aeskeygenassist $0, %[in], %[out]"
      : [out]"=x"(out) : [in]"xm"(in)
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
  asm ( "aesenc %[subkey], %[bl]"
      : [bl]"+x"(bl) : [subkey]"x"(subkey)
      );
}

inline void __attribute__((__gnu_inline__, __always_inline__))
aes_enc_last (const block &subkey, block &bl) {
  asm ( "aesenclast %[subkey], %[bl]"
      : [bl]"+x"(bl) : [subkey]"x"(subkey)
      );
}

const int N=8;

void aes256(unsigned long long iv, const block key[2], block data[N]) {
  block x = key[0], z=key[1], rc={0,0x100000000};
    
  for (int i=0; i<N; i++)
    data[i] = int2block(iv + i) ^ x;
  
  block
    data0 = data[0],
    data1 = data[1],
    data2 = data[2],
    data3 = data[3],
    data4 = data[4],
    data5 = data[5],
    data6 = data[6],
    data7 = data[7];
  
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
    t = shuffle(t ^ rc, 0xff);
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

int main(int argc, char **argv) {
  block x[N] = {0,0,0,0,0,0,0,0};
  unsigned long long iv = 0;
  for (int i=0; i<1000000; i++) {
    aes256(iv,x,x);
    iv += N;
  }
  pvec(x[7]);
  return 0;
}
