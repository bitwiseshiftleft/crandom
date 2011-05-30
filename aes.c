#include <string.h>
#include "intrinsics.h"

#if MIGHT_HAVE(AESNI)
// ----------------------------------- AES-NI version -----------------------------------

#define shift4(_x) _mm_slli_si128(_x,4)

static inline void
crandom_aes_expand_aesni(u_int64_t iv,
                         u_int64_t ctr,
                         const unsigned char *key_,
                         unsigned char *data_) {
  int i;
  const ssereg *key = (const ssereg *) key_;
  ssereg *data = (ssereg *) data_;
  
  ssereg x = key[0], z=key[1], rc={1,0}, tmp={0, iv},
    data0={ctr,   0}, data1={ctr+1, 0}, data2={ctr+2, 0}, data3={ctr+3, 0},
    data4={ctr+4, 0}, data5={ctr+5, 0}, data6={ctr+6, 0}, data7={ctr+7, 0};
    
  tmp ^= x;
  data0 ^= tmp; data1 ^= tmp; data2 ^= tmp; data3 ^= tmp;
  data4 ^= tmp; data5 ^= tmp; data6 ^= tmp; data7 ^= tmp;
  
  for (i=7;;) {
    ssereg t = aeskeygenassist(0,z), u;
    data0 = aesenc(z, data0);
    data1 = aesenc(z, data1);
    data2 = aesenc(z, data2);
    data3 = aesenc(z, data3);
    data4 = aesenc(z, data4);
    data5 = aesenc(z, data5);
    data6 = aesenc(z, data6);
    data7 = aesenc(z, data7);
    t = pshufd(t, 0xff);
    x ^= rc;
    rc = pslldq(rc,1);
    u = shift4(x); x ^= u;
    u = shift4(u); x ^= u;
    u = shift4(u); x ^= u;
    x ^= t;
    
    if (!--i) break;
    
    t = aeskeygenassist(0,x);
    data0 = aesenc(x, data0);
    data1 = aesenc(x, data1);
    data2 = aesenc(x, data2);
    data3 = aesenc(x, data3);
    data4 = aesenc(x, data4);
    data5 = aesenc(x, data5);
    data6 = aesenc(x, data6);
    data7 = aesenc(x, data7);
    t = pshufd(t, 0xaa);
    u = shift4(z); z ^= u;
    u = shift4(u); z ^= u;
    u = shift4(u); z ^= u;
    z ^= t;
  }
  
  data[0] = aesenclast(x, data0);
  data[1] = aesenclast(x, data1);
  data[2] = aesenclast(x, data2);
  data[3] = aesenclast(x, data3);
  data[4] = aesenclast(x, data4);
  data[5] = aesenclast(x, data5);
  data[6] = aesenclast(x, data6);
  data[7] = aesenclast(x, data7);
}
#endif // __AES__

// ----------------------------------- non-AES-NI version -----------------------------------
#if (!MUST_HAVE(AESNI))

#ifndef USE_SMALL_TABLES
#  define USE_SMALL_TABLES 1
#endif

static const u_int8_t crandom_aes_sbox[256] = 
{
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
   0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
   0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
   0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
   0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
   0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
   0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
   0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
   0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
   0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
   0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
   0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
   0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
   0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
   0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
   0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
   0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static u_int32_t crandom_aes_tbox[USE_SMALL_TABLES ? 256 : 1024];

static inline u_int32_t rotate(u_int32_t r, u_int32_t x) {
  return x<<r ^ x>>(32-r);
}

static inline u_int32_t T(int table, u_int8_t x) {
  if (USE_SMALL_TABLES) {
    u_int32_t y = crandom_aes_tbox[x];
    if (table) {
      return rotate(32-8*table, y);
    } else {
      return y;
    }
  } else {
    return crandom_aes_tbox[table*256 + x];
  }
}

static void
fill_t_tables() {
  int i,j;
  for (i=0; i<256; i++) {
    u_int32_t si = crandom_aes_sbox[i], dsi = (si<<1) ^ (si>>7)*283;
    u_int32_t tt = si * 0x10101ul ^ dsi * 0x1010000ul;
    for (j=0; j < (USE_SMALL_TABLES ? 1 : 4); j++, tt = tt<<24 ^ tt>>8)
      crandom_aes_tbox[j*256 + i] = tt;
  }
}

typedef struct block { u_int32_t a,b,c,d; } block;

static inline u_int32_t
assist0 (u_int32_t d) {
  const u_int8_t *s = crandom_aes_sbox;
  return s[d>>24]<<24 ^ s[d>>16&0xff]<<16 ^ s[d>>8&0xff]<<8 ^ s[d&0xff];
}

static inline u_int32_t
assist1 (u_int32_t d) {
  const u_int8_t *s = crandom_aes_sbox;
  return s[d>>24]<<16 ^ s[d>>16&0xff]<<8 ^ s[d>>8&0xff] ^ s[d&0xff]<<24;
}

static void
aes_enc(const block subkey, block *bl) {
  u_int32_t a=bl->a, b=bl->b, c=bl->c, d=bl->d;
  bl->a = T(0,d>>24) ^ T(1,c>>16&0xff) ^ T(2,b>>8&0xff) ^ T(3,a&0xff) ^ subkey.a;
  bl->b = T(0,a>>24) ^ T(1,d>>16&0xff) ^ T(2,c>>8&0xff) ^ T(3,b&0xff) ^ subkey.b;
  bl->c = T(0,b>>24) ^ T(1,a>>16&0xff) ^ T(2,d>>8&0xff) ^ T(3,c&0xff) ^ subkey.c;
  bl->d = T(0,c>>24) ^ T(1,b>>16&0xff) ^ T(2,a>>8&0xff) ^ T(3,d&0xff) ^ subkey.d;
}

static void
aes_enc_last(const block subkey, block *bl) {
  const u_int8_t *s = crandom_aes_sbox;
  u_int32_t a=bl->a, b=bl->b, c=bl->c, d=bl->d;
  bl->a = s[d>>24]<<24 ^ s[c>>16 & 0xff]<<16 ^ s[b>>8 & 0xff]<<8 ^ s[a & 0xff] ^ subkey.a;
  bl->b = s[a>>24]<<24 ^ s[d>>16 & 0xff]<<16 ^ s[c>>8 & 0xff]<<8 ^ s[b & 0xff] ^ subkey.b;
  bl->c = s[b>>24]<<24 ^ s[a>>16 & 0xff]<<16 ^ s[d>>8 & 0xff]<<8 ^ s[c & 0xff] ^ subkey.c;
  bl->d = s[c>>24]<<24 ^ s[b>>16 & 0xff]<<16 ^ s[a>>8 & 0xff]<<8 ^ s[d & 0xff] ^ subkey.d;
}

static const int N=8;

static inline void
crandom_aes_expand_conventional(u_int64_t iv,
                                u_int64_t ctr,
                                const unsigned char *key_,
                                unsigned char *data_) {
  /* FIXME thread safety */
  static int t_tables_full = 0;
  if (!t_tables_full) {
    fill_t_tables();
    t_tables_full = 1;
  }
  
  const block *key = (const block *) key_;
  block *data = (block *) data_;

  block x = key[0], z=key[1];
  
  int i;

  for (i=0; i<N; i++) {
    data[i] = x;
    data[i].a ^= ctr + i;
    data[i].b ^= ctr >> 32;
    data[i].c ^= iv;
    data[i].d ^= iv >> 32;
  }
  
  block
    data0 = data[0],
    data1 = data[1],
    data2 = data[2],
    data3 = data[3],
    data4 = data[4],
    data5 = data[5],
    data6 = data[6],
    data7 = data[7];
    
  aes_enc(z, &data0);
  aes_enc(z, &data1);
  aes_enc(z, &data2);
  aes_enc(z, &data3);
  aes_enc(z, &data4);
  aes_enc(z, &data5);
  aes_enc(z, &data6);
  aes_enc(z, &data7);
  
  for (i=6;i;i--) {
    x.a ^= assist1(z.d) ^ 64>>i;
    x.b ^= x.a;
    x.c ^= x.b;
    x.d ^= x.c;
    
    z.a ^= assist0(x.d);
    z.b ^= z.a;
    z.c ^= z.b;
    z.d ^= z.c;
    
    aes_enc(x, &data0);  aes_enc(z, &data0);
    aes_enc(x, &data1);  aes_enc(z, &data1);
    aes_enc(x, &data2);  aes_enc(z, &data2);
    aes_enc(x, &data3);  aes_enc(z, &data3);
    aes_enc(x, &data4);  aes_enc(z, &data4);
    aes_enc(x, &data5);  aes_enc(z, &data5);
    aes_enc(x, &data6);  aes_enc(z, &data6);
    aes_enc(x, &data7);  aes_enc(z, &data7);
  }
  
  x.a ^= assist1(z.d) ^ 64;
  x.b ^= x.a;
  x.c ^= x.b;
  x.d ^= x.c;
  
  aes_enc_last(x, &data0); data[0] = data0;
  aes_enc_last(x, &data1); data[1] = data1;
  aes_enc_last(x, &data2); data[2] = data2;
  aes_enc_last(x, &data3); data[3] = data3;
  aes_enc_last(x, &data4); data[4] = data4;
  aes_enc_last(x, &data5); data[5] = data5;
  aes_enc_last(x, &data6); data[6] = data6;
  aes_enc_last(x, &data7); data[7] = data7;
}

#endif // !MUST_HAVE(AESNI)

extern_c void
crandom_aes_expand(u_int64_t iv,
                   u_int64_t ctr,
                   const unsigned char *key,
                   unsigned char *data) {
# if (MIGHT_HAVE(AESNI))
    if (HAVE(AESNI)) {
      crandom_aes_expand_aesni(iv, ctr, key, data);
      return;
    }
# endif
# if (!MUST_HAVE(AESNI))
    crandom_aes_expand_conventional(iv, ctr, key, data);
# endif
}