#include "crandom.hpp"
#include "chacha.hpp"
#include "aes.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "intrinsics.h"

static inline double
now() {
  struct timeval tp;
  gettimeofday(&tp, 0);
  return tp.tv_sec + double(tp.tv_usec)/1000000;
}

void print_features(unsigned int features) {
  printf("   w/%s%s%s%s%s\n",
         (features) ? "" : "??",
         (features & SSE2)  ? " SSE2"  : "",
         (features & SSSE3) ? " SSSE3" : "",
         (features & AESNI) ? " AESNI" : "",
         (features & XOP)   ? " XOP"   : "");
}

using namespace crandom;

template<class gen, class t>
void test(int n, unsigned int new_features, unsigned int of_features, gen *generator) {
  unsigned int old_features = crandom_features,
    good = HAVE(new_features) && ((new_features & MUST_MASK) == (MUST_MASK & of_features));
  int i;
  crandom_features = (crandom_features & ~of_features) | new_features | 1;
  print_features(crandom_features);
  
  if (good) {
    double start=now();
    for (i=0; i<n; i++) {
       generator->template random<t>();
    }
    start = now() - start;
    
    printf("%0.1f ME (%0.1f MB) / %0.3f sec = %0.1f MB/sec",
           i / 1000000.0,
           i * sizeof(t) / 1000000.0,
           start,
           i * sizeof(t) / 1000000.0 / start);
    printf("\n\n");
  } else {
    printf("(unsupported)\n\n");
  }
  
  crandom_features = old_features;
}

void test_rand(int n) {
  int i;
  double start=now();
  for (i=0; i<n; i++) {
    rand();
  }
  start = now() - start;
  
  printf("%0.1f ME (%0.1f MB) / %0.3f sec = %0.1f MB/sec",
         i / 1000000.0,
         i * sizeof(int) / 1000000.0,
         start,
         i * sizeof(int) / 1000000.0 / start);
  printf("\n\n");
}

void test_random(int n) {
  int i;
  double start=now();
  for (i=0; i<n; i++) {
    random();
  }
  start = now() - start;
  
  printf("%0.1f ME (%0.1f MB) / %0.3f sec = %0.1f MB/sec",
         i / 1000000.0,
         i * sizeof(int) / 1000000.0,
         start,
         i * sizeof(int) / 1000000.0 / start);
  printf("\n\n");
}

#ifdef __MAC_10_0
void test_arc4random(int n) {
  int i;
  double start=now();
  for (i=0; i<n; i++) {
    arc4random();
  }
  start = now() - start;
  
  printf("%0.1f ME (%0.1f MB) / %0.3f sec = %0.1f MB/sec",
         i / 1000000.0,
         i * sizeof(int) / 1000000.0,
         start,
         i * sizeof(int) / 1000000.0 / start);
  printf("\n\n");
}
#endif

void test_drand48(int n) {
  int i;
  double start=now();
  for (i=0; i<n; i++) {
    drand48();
  }
  start = now() - start;
  
  printf("%0.1f ME (%0.1f MB) / %0.3f sec = %0.1f MB/sec",
         i / 1000000.0,
         i * 6 / 1000000.0,
         start,
         i * 6 / 1000000.0 / start);
  printf("\n\n");
}


int main(int argc, char **argv) {
  (void) argc; (void) argv;
  
  crandom_features = crandom_detect_features();
  
  unsigned int chacha_features = SSE2 | SSSE3 | XOP, aes_features = AESNI;
  
  prg_generator<chacha> *ch = new prg_generator<chacha>(true);
  prg_generator<aes> *ae = new prg_generator<aes>(true);
  printf("****** Generators and processor features ******\n\n");
  
  printf("chacha, direct, u_int32_t");
  test<prg_generator<chacha>, u_int32_t>(100000000, SSE2 | SSSE3 | XOP, chacha_features, ch);
  printf("chacha, direct, u_int32_t");
  test<prg_generator<chacha>, u_int32_t>(100000000, SSE2 | SSSE3, chacha_features, ch);
  printf("chacha, direct, u_int32_t");
  test<prg_generator<chacha>, u_int32_t>(100000000, SSE2, chacha_features, ch);
  printf("chacha, direct, u_int32_t");
  test<prg_generator<chacha>, u_int32_t>(10000000, 0, chacha_features, ch);
  
  printf("aes, direct, u_int32_t");
  test<prg_generator<aes>, u_int32_t>(100000000, AESNI, aes_features, ae);
  printf("aes, direct, u_int32_t");
  test<prg_generator<aes>, u_int32_t>(10000000, 0, aes_features, ae);
  
  printf("rand, int\n");
  test_rand(100000000);
  
  printf("random, int\n");
  test_random(100000000);
  
  #ifdef __MAC_10_0
    printf("arc4random, int\n");
    test_arc4random(10000000);
  #endif
  
  printf("drand48, int\n");
  test_drand48(10000000);
  
  printf("****** Data sizes ******\n\n");
  
  printf("chacha, direct, u_int128_t");
  test<prg_generator<chacha>, u_int128_t>(100000000, 0, 0, ch);
  printf("chacha, direct, u_int8_t");
  test<prg_generator<chacha>, u_int8_t>(100000000, 0, 0, ch);
  printf("chacha, direct, float");
  test<prg_generator<chacha>, float>(100000000, 0, 0, ch);
  printf("chacha, direct, double");
  test<prg_generator<chacha>, double>(100000000, 0, 0, ch);
  printf("aes, direct, u_int128_t");
  test<prg_generator<aes>, u_int128_t>(100000000, AESNI, aes_features, ae);
  printf("aes, direct, u_int8_t");
  test<prg_generator<aes>, u_int8_t>(100000000, 0, 0, ae);
  
  printf("****** Indirection ******\n\n");
  
  printf("aes, indirect, u_int32_t");
  test<generator_base, u_int32_t>(100000000, 0, 0,
    opacify(1) ? static_cast<generator_base *>(ae) : static_cast<generator_base *>(ch));
  printf("chacha, indirect, u_int32_t");
  test<generator_base, u_int32_t>(100000000, 0, 0,
    opacify(1) ? static_cast<generator_base *>(ch) : static_cast<generator_base *>(ae));
  
  return 0;
}


