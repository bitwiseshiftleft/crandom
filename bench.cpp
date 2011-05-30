#include "chacha.hpp"
#include "aes.hpp"
#include <stdio.h>
#include <sys/time.h>

#include "intrinsics.h"

using namespace crandom;

static inline double
now() {
  struct timeval tp;
  gettimeofday(&tp, 0);
  return tp.tv_sec + double(tp.tv_usec)/1000000;
}

void print_features(unsigned int features) {
  printf("features:%s%s%s%s\n",
         (features & SSE2)  ? " SSE2"  : "",
         (features & SSSE3) ? " SSSE3" : "",
         (features & AESNI) ? " AESNI" : "",
         (features & XOP)   ? " XOP"   : "");
}

template<class generator, unsigned int new_features, unsigned int of_features>
void test(int n) {
  unsigned int old_features = crandom_features,
    good = HAVE(new_features) && ((new_features & MUST_MASK) == (MUST_MASK & of_features));
  crandom_features = (crandom_features & ~of_features) | new_features | 1;
  print_features(new_features);
  
  if (good) {
    unsigned char key[generator::input_size], output[generator::output_size];
    int i;
    u_int64_t iv=0, ctr=0;
    for (i=0; i<32; i++) {
      key[i] = 0;
    }
    
    double start=now();
    for (i=0; i<n; i++) {
      generator::expand(iv, ctr, key, output);
    }
    start = now() - start;
    
    printf("%s: %0.1f MB / %0.3f sec = %0.1f MB/sec\nchecksum = ",
           generator::get_name().c_str(),
           i * generator::output_size / 1000000.0,
           start,
           i * generator::output_size / 1000000.0 / start);
    for (i=0; i<16; i++) {
      printf("%02x", output[i]);
      if ((i&3)==3) printf(" ");
    }
    printf("\n\n");
  } else {
    printf("(unsupported)\n\n");
  }
  
  crandom_features = old_features;
}

int main(int argc, char **argv) {
  (void) argc; (void) argv;
  crandom_features = crandom_detect_features();
  
  test<chacha, SSE2 | SSSE3 | XOP, SSE2 | SSSE3 | XOP>(1000000);
  test<chacha, SSE2 | SSSE3, SSE2 | SSSE3 | XOP>(1000000);
  test<chacha, SSE2, SSE2 | SSSE3 | XOP>(1000000);
  test<chacha, 0, SSE2 | SSSE3 | XOP>(1000000);
  
  test<aes, AESNI, AESNI>(1000000);
  test<aes, 0, AESNI>(1000000);
  
  return 0;
}
