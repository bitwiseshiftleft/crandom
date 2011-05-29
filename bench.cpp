#include "chacha.hpp"
#include "aes.hpp"
#include <stdio.h>
#include <sys/time.h>

using namespace crandom;

static volatile inline double
now() {
  struct timeval tp;
  gettimeofday(&tp, 0);
  return tp.tv_sec + double(tp.tv_usec)/1000000;
}

template<class generator>
void test(int n) {
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
         i * generator::output_size / double(n),
         start,
         i * generator::output_size / double(n) / start);
  for (i=0; i<16; i++) {
    printf("%02x", output[i]);
    if ((i&3)==3) printf(" ");
  }
  printf("\n\n");
}

int main(int argc, char **argv) {
  (void) argc; (void) argv;
  
  test<chacha>(1000000);
  test<aes>(1000000);
  
  return 0;
}
