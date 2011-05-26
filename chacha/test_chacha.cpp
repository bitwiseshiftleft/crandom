#include "chacha.hpp"
#include <stdio.h>
#include <sys/time.h>

using namespace crandom;

static volatile inline double
now() {
  struct timeval tp;
  gettimeofday(&tp, 0);
  return tp.tv_sec + double(tp.tv_usec)/1000000;
}

int main(int argc, char **argv) {
  (void) argc; (void) argv;
  
  const int output_size = 128;
  const int rounds = 12;
  
  unsigned char key[32], output[output_size];
  int i;
  for (i=0; i<32; i++) {
    key[i] = 0;
  }
  
  double start=now();
  for (i=0; i<1000000; i++) {
    chacha_expand(key, 0, i, rounds, output_size, output);
  }
  start = now() - start;
  printf("chacha/%d: %0.1f MB / %0.3f sec = %0.1f MB/sec\nchecksum = ",
         rounds,
         i * output_size / 1000000.0,
         start,
         i * output_size / 1000000.0 / start);
  for (i=0; i<16; i++) {
    printf("%02x", output[i]);
    if ((i&3)==3) printf(" ");
  }
  printf("\n");
  return 0;
}
