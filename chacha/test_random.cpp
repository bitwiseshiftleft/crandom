#include "crandom.hpp"
#include <stdio.h>
#include <stdlib.h>

using namespace crandom;

int main(int argc, char **argv) {
  (void) argc; (void) argv;
  
  //auto_seeded<chacha_generator> gen;
  chacha_generator gen(1024, false);

  u_int32_t y=0;

  for (int i=0; i<100; i++) {
    //gen.random<u_int128_t>();
    //random();    

    //printf("%d\n", gen.random<u_int32_t>(0,9));
    //gen.permutation(perm, 20);
    //for (int j=0; j<20; j++) {
    //  printf("%d ", perm[j]);
    // }
    u_int32_t x;
    gen.randomize(x);
    y += x;
  }
  printf("%x\n", y);

  return 0;
}


