#include "crandom.hpp"
#include "chacha.hpp"
#include "aes.hpp"
#include <stdio.h>
#include <stdlib.h>

using namespace crandom;

int main(int argc, char **argv) {
  (void) argc; (void) argv;
  
  prg_generator<chacha> gen(false);

  u_int32_t y=0, perm[100];
  (void) y;

  for (int i=0; i<1000000; i++) {
    //gen.random<u_int128_t>();
    //random();    

    //printf("%d\n", gen.random<u_int32_t>(0,9));
    gen.permutation(perm, 100);
    //for (int j=0; j<20; j++) {
    //  printf("%d ", perm[j]);
    //}
    //printf("\n");
    
    //u_int32_t x;
    //gen.randomize(x);
    //y += x;
  }
  //printf("%x\n", y);

  return 0;
}


