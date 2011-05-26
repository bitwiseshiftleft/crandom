#include "chacha.hpp"
#include <stdio.h>

int main(int argc, char **argv) {
  unsigned char key[32], output[1024];
  int i;
  for (i=0; i<32; i++) {
    key[i] = 0;
  }
  for (i=0; i<1000000; i++) {
    chacha_expand(key, 0, i, 12, 128/64, output);
  }
  /*
  for (i=0; i<1024; i++) {
    printf("%02x", output[i]);
    if (!((i+1) & 31))
      printf("\n");
  }
  */
  return 0;
}
