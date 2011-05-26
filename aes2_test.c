#include <stdio.h>

extern "C" volatile void aes_expand(unsigned long long iv, unsigned long long ivhi, unsigned char key[32], unsigned char data[128]);

int main(int argc, char **argv) {
  unsigned long long iv = 0;
  unsigned char data[128];
  for (int i=0; i<128; i++) data[i] = 0;
  for (int i=0; i<10000000; i++) {
    aes_expand(iv, 0, data, data);
    iv += 8;
  }
  printf("%llx\n", *(unsigned long long *)data);
}