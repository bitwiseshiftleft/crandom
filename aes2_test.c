#include <stdio.h>

extern "C" volatile void aes_refill(unsigned long long iv, unsigned long long ivhi, char data[128]);

int main(int argc, char **argv) {
  unsigned long long iv = 0;
  char data[128];
  for (int i=0; i<128; i++) data[i] = 0;
  for (int i=0; i<1000000; i++) {
    aes_refill(iv, 0, data);
    iv += 8;
  }
  printf("%llx\n", *(unsigned long long *)data);
}