#include <string.h>
#include "cryptlib.h"
#include "modes.h"
#include "aes.h"
#include <stdio.h>

using namespace CryptoPP;

extern "C" void aes_expand(
  unsigned long long iv,
  unsigned long long ctr,
  const unsigned char key[32],
  unsigned char data[128]) {
  
  unsigned long long inputs[16];
  for (int i=0; i<8; i++) {
    inputs[2*i] = ctr+i;
    inputs[2*i+1] = iv;
  }
  
  ECB_Mode<AES>::Encryption e;
  e.SetKey(key, 32);
  for (int i=0; i<128; i++) {
    printf("%02x", ((const byte *)inputs)[i]);
  }
  printf("\n");
  e.ProcessData(data, (const byte *)inputs, 128);
  for (int i=0; i<128; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}