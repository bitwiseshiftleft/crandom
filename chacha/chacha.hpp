#ifndef __CHACHA_H__
#define __CHACHA_H__

#include <sys/types.h>

namespace crandom {

// niter must be even
// output = 64*niter bytes
void chacha_expand(const unsigned char *key_,
                   u_int64_t iv,
                   u_int64_t ctr,
                   int nr,
                   int output_size,
                   unsigned char *output_);

template<int nr=12, int buffer_size=128>
class chacha {
public:
  static const int key_size = 32;
  
  unsigned char key[key_size] __attribute__ ((aligned (16) ));
  unsigned char buffer[buffer_size - key_size];
  
  void expand(u_int64_t iv, u_int64_t &ctr) {
    chacha_expand(key, iv, ctr, nr, buffer_size, buffer);
    ctr += buffer_size/64;
  }
};

}

#endif // __CHACHA_H__

