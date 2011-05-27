#ifndef __AES_H__
#define __AES_H__

#include <sys/types.h>

namespace crandom {

void aes_expand(u_int64_t iv,
                u_int64_t ctr,
                const unsigned char *key_,
                unsigned char *output_);

class aes {
public:
  static const int input_size = 32;
  static const int output_size = 128;
  
  static std::string get_name() {
    return "aes256";
  }
  
  static void expand(u_int64_t iv,
                     u_int64_t &ctr,
                     const unsigned char input[input_size],
                     unsigned char output[output_size]) {
    aes_expand(iv, ctr, input, output);
    ctr += input_size/16;
  }
};

}

#endif // __AES_H__

