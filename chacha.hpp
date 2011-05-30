#ifndef __CHACHA_H__
#define __CHACHA_H__

#include <sys/types.h>
#include <string>
#include <sstream>

// niter must be even
// output = 64*niter bytes
extern "C"
void crandom_chacha_expand(u_int64_t iv,
                           u_int64_t ctr,
                           int nr,
                           int output_size,
                           const unsigned char *key_,
                           unsigned char *output_);

namespace crandom {

template<int nr, int buffer_size>
class v_chacha {
public:
  static const int input_size = 32;
  static const int output_size = buffer_size;
  
  static std::string get_name() {
    std::stringstream str;
    str << "chacha/" << nr << "[" << buffer_size << "]";
    return str.str();
  }
  
  static void expand(u_int64_t iv,
                     u_int64_t &ctr,
                     const unsigned char input[input_size],
                     unsigned char output[output_size]) {
    crandom_chacha_expand(iv, ctr, nr, output_size, input, output);
    ctr += output_size/64;
  }
};

typedef class v_chacha<12, 128> chacha;

}

#endif // __CHACHA_H__

