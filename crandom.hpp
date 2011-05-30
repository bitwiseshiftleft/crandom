#ifndef __CRANDOM_H__
#define __CRANDOM_H__

#include "intrinsics.h"

#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <algorithm>
#include <math.h>

namespace crandom {

typedef          int   int128_t __attribute__((mode(TI)));
typedef unsigned int u_int128_t __attribute__((mode(TI)));

class generator_base {
public:
  ~generator_base();

  // slow case: fill a buffer with randomness
  void randomize_slow_case(unsigned char *output, size_t n);
  void randomize(unsigned char *output, size_t n) {
    if (unlikely(!fill)) refill();
    if (likely(fill >= n)) {
      fill -= (u_int32_t)n;
      
      // the compiler understands memcpy
      memcpy(output, buffer+fill, n);
      bzero(buffer+fill, n);
      return;
    }
    randomize_slow_case(output, n);
  }
  
  template<class T>
  void randomize(T &out) {
    randomize((unsigned char *) &out, sizeof(out));
  }
  
  template<class T> inline
  T random() {
    T out;
    randomize(out);
    return out;
  }
  
  template<class T> T random(T min, T max);
  
  template<class integer>
  void permutation(integer *elements, u_int32_t n);
  
  template<class it> void
  permute(it elements, u_int32_t n) {
    u_int32_t i;
    for (i=1; i<n; i++) {
      u_int32_t j = random<u_int32_t>(0,i);
      std::swap(elements[i], elements[j]);
    }
  }
  
  // stir in entropy
  // ... from a buffer
  void stir(const unsigned char *entropy, size_t n);
  
  // ... from an object
  template<class T>
  inline void stir(const T &x) {
    stir((const unsigned char *) &x, sizeof(x));
  }
  
  // ... from /dev/u?random
  virtual void stir() {}
  
protected:
  generator_base(u_int32_t buffer_size,
                 bool is_deterministic,
                 u_int32_t key_size);
  
  // refill the buffer using the key
  virtual void refill() = 0;
  
  inline unsigned char *key() {
    return (unsigned char *)(buffer) + buffer_size - key_size;
  }
  
  const u_int32_t buffer_size;
  const u_int32_t key_size;
  const bool is_deterministic;
  
  u_int32_t fill;
  unsigned char *buffer;
};

template<class prg>
class prg_generator : public generator_base {
public:
  prg_generator(bool is_deterministic = true)
    : generator_base(prg::output_size, is_deterministic, prg::input_size)
    , ctr(0) {}

  virtual void refill() {
    u_int64_t iv = is_deterministic ? 0 : rdtsc();
    prg::expand(iv, ctr, key(), buffer);
    fill = buffer_size - key_size;
  }

protected:
  u_int64_t ctr;
};

template<> inline
float generator_base::random<float>() {
  // return scalblnf(random<u_int32_t>(), -32);
  // This seems to work around a bug in GCC on the Mac:
  union { float f; u_int32_t i; } out;
  out.i = (random<u_int32_t>() >> 9) | 0x3f800000;
  return out.f - 1.0;
}

template<> inline
float generator_base::random<float>(float min, float max) {
  return min + (max-min) * random<float>();
}

template<> inline
double generator_base::random<double>() {
  // return scalbln(random<u_int64_t>(), -64);
  union { double f; u_int64_t i; } out;
  out.i = (random<u_int64_t>() >> 12) | 0x3ff0000000000000ull;
  return out.f - 1.0;
}

template<> inline
double generator_base::random<double>(double min, double max) {
  return min + (max-min) * random<double>();
}

class dev_random_handle {
public:
  dev_random_handle(const char *filename = "/dev/urandom");
  dev_random_handle(const dev_random_handle &h);
  ~dev_random_handle();
  const int fd;
private:
  volatile int *const ref;
};

template <class gen>
class auto_seeded : public gen {
public:
  auto_seeded(u_int32_t reseed_interval_ = 10000)
    : gen(false), reseeds_remaining(0), reseed_interval(reseed_interval_) {}

protected:
  virtual void stir();
  virtual void refill();
  
  dev_random_handle dev;
  u_int32_t reseeds_remaining;
  const u_int32_t reseed_interval;
};

} // namespace crandom

#endif // __CRANDOM_H__

