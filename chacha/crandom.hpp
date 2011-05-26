#ifndef __CRANDOM_H__
#define __CRANDOM_H__

#include <sys/types.h>

#include <strings.h>
#include <string.h>
#include <unistd.h>

#ifndef likely
#  define likely(x)       __builtin_expect((x),1)
#  define unlikely(x)     __builtin_expect((x),0)
#endif

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
  
  // fast but slightly wasteful cases: one random element
  template<class T> inline
  T random() {
    if (fill < sizeof(T)) refill();
    fill -= sizeof(T);
    T *buf = (T *)(&buffer[fill]);
    T out = *buf;
    *buf = 0;
    return out;
  }
  
  template<class T> T random(T min, T max);
  
  template<class integer>
  void permutation(integer *elements, u_int32_t n);
  
  /*
  template<class it> void
  permute(it elements, u_int32_t n) {
    u_int32_t i;
    for (i=1; i<n; i++) {
      u_int32_t j = random<u_int32_t>(0,i);
      decltype(elements[i]) tmp = elements[i];
      elements[i] = elements[j];
      elements[j] = tmp;
    }
  }
  */
  
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

class chacha_generator : public generator_base {
public:
  chacha_generator(u_int32_t buffer_size = 1024,
                   bool is_deterministic = true)
    : generator_base((buffer_size + 127) & -128, is_deterministic, 32)
    , ctr(0) {}

protected:
  u_int64_t ctr;
  virtual void refill();
};

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
  auto_seeded(u_int32_t buffer_size = 1024, u_int32_t reseed_interval_ = 10000)
    : gen(buffer_size, false), reseeds_remaining(0), reseed_interval(reseed_interval_) {}

protected:
  virtual void stir();
  virtual void refill();
  
  dev_random_handle dev;
  u_int32_t reseeds_remaining;
  const u_int32_t reseed_interval;
};

} // namespace crandom

#endif // __CRANDOM_H__
