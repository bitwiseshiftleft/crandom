#include "crandom.hpp"
#include "chacha.hpp"
#include "aes.hpp"

#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

namespace crandom {

void *secure_malloc(size_t s) {
  // TODO
  return calloc(s, 1);
}

void secure_free(void *s) {
  // TODO
  free(s);
}

template<class T>
static inline u_int32_t prec(T x) {
  T out;
  asm("bsr %1, %0;\n" : "=r"(out) : "r"(x));
  return out;
}

template<u_int128_t>
static inline u_int32_t prec(u_int128_t x) {
  u_int64_t out;
  if (x >> 64) {
    return 64+prec<u_int64_t>(x>>64);
  } else {
    return prec<u_int64_t>(x);
  }
}

template<u_int128_t>
static inline int32_t prec(u_int128_t x) {
  return prec(u_int128_t(x));
}

template<class T>
static inline T prec_mask(T x) {
  if (x == 0) { return 0; }
  T offset = T(1) << prec(x);
  return offset + offset - 1;
} 

template<class T>
T generator_base::random(T min, T max) {
  if (min > max) {
    // todo
    throw 0;
  } else {
    T mask = prec_mask(max-min), x;
    do {
      x = (random<T>() & mask) + min;
    } while (x < min || x > max);
    return x;
  }
}

template int8_t     generator_base::random(int8_t     min, int8_t     max);
template int16_t    generator_base::random(int16_t    min, int16_t    max);
template int32_t    generator_base::random(int32_t    min, int32_t    max);
template int64_t    generator_base::random(int64_t    min, int64_t    max);
template int128_t   generator_base::random(int128_t   min, int128_t   max);
template u_int8_t   generator_base::random(u_int8_t   min, u_int8_t   max);
template u_int16_t  generator_base::random(u_int16_t  min, u_int16_t  max);
template u_int32_t  generator_base::random(u_int32_t  min, u_int32_t  max);
template u_int64_t  generator_base::random(u_int64_t  min, u_int64_t  max);
template u_int128_t generator_base::random(u_int128_t min, u_int128_t max);

// stir in entropy
// FIXME: should we use a hash here? probably...
void generator_base::stir
(const unsigned char *entropy, size_t n) {
  unsigned char *k = key();
  size_t i;
  while (n > 0) {
    for (i=0; i<n && i<key_size; i++) {
      k[i] ^= entropy[i];
    }
    n -= i;
    entropy += i;
    if (n > 0) refill();
  }
}

// create a new PRNG
generator_base::generator_base (u_int32_t bs, bool det, u_int32_t ks)
  : buffer_size(bs), key_size(ks), is_deterministic(det), fill(0)
{
  buffer = (unsigned char *)secure_malloc(buffer_size);
  stir();
}

generator_base::~generator_base() {
  secure_free(buffer);
}

// fill a buffer with randomness
void generator_base::randomize_slow_case
(unsigned char *output, size_t n) {
  while (n>0) {
    if (!fill) refill();
  
    size_t transfer = (n > fill) ? fill : n;
    
    fill -= transfer;
    n -= transfer;
    
    memcpy(output, buffer + fill, transfer);
    bzero(buffer + fill, transfer);
    
    output += transfer;
  }
}

template<class integer>
void
generator_base::permutation(integer *elements, u_int32_t n) {
  u_int32_t i;
  for (i=0; i<n; i++) elements[i] = i;
  for (i=1; i<n; i++) {
    u_int32_t j = random<u_int32_t>(0,i);
    integer tmp = elements[i];
    elements[i] = elements[j];
    elements[j] = tmp;
  }
}

dev_random_handle::dev_random_handle(const char *filename)
 : fd(open(filename, O_RDONLY)), ref(new volatile int(1))
{
  if (fd < 0) {
    // TODO
    throw 0;
  }
}

dev_random_handle::dev_random_handle(const dev_random_handle &h)
  : fd (h.fd), ref (h.ref) {
  (*ref)++; // the compiler had better make this atomic
} 

dev_random_handle::~dev_random_handle() {
  // FIXME it doesn't...
  if (!--(*ref)) {
    close(fd);
    delete ref;
  }
}

template<class gen>
void auto_seeded<gen>::stir() {
  reseeds_remaining = reseed_interval;
  gen::fill = 0;
    
  size_t remaining = gen::key_size;
  unsigned char *rbuf = gen::buffer, *k = gen::key();
  
  while (remaining > 0) {
    ssize_t red = read(dev.fd, rbuf, remaining);
    if (red < 0) {
      // todo
      throw(0);
    }
    remaining -= red;
  }
  
  for (u_int32_t i=0; i<gen::key_size; i++)
    k[i] ^= gen::buffer[i];
  
  gen::refill();
}

template<class gen>
void
auto_seeded<gen>::refill() {
  if (reseeds_remaining == 0)
    stir();
  else
    gen::refill();
  reseeds_remaining--;
}

template void generator_base::permutation(int8_t    *elements, u_int32_t n);
template void generator_base::permutation(u_int8_t  *elements, u_int32_t n);
template void generator_base::permutation(int16_t   *elements, u_int32_t n);
template void generator_base::permutation(u_int16_t *elements, u_int32_t n);
template void generator_base::permutation(int32_t   *elements, u_int32_t n);
template void generator_base::permutation(u_int32_t *elements, u_int32_t n);
template void generator_base::permutation(int64_t   *elements, u_int32_t n);
template void generator_base::permutation(u_int64_t *elements, u_int32_t n);

} // namespace crandom

