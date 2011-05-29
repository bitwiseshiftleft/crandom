#include "crandom.hpp"
#include "chacha.hpp"
#include "aes.hpp"
#include <unistd.h>
#include <assert.h>
#include <stdio.h>

using namespace crandom;

int main(int argc, char **argv) {
  (void) argc; (void) argv;
  
  const int buffer_size = 65536;

  // auto-seeded?
  prg_generator<chacha> gen(true);

  unsigned char buffer[buffer_size];

  if (isatty(1)) {
    fprintf(stderr, "%s: refusing to write random data to a terminal.\n", argv[0]);
    return 1;
  }

  while(true) {
    gen.randomize(buffer, buffer_size);
    long long int ret = write(1, buffer, buffer_size);
    assert(ret == buffer_size);
  }

  return 2;
}


