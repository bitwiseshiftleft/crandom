#ifndef __CHACHA_H__
#define __CHACHA_H__

#include <sys/types.h>

// niter must be even
// output = 64*niter bytes
void chacha_expand(const unsigned char *key_,
                   u_int64_t iv,
                   u_int64_t ctr,
                   int nr,
                   int niter,
                   unsigned char *output_);
                   
#endif // __CHACHA_H__

